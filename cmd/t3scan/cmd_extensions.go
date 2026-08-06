package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Vozec/typo3-version-detector/pkg/t3finger"
)

func runExtensions(args []string) {
	fs := flag.NewFlagSet("extensions", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	insecure := fs.Bool("k", false, "skip TLS certificate verification")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	proxy := fs.String("proxy", "", "route through a proxy (http://, https:// or socks5://)")
	verbose := fs.Bool("v", false, "verbose: also print baseline/mode notes")
	wordlist := fs.String("w", "", "candidate list file (default: bundled list for the chosen mode)")
	extSel := fs.String("e", "", "scan only these extension(s): comma-separated names/keys, or a file of them (one per line)")
	live := fs.Bool("live-versions", false, "query Packagist for each found extension's newest release (else use the DB snapshot)")
	mode := fs.String("mode", "auto", "enumeration mode: auto | composer | legacy")
	conc := fs.Int("t", 16, "concurrent requests (threads)")
	rate := fs.Float64("rate", 20, "max requests per second (0 = unlimited)")
	timeout := fs.Duration("timeout", 20*time.Minute, "overall timeout")
	output := fs.String("o", "", "write results as JSON to this file")
	all := fs.Bool("all", false, "list unconfirmed hits too (default hides stale-symlink-only)")
	cve := fs.Bool("cve", false, "look up known CVEs for found extensions (legacy mode; queries Packagist)")
	passiveOnly := fs.Bool("passive", false, "passive discovery ONLY — HTML /_assets md5 reversal, composer.lock, PackageStates.php; no brute force")
	noPassive := fs.Bool("no-passive", false, "skip the passive pre-pass; brute force only")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Enumerate TYPO3 extensions installed on a site.\n\nUsage:\n  t3scan extensions [flags] <url>\n\nModes:\n  composer  probe /_assets/<md5(\"/vendor/<pkg>/\")>/  (TYPO3 >= 11 composer installs)\n  legacy    probe /typo3conf/ext/<key>/ and /typo3/sysext/<key>/  (+ reads versions)\n  auto      detect the install mode first, then pick (default)\n\nFlags:\n")
		fs.PrintDefaults()
	}
	positionals := parseFlags(fs, args)
	if *noColor || *asJSON || *output != "" {
		useColor = false
	}
	if len(positionals) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	target := positionals[0]

	f, err := t3finger.New(
		t3finger.WithInsecure(*insecure),
		t3finger.WithProxy(*proxy),
		t3finger.WithConcurrency(*conc),
		t3finger.WithRate(*rate),
	)
	if err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Resolve mode.
	chosen := *mode
	if chosen == "auto" {
		m, _ := f.DetectMode(ctx, target)
		switch m {
		case t3finger.ModeLegacy:
			chosen = "legacy"
		case t3finger.ModeComposer:
			chosen = "composer"
		default:
			chosen = "composer" // default technique when undetermined
			if !*asJSON {
				fmt.Fprintln(os.Stderr, cDim("  (mode undetermined; defaulting to composer — use -mode legacy to force)"))
			}
		}
	}

	// Load the candidate list: an explicit -e selection (single ext or a file of
	// them) overrides the full bundled wordlist.
	var packages []string
	var src string
	if *extSel != "" {
		packages = resolveSelectors(f, chosen, parseSelectorArg(*extSel))
		if len(packages) == 0 {
			fatal(fmt.Errorf("no valid extensions resolved from -e %q (for %s mode)", *extSel, chosen))
		}
		src = fmt.Sprintf("%d explicit (-e)", len(packages))
	} else if chosen == "legacy" {
		packages, err = t3finger.LoadExtensionKeys(*wordlist)
		src = "bundled TER key list"
		if *wordlist != "" {
			src = *wordlist
		}
	} else {
		packages, err = t3finger.LoadExtensionList(*wordlist)
		src = "bundled Packagist list"
		if *wordlist != "" {
			src = *wordlist
		}
	}
	if err != nil {
		fatal(err)
	}

	if !*asJSON {
		fmt.Fprintf(stdout, "%s %s\n", cCyan("▸"), cBold(target))
		kv("mode", chosen)
		if !*passiveOnly { // brute-force framing is meaningless in passive-only mode
			kv("candidates", fmt.Sprintf("%d  %s", len(packages), cDim("("+src+")")))
			thr := "unlimited"
			if *rate > 0 {
				thr = fmt.Sprintf("%g req/s", *rate)
			}
			kv("throttle", fmt.Sprintf("%d workers, %s", *conc, thr))
		}
	}

	var lastPct int64 = -1
	progress := func(done, total int) {
		if *asJSON || !stderrIsTTY() {
			return
		}
		pct := int64(done) * 100 / int64(total)
		if pct != atomic.LoadInt64(&lastPct) {
			atomic.StoreInt64(&lastPct, pct)
			fmt.Fprint(os.Stderr, renderBar("extensions", done, total))
		}
	}

	// Passive pre-pass (free, no brute force): reverse /_assets/<md5>/ in the
	// HTML against the catalogue, read composer.lock / PackageStates.php.
	var passive *t3finger.ExtResult
	if !*noPassive {
		if passive, err = f.PassiveExtensions(ctx, target); err != nil {
			passive = nil
		} else if passive != nil && !*asJSON {
			kv("passive", fmt.Sprintf("%d found without brute force %s",
				len(passive.Extensions), cDim("(HTML assets, composer.lock, PackageStates)")))
		}
	}

	var res *t3finger.ExtResult
	if *passiveOnly {
		res = passive
		if res == nil {
			res = &t3finger.ExtResult{Target: target}
		}
	} else {
		if chosen == "legacy" {
			res, err = f.EnumerateExtensionsLegacy(ctx, target, packages, progress)
		} else {
			res, err = f.EnumerateExtensions(ctx, target, packages, progress)
		}
		if stderrIsTTY() && !*asJSON {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
		if err != nil {
			fatal(err)
		}
		res = mergeExtResults(res, passive) // fold passive hits in (dedup)
	}

	if *cve && res != nil {
		if err := f.AnnotateExtensionCVEs(ctx, res); err != nil && !*asJSON {
			fmt.Fprintln(os.Stderr, cYellow("⚠ CVE lookup failed: "+err.Error()))
		}
	}

	if *live && res != nil {
		if !*asJSON {
			fmt.Fprintln(os.Stderr, cDim("  querying Packagist for each extension's newest release…"))
		}
		f.RefreshExtensionLatestLive(ctx, res)
	}

	render := func() {
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			enc.Encode(res)
			return
		}
		printExtensions(res, *all || *verbose)
		if *verbose {
			for _, n := range res.Notes {
				printNote(n)
			}
		}
	}

	if *output != "" {
		useColor = false
		sink, err := newSink(*output, false, *asJSON) // single target → single file
		if err != nil {
			fatal(err)
		}
		p, err := sink.write(target, renderCaptured(render))
		if err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "%s %s\n", cDim("wrote"), p)
		return
	}
	render()
}

func printExtensions(res *t3finger.ExtResult, all bool) {
	if res.Baseline.OK { // only meaningful when a brute-force pass calibrated it
		fmt.Fprintf(stdout, "  %s  HTTP %d, %d bytes = not installed\n",
			cDim("baseline"), res.Baseline.Status, res.Baseline.Size)
	}
	if res.NotEnumerable {
		fmt.Fprintf(stdout, "  %s\n", cYellow("⚠ "+firstNote(res.Notes)))
	}

	type erow struct {
		e      *t3finger.Extension
		plugin string
		ver    string
		vc     func(string) string
		latest string
		lc     func(string) string
		cve    string
		cc     func(string) string
		author string
		link   string
	}
	anyLatest, anyOutdated := false, false
	for i := range res.Extensions {
		e := &res.Extensions[i]
		if e.Confirmed || all {
			anyLatest = anyLatest || e.Latest != ""
			anyOutdated = anyOutdated || e.Outdated
		}
	}

	var rows []erow
	confirmed, unconfirmed, ambiguous := 0, 0, 0
	for i := range res.Extensions {
		e := &res.Extensions[i]
		if e.Confirmed {
			confirmed++
		} else {
			unconfirmed++
			if !all {
				continue
			}
		}
		if e.Ambiguous {
			ambiguous++
		}
		plugin := e.Package
		if e.Ambiguous && e.Key != "" { // the shared composer name needs the key to tell siblings apart
			plugin = e.Package + " (" + e.Key + ")"
		}
		ver, vc := "?", cDim
		if e.Version != "" {
			ver = e.Version
			if e.VersionExact && len(e.VersionCandidates) <= 1 {
				vc = cGreen
			} else {
				vc = cCyan
			}
		}
		latest, lc := "-", cDim
		if e.Latest != "" {
			if e.Outdated {
				latest, lc = "⇡ "+e.Latest, cYellow
			} else {
				latest, lc = e.Latest, cGreen
			}
		}
		cve, cc := "-", cDim
		switch {
		case len(e.Vulns) > 0:
			cve, cc = fmt.Sprintf("%d!", len(e.Vulns)), cRed
		case len(e.VulnsPossible) > 0:
			cve, cc = fmt.Sprintf("~%d", len(e.VulnsPossible)), cYellow
		}
		author := e.Author
		if author == "" {
			author = e.Owner
		}
		rows = append(rows, erow{e, plugin, ver, vc, latest, lc, cve, cc, author, e.Link})
	}

	if len(rows) > 0 {
		// Compact, terminal-fit columns: VERSION/LATEST/CVE sized to data, PLUGIN
		// takes the rest (middle-ellipsized). AUTHOR + LINK move to a wrapped
		// sub-line so the table never overflows the screen.
		wV, wL, wC, wP := len("VERSION"), len("LATEST"), len("CVE"), len("PLUGIN")
		for _, r := range rows {
			wV = maxi(wV, dispLen(r.ver))
			wC = maxi(wC, dispLen(r.cve))
			wL = maxi(wL, dispLen(r.latest))
			wP = maxi(wP, dispLen(r.plugin))
		}
		fixed := 2 + wV + 2 + wC + 2 // marker+space + version col + cve col + gaps
		if anyLatest {
			fixed += wL + 2
		}
		if wP+fixed+2 > termWidth() {
			if wP = termWidth() - fixed - 2; wP < 12 {
				wP = 12
			}
		}
		for i := range rows {
			rows[i].plugin = ellipsizeMiddle(rows[i].plugin, wP)
		}

		hdr := cBold(pad("PLUGIN", wP)) + "  " + cBold(pad("VERSION", wV)) + "  "
		if anyLatest {
			hdr += cBold(pad("LATEST", wL)) + "  "
		}
		hdr += cBold("CVE")
		ruleW := wP + 2 + wV + 2 + wC + 2
		if anyLatest {
			ruleW += wL + 2
		}
		fmt.Fprintf(stdout, "\n  %s\n", hdr)
		fmt.Fprintf(stdout, "  %s\n", cDim(strings.Repeat("─", mini(ruleW, termWidth()-2))))
		for _, r := range rows {
			marker := cGreen("+")
			if r.e.Ambiguous || !r.e.Confirmed {
				marker = cYellow("?")
			}
			line := marker + " " + cBold(pad(r.plugin, wP)) + "  " + r.vc(pad(r.ver, wV)) + "  "
			if anyLatest {
				line += r.lc(pad(r.latest, wL)) + "  "
			}
			line += r.cc(r.cve)
			fmt.Fprintln(stdout, line)
			if r.author != "" || r.link != "" {
				printAuthorLink(4, r.author, r.link)
			}
		}
		if anyOutdated {
			fmt.Fprintf(stdout, "\n  %s\n", cDim("⇡ = newer release available (the installed version is behind LATEST)"))
		}
	}

	// Ambiguity notes: several extensions share one composer name; only one is
	// installed and the served files couldn't single it out.
	printAmbiguityNotes(res.Extensions)

	// Per-plugin CVE detail (only for plugins that have any).
	for _, r := range rows {
		if len(r.e.Vulns) == 0 && len(r.e.VulnsPossible) == 0 {
			continue
		}
		fmt.Fprintf(stdout, "\n  %s\n", cBold(r.e.Package))
		for _, v := range r.e.Vulns {
			fmt.Fprintf(stdout, "     %s %s\n", cRed("⚠"), advLine(v))
		}
		if n := len(r.e.VulnsPossible); n > 0 {
			fmt.Fprintf(stdout, "     %s %s\n", cYellow("~"),
				cDim(fmt.Sprintf("%d known CVE%s for this package — version unknown, verify each applies:", n, plural2(n))))
			for _, v := range r.e.VulnsPossible {
				fmt.Fprintf(stdout, "       %s %s\n", cYellow("~"), advLinePossible(v))
			}
		}
	}

	fmt.Fprintf(stdout, "\n%s probed %d, %s %d confirmed", cDim("›"), res.Probed, cGreen("●"), confirmed)
	if ambiguous > 0 {
		fmt.Fprintf(stdout, ", %s %d ambiguous", cYellow("?"), ambiguous)
	}
	if unconfirmed > 0 {
		hint := ""
		if !all {
			hint = cDim(" (use -all to list)")
		}
		fmt.Fprintf(stdout, ", %s %d unconfirmed%s", cYellow("◐"), unconfirmed, hint)
	}
	if res.Errors > 0 {
		fmt.Fprintf(stdout, ", %s %d errors", cRed("✗"), res.Errors)
	}
	fmt.Fprintln(stdout)
}

// printAmbiguityNotes explains each set of extensions that share a composer name
// where the served files couldn't determine which one is installed.
func printAmbiguityNotes(exts []t3finger.Extension) {
	groups := map[string][]t3finger.Extension{}
	var order []string
	for _, e := range exts {
		if !e.Ambiguous {
			continue
		}
		if _, ok := groups[e.ComposerName]; !ok {
			order = append(order, e.ComposerName)
		}
		groups[e.ComposerName] = append(groups[e.ComposerName], e)
	}
	for _, name := range order {
		g := groups[name]
		fmt.Fprintf(stdout, "\n  %s %s\n", cYellow("?"),
			cBold(name)+cDim(fmt.Sprintf(" — %d extensions share this composer name; only one is installed:", len(g))))
		for _, e := range g {
			who := e.Author
			if who == "" {
				who = "unknown author"
			}
			if e.Owner != "" {
				who += " · @" + e.Owner // the TER account — the real disambiguator
			}
			ver := ""
			if e.Version != "" {
				src := e.VersionSource
				if src == "" {
					src = "detected"
				}
				ver = cCyan(" v"+e.Version) + cDim(" ("+src+")")
			}
			fmt.Fprintf(stdout, "      %s %s %s%s\n", cDim("•"), cBold(e.Key), cDim("by "+who), ver)
			if e.Link != "" {
				fmt.Fprintf(stdout, "        %s\n", cCyan(e.Link))
			}
		}
	}
}

// mergeExtResults folds passively-discovered extensions into the brute-force
// result, de-duplicating by composer name (or key). A passive hit fills in a
// version/evidence the brute-force pass lacked, and passive-only finds (e.g.
// when the host blocks enumeration entirely) are appended.
func mergeExtResults(primary, extra *t3finger.ExtResult) *t3finger.ExtResult {
	if extra == nil {
		return primary
	}
	if primary == nil {
		return extra
	}
	key := func(e t3finger.Extension) string {
		if e.ComposerName != "" {
			return "c:" + e.ComposerName
		}
		return "k:" + e.Package
	}
	idx := map[string]int{}
	for i := range primary.Extensions {
		idx[key(primary.Extensions[i])] = i
	}
	for _, e := range extra.Extensions {
		if i, ok := idx[key(e)]; ok {
			p := &primary.Extensions[i]
			p.Confirmed = p.Confirmed || e.Confirmed
			if p.Version == "" && e.Version != "" {
				p.Version, p.VersionSource, p.VersionExact, p.VersionCandidates = e.Version, e.VersionSource, e.VersionExact, e.VersionCandidates
			}
			if p.Evidence == "" {
				p.Evidence = e.Evidence
			}
			if p.Latest == "" && e.Latest != "" {
				p.Latest, p.LatestSource, p.Outdated = e.Latest, e.LatestSource, e.Outdated
			}
		} else {
			primary.Extensions = append(primary.Extensions, e)
			idx[key(e)] = len(primary.Extensions) - 1
		}
	}
	// If enumeration was impossible but passive still found plugins, it's no
	// longer a dead end — drop the misleading not-enumerable flag.
	if primary.NotEnumerable && len(primary.Extensions) > 0 {
		primary.NotEnumerable = false
	}
	return primary
}

// parseSelectorArg turns a -e value into a selector list: if it names an
// existing file, one selector per line; otherwise a comma-separated inline list.
func parseSelectorArg(arg string) []string {
	if isFile(arg) {
		b, err := os.ReadFile(arg)
		if err != nil {
			fatal(err)
		}
		var out []string
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln != "" && !strings.HasPrefix(ln, "#") {
				out = append(out, ln)
			}
		}
		return out
	}
	var out []string
	for _, s := range strings.Split(arg, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// resolveSelectors maps user-supplied extension selectors (a composer name like
// "georgringer/news" or a TER key like "news") to the probe candidates the
// chosen mode expects: composer mode wants "vendor/name", legacy wants the key.
// Bare keys/names are resolved through the bundled extension DB.
func resolveSelectors(f *t3finger.Fingerprinter, mode string, sels []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range sels {
		if mode == "legacy" {
			if strings.Contains(s, "/") { // composer name → key
				if k := f.ExtProbes.KeyForComposer(s); k != "" {
					add(k)
				} else {
					fmt.Fprintln(os.Stderr, cYellow("⚠ no TER key known for "+s+" — skipped"))
				}
				continue
			}
			add(s) // already a key
			continue
		}
		// composer mode: need vendor/name
		if strings.Contains(s, "/") {
			add(s)
			continue
		}
		if e, ok := f.ExtProbes.Extensions[s]; ok && e.Composer != "" {
			add(e.Composer)
		} else {
			fmt.Fprintln(os.Stderr, cYellow("⚠ no composer name known for key "+s+" — pass vendor/name, or use -mode legacy"))
		}
	}
	return out
}

func pad(s string, w int) string {
	if n := dispLen(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// depsSummary renders the most relevant dependencies (TYPO3 + other extensions
// first, then php/ext-*), compactly.
func depsSummary(req map[string]string) string {
	var typo3, exts, other []string
	for name, constraint := range req {
		pair := name + " " + constraint
		switch {
		case strings.HasPrefix(name, "typo3/"):
			typo3 = append(typo3, pair)
		case strings.HasPrefix(name, "php") || strings.HasPrefix(name, "ext-"):
			other = append(other, pair)
		default:
			exts = append(exts, pair)
		}
	}
	sort.Strings(typo3)
	sort.Strings(exts)
	sort.Strings(other)
	all := append(append(typo3, exts...), other...)
	if len(all) > 5 {
		return strings.Join(all[:5], " · ") + fmt.Sprintf(" (+%d)", len(all)-5)
	}
	return strings.Join(all, " · ")
}

func advLine(v t3finger.Advisory) string {
	id := v.CVE
	if id == "" {
		id = v.ID
	}
	sev := ""
	if v.Severity != "" {
		sev = cDim(" [" + v.Severity + "]")
	}
	return cBold(id) + sev + "  " + cDim(v.Title)
}

// advLinePossible renders a "possible" advisory: the id + severity + the
// affected constraint (so the user can check it against the install) + title.
func advLinePossible(v t3finger.Advisory) string {
	id := v.CVE
	if id == "" {
		id = v.ID
	}
	sev := ""
	if v.Severity != "" {
		sev = cDim(" [" + v.Severity + "]")
	}
	aff := ""
	if v.Affected != "" {
		aff = cDim(" (affects " + v.Affected + ")")
	}
	return cBold(id) + sev + aff + "  " + cDim(v.Title)
}

func plural2(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func firstNote(notes []string) string {
	if len(notes) > 0 {
		return notes[0]
	}
	return ""
}
