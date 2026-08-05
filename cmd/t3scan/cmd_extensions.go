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
	mode := fs.String("mode", "auto", "enumeration mode: auto | composer | legacy")
	conc := fs.Int("t", 16, "concurrent requests (threads)")
	rate := fs.Float64("rate", 20, "max requests per second (0 = unlimited)")
	timeout := fs.Duration("timeout", 20*time.Minute, "overall timeout")
	output := fs.String("o", "", "write results as JSON to this file")
	all := fs.Bool("all", false, "list unconfirmed hits too (default hides stale-symlink-only)")
	cve := fs.Bool("cve", false, "look up known CVEs for found extensions (legacy mode; queries Packagist)")
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

	// Load the right candidate list for the mode.
	var packages []string
	src := *wordlist
	if chosen == "legacy" {
		packages, err = t3finger.LoadExtensionKeys(*wordlist)
		if src == "" {
			src = "bundled TER key list"
		}
	} else {
		packages, err = t3finger.LoadExtensionList(*wordlist)
		if src == "" {
			src = "bundled Packagist list"
		}
	}
	if err != nil {
		fatal(err)
	}

	if !*asJSON {
		fmt.Fprintf(stdout, "%s %s\n", cCyan("▸"), cBold(target))
		kv("mode", chosen)
		kv("candidates", fmt.Sprintf("%d  %s", len(packages), cDim("("+src+")")))
		thr := "unlimited"
		if *rate > 0 {
			thr = fmt.Sprintf("%g req/s", *rate)
		}
		kv("throttle", fmt.Sprintf("%d workers, %s", *conc, thr))
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

	var res *t3finger.ExtResult
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

	if *cve && res != nil {
		if err := f.AnnotateExtensionCVEs(ctx, res); err != nil && !*asJSON {
			fmt.Fprintln(os.Stderr, cYellow("⚠ CVE lookup failed: "+err.Error()))
		}
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
	fmt.Fprintf(stdout, "  %s  HTTP %d, %d bytes = not installed\n",
		cDim("baseline"), res.Baseline.Status, res.Baseline.Size)
	if res.NotEnumerable {
		fmt.Fprintf(stdout, "  %s\n", cYellow("⚠ "+firstNote(res.Notes)))
	}

	// Collect rows (confirmed first, then unconfirmed if -all).
	type erow struct {
		e        *t3finger.Extension
		plugin   string
		version  string
		vColor   func(string) string
		cve      string
		cColor   func(string) string
		evidence string
	}
	var rows []erow
	confirmed, unconfirmed := 0, 0
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
		ver, vc := "?", cDim
		if e.Version != "" {
			ver = e.Version
			if e.VersionExact && len(e.VersionCandidates) <= 1 {
				vc = cGreen
			} else {
				vc = cCyan
			}
		}
		cve, cc := "-", cDim
		switch {
		case len(e.Vulns) > 0:
			cve, cc = fmt.Sprintf("%d!", len(e.Vulns)), cRed
		case len(e.VulnsPossible) > 0:
			cve, cc = fmt.Sprintf("~%d", len(e.VulnsPossible)), cYellow
		}
		ev := e.Evidence
		if e.Location != "" {
			ev = e.Location
		}
		if !e.Confirmed {
			ev = "stale symlink?"
		}
		rows = append(rows, erow{e, e.Package, ver, vc, cve, cc, ev})
	}

	if len(rows) > 0 {
		// Column widths from plain text.
		wP, wV, wC := len("PLUGIN"), len("VERSION"), len("CVE")
		for _, r := range rows {
			wP, wV, wC = max(wP, len(r.plugin)), max(wV, len(r.version)), max(wC, len(r.cve))
		}
		fmt.Fprintf(stdout, "\n  %s  %s  %s  %s\n",
			cBold(pad("PLUGIN", wP)), cBold(pad("VERSION", wV)), cBold(pad("CVE", wC)), cBold("EVIDENCE"))
		fmt.Fprintf(stdout, "  %s\n", cDim(strings.Repeat("─", wP+wV+wC+10+8)))
		for _, r := range rows {
			mark := cGreen("+")
			if !r.e.Confirmed {
				mark = cYellow("?")
			}
			fmt.Fprintf(stdout, "%s %s  %s  %s  %s\n",
				mark, pad(r.plugin, wP), r.vColor(pad(r.version, wV)), r.cColor(pad(r.cve, wC)), cDim(r.evidence))
		}
	}

	// Per-plugin CVE detail (only for plugins that have any).
	for _, r := range rows {
		if len(r.e.Vulns) == 0 && len(r.e.VulnsPossible) == 0 {
			continue
		}
		fmt.Fprintf(stdout, "\n  %s\n", cBold(r.plugin))
		for _, v := range r.e.Vulns {
			fmt.Fprintf(stdout, "     %s %s\n", cRed("⚠"), advLine(v))
		}
		if n := len(r.e.VulnsPossible); n > 0 {
			fmt.Fprintf(stdout, "     %s %s\n", cYellow("~"),
				cDim(fmt.Sprintf("%d known CVE%s for this package — version unknown, verify", n, plural2(n))))
		}
	}

	fmt.Fprintf(stdout, "\n%s probed %d, %s %d confirmed", cDim("›"), res.Probed, cGreen("●"), confirmed)
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
