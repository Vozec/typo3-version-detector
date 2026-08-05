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
	fmt.Fprintf(stdout, "  %s     HTTP %d, %d bytes = not installed\n\n",
		cDim("baseline"), res.Baseline.Status, res.Baseline.Size)

	if res.NotEnumerable {
		fmt.Fprintf(stdout, "  %s\n\n", cYellow("⚠ "+firstNote(res.Notes)))
	}

	confirmed, unconfirmed := 0, 0
	for _, e := range res.Extensions {
		if e.Confirmed {
			confirmed++
		} else {
			unconfirmed++
		}
	}

	for _, e := range res.Extensions {
		if !e.Confirmed && !all {
			continue
		}
		ver := ""
		if e.Version != "" {
			src := e.VersionSource
			if e.VersionExact {
				src = "✓ " + src
			}
			ver = "  " + cCyan("v"+e.Version) + cDim(" ("+src+")")
		}
		if e.Confirmed {
			ev := e.Evidence
			if e.Location != "" {
				ev = e.Location
			}
			name := e.Package
			if e.ComposerName != "" {
				name += cDim(" [" + e.ComposerName + "]")
			}
			fmt.Fprintf(stdout, "  %s %s%s  %s\n", cGreen("[+]"), cBold(name), ver, cDim(ev))
			if n := len(e.Requires); n > 0 {
				fmt.Fprintf(stdout, "      %s %s\n", cDim("deps"), cDim(depsSummary(e.Requires)))
			}
			for _, v := range e.Vulns {
				fmt.Fprintf(stdout, "      %s %s\n", cRed("⚠"), advLine(v))
			}
			if n := len(e.VulnsPossible); n > 0 {
				fmt.Fprintf(stdout, "      %s %s\n", cYellow("~"), cDim(fmt.Sprintf("%d known CVE%s for this package — version unknown, verify", n, plural2(n))))
			}
		} else {
			fmt.Fprintf(stdout, "  %s %s  %s\n", cYellow("[?]"), e.Package, cDim("(directory only — stale symlink?)"))
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
	if res.Errors > 0 {
		fmt.Fprintln(stdout, cDim("  errors usually mean rate limiting — lower --rate and -c, then retry"))
	}
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
