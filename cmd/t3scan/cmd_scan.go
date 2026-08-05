package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/Vozec/typo3-version-detector/pkg/t3finger"
)

// scanReport is the unified result of a full scan: core version + CVEs, and
// (optionally) the enumerated extensions with their CVEs.
type scanReport struct {
	Target     string                  `json:"target"`
	Version    *t3finger.VersionResult `json:"version"`
	Extensions *t3finger.ExtResult     `json:"extensions,omitempty"`
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	verbose := fs.Bool("v", false, "verbose: show every probed asset and full evidence")
	insecure := fs.Bool("k", false, "skip TLS certificate verification")
	proxy := fs.String("proxy", "", "route through a proxy (http://, https:// or socks5://)")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	threads := fs.Int("t", 16, "concurrent requests (threads)")
	rate := fs.Float64("rate", 0, "max requests per second (0 = unlimited)")
	doExt := fs.Bool("ext", false, "also enumerate installed extensions (many requests)")
	mode := fs.String("mode", "auto", "extension mode when -ext: auto | composer | legacy")
	wordlist := fs.String("w", "", "extension candidate list (with -ext)")
	cve := fs.Bool("cve", true, "map versions to known CVEs")
	failOnVuln := fs.Bool("fail-on-vuln", false, "exit non-zero (2) if any confirmed vulnerability is found")
	force := fs.Bool("f", false, "force: scan even when classic markers don't confirm TYPO3")
	fs.BoolVar(force, "force", false, "alias for -f")
	listFile := fs.String("l", "", "read targets from a file (one URL per line; '-' for stdin)")
	output := fs.String("o", "", "output file (single target) or directory (list); created if missing")
	timeout := fs.Duration("timeout", 20*time.Minute, "overall timeout")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Full TYPO3 scan: core version + CVEs, optionally extensions.\n\nUsage:\n  t3scan scan [flags] <url|file> [...]\n  cat urls.txt | t3scan scan -ext -o out/\n\nFlags:\n")
		fs.PrintDefaults()
	}
	positionals := parseFlags(fs, args)
	if *noColor || *asJSON || *output != "" {
		useColor = false
	}

	targets := gatherTargets(positionals, *listFile)
	if len(targets) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	f, err := t3finger.New(
		t3finger.WithInsecure(*insecure),
		t3finger.WithProxy(*proxy),
		t3finger.WithConcurrency(*threads),
		t3finger.WithRate(*rate),
	)
	if err != nil {
		fatal(err)
	}
	if !*cve {
		f.Advisories = nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	opts := scanOpts{doExt: *doExt, mode: *mode, wordlist: *wordlist, cve: *cve, asJSON: *asJSON, force: *force}
	reports := make([]*scanReport, 0, len(targets))
	for _, target := range targets {
		if !*asJSON && len(targets) > 1 {
			fmt.Fprintf(os.Stderr, "%s scanning %s\n", cDim("›"), target)
		}
		reports = append(reports, scanOneTarget(ctx, f, target, opts))
	}

	// Render one report to the current stdout writer (human or JSON).
	renderReport := func(rep *scanReport) {
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			enc.Encode(rep)
			return
		}
		printVersion(rep.Version, *verbose, *force)
		switch {
		case rep.Extensions != nil:
			fmt.Fprintf(stdout, "\n%s %s\n", cCyan("▸"), cBold("extensions"))
			printExtensions(rep.Extensions, false)
		case rep.Version.IsTypo3 || *force:
			hint := "9,289-key TER catalogue"
			if rep.Version.Mode == t3finger.ModeComposer {
				hint = "~4,400 Composer packages via /_assets/"
			}
			fmt.Fprintf(stdout, "\n  %s %s\n", cYellow("extensions       not scanned —"),
				cBold("add -ext to enumerate the "+hint))
			if n := len(rep.Version.ExtensionsHint); n > 0 {
				fmt.Fprintf(stdout, "     %s\n", cDim(fmt.Sprintf("(%d were seen passively in the HTML, shown above)", n)))
			}
		}
	}

	// Output: one file per target when -o is set, else stdout.
	if *output != "" {
		sink, err := newSink(*output, len(targets) > 1, *asJSON)
		if err != nil {
			fatal(err)
		}
		for _, rep := range reports {
			content := renderCaptured(func() { renderReport(rep) })
			p, err := sink.write(rep.Target, content)
			if err != nil {
				fatal(err)
			}
			fmt.Fprintf(os.Stderr, "%s %s\n", cDim("wrote"), p)
		}
	} else {
		for _, rep := range reports {
			renderReport(rep)
		}
	}

	// Exit code for pipelines.
	if *failOnVuln {
		for _, rep := range reports {
			if scanHasVuln(rep) {
				os.Exit(2)
			}
		}
	}
}

// scanOpts carries the per-run scan configuration.
type scanOpts struct {
	doExt    bool
	mode     string
	wordlist string
	cve      bool
	asJSON   bool
	force    bool
}

func scanOneTarget(ctx context.Context, f *t3finger.Fingerprinter, target string, o scanOpts) *scanReport {
	rep := &scanReport{Target: target}
	var err error
	rep.Version, err = f.Detect(ctx, target)
	if err != nil {
		rep.Version = &t3finger.VersionResult{Target: target, Notes: []string{err.Error()}, Confidence: "low"}
	}

	if o.doExt && (rep.Version.IsTypo3 || o.force) {
		chosen := o.mode
		if chosen == "auto" {
			if rep.Version.Mode == t3finger.ModeLegacy {
				chosen = "legacy"
			} else {
				chosen = "composer"
			}
		}
		var pkgs []string
		if chosen == "legacy" {
			pkgs, _ = t3finger.LoadExtensionKeys(o.wordlist)
		} else {
			pkgs, _ = t3finger.LoadExtensionList(o.wordlist)
		}
		var lastPct int64 = -1
		progress := func(done, total int) {
			if o.asJSON || !stderrIsTTY() {
				return
			}
			pct := int64(done) * 100 / int64(total)
			if pct != atomic.LoadInt64(&lastPct) {
				atomic.StoreInt64(&lastPct, pct)
				fmt.Fprint(os.Stderr, renderBar("extensions", done, total))
			}
		}
		if chosen == "legacy" {
			rep.Extensions, _ = f.EnumerateExtensionsLegacy(ctx, target, pkgs, progress)
		} else {
			rep.Extensions, _ = f.EnumerateExtensions(ctx, target, pkgs, progress)
		}
		if stderrIsTTY() && !o.asJSON {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
		if o.cve && rep.Extensions != nil {
			_ = f.AnnotateExtensionCVEs(ctx, rep.Extensions)
		}
	}
	return rep
}

func scanHasVuln(rep *scanReport) bool {
	if rep.Version != nil && len(rep.Version.Vulnerabilities) > 0 {
		return true
	}
	if rep.Extensions != nil {
		for _, e := range rep.Extensions.Extensions {
			if len(e.Vulns) > 0 {
				return true
			}
		}
	}
	return false
}
