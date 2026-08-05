package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Vozec/typo3-version-detector/pkg/t3finger"
)

func runVersion(args []string) {
	fs := flag.NewFlagSet("t3scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	insecure := fs.Bool("k", false, "skip TLS certificate verification")
	verbose := fs.Bool("v", false, "show per-file probe details")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	proxy := fs.String("proxy", "", "route through a proxy (http://, https:// or socks5://)")
	listFile := fs.String("l", "", "read targets from a file (one URL per line; '-' for stdin)")
	conc := fs.Int("c", 8, "concurrent targets when scanning a list")
	reqConc := fs.Int("t", 16, "concurrent requests per target (threads)")
	rate := fs.Float64("rate", 0, "max requests per second per target (0 = unlimited)")
	failOnVuln := fs.Bool("fail-on-vuln", false, "exit non-zero (2) if any confirmed vulnerability is found")
	force := fs.Bool("f", false, "force: report/enumerate even when classic markers don't confirm TYPO3")
	fs.BoolVar(force, "force", false, "alias for -f")
	output := fs.String("o", "", "write output to a file (single target) or directory (list); created if missing")
	timeout := fs.Duration("timeout", 30*time.Second, "per-target timeout")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "TYPO3 version detection\n\nUsage:\n  t3scan [flags] <url|file> [<url|file> ...]\n  cat urls.txt | t3scan [flags]\n  t3scan -l urls.txt -o out/\n\nFlags:\n")
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
		t3finger.WithConcurrency(*reqConc),
		t3finger.WithRate(*rate),
	)
	if err != nil {
		fatal(err)
	}
	if f.DB.Empty() {
		fmt.Fprintln(os.Stderr, cYellow("⚠ embedded version DB is empty — run `t3scan builddb` and rebuild; only exact-file reads and markers will work"))
	}

	results := scanTargets(f, targets, *conc, *timeout)

	if *output != "" {
		// One file per target (or a single file for a single target).
		sink, err := newSink(*output, len(targets) > 1, *asJSON)
		if err != nil {
			fatal(err)
		}
		for i, r := range results {
			content := renderCaptured(func() {
				if *asJSON {
					enc := json.NewEncoder(stdout)
					enc.SetIndent("", "  ")
					enc.Encode(r)
				} else {
					printVersion(r, *verbose, *force)
				}
			})
			p, err := sink.write(targets[i], content)
			if err != nil {
				fatal(err)
			}
			fmt.Fprintf(os.Stderr, "%s %s\n", cDim("wrote"), p)
		}
	} else {
		switch {
		case *asJSON:
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if len(results) == 1 {
				enc.Encode(results[0])
			} else {
				enc.Encode(results)
			}
		case len(targets) > 1:
			renderVersionTable(results)
		default:
			for _, r := range results {
				printVersion(r, *verbose, *force)
			}
		}
	}

	if *failOnVuln {
		for _, r := range results {
			if r != nil && len(r.Vulnerabilities) > 0 {
				os.Exit(2)
			}
		}
	}
}

// renderCaptured runs fn with stdout redirected to a buffer and returns the
// bytes it produced (for writing a target's output to a file).
func renderCaptured(fn func()) []byte {
	var buf bytes.Buffer
	old := stdout
	stdout = &buf
	fn()
	stdout = old
	return buf.Bytes()
}

func scanTargets(f *t3finger.Fingerprinter, targets []string, conc int, timeout time.Duration) []*t3finger.VersionResult {
	if conc < 1 {
		conc = 1
	}
	out := make([]*t3finger.VersionResult, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	var mu sync.Mutex
	done := 0
	progress := len(targets) > 1 && stderrIsTTY()
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			r, err := f.Detect(ctx, t)
			if err != nil {
				r = &t3finger.VersionResult{Target: t, Notes: []string{err.Error()}, Confidence: "low"}
			}
			out[i] = r
			if progress {
				mu.Lock()
				done++
				fmt.Fprintf(os.Stderr, "\r\033[K  scanning… %d/%d", done, len(targets))
				mu.Unlock()
			}
		}(i, t)
	}
	wg.Wait()
	if progress {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
	return out
}

func printVersion(r *t3finger.VersionResult, verbose, force bool) {
	fmt.Fprintf(stdout, "\n%s\n", cDim(strings.Repeat("─", 60)))
	fmt.Fprintf(stdout, "%s %s\n", cCyan("▸"), cBold(r.Target))

	if !r.IsTypo3 && !force {
		fmt.Fprintf(stdout, "  %s\n", cRed("✗ not detected as TYPO3"))
		for _, n := range r.Notes {
			printNote(n)
		}
		return
	}
	if !r.IsTypo3 {
		fmt.Fprintf(stdout, "  %s\n", cYellow("⚠ not confirmed TYPO3 by markers — forced (-f); showing best-effort findings"))
	}

	verdict := r.Range
	if verdict == "" {
		verdict = "unknown"
	}
	head := "TYPO3 " + verdict
	switch r.Confidence {
	case "high":
		head = cGreen(cBold(head))
	case "medium":
		head = cYellow(cBold(head))
	default:
		head = cBold(head)
	}
	fmt.Fprintf(stdout, "\n  %s   %s\n\n", head, confidenceBadge(r.Confidence))
	if r.Mode != "" && r.Mode != "unknown" {
		kv("install mode", string(r.Mode))
	}
	if r.BasePath != "" {
		kv("base path", "/"+r.BasePath)
	}
	if r.Method != "" {
		kv("method", r.Method)
	}
	if n := len(r.Candidates); n > 1 {
		if n <= 12 {
			kv(fmt.Sprintf("candidates (%d)", n), strings.Join(r.Candidates, "  "))
		} else {
			kv(fmt.Sprintf("candidates (%d)", n), r.Candidates[0]+" … "+r.Candidates[n-1])
		}
	}
	if len(r.Markers) > 0 {
		kvWrap("evidence", r.Markers, cDim(" · "))
	}
	if len(r.ExtensionsHint) > 0 {
		kvWrap(fmt.Sprintf("extensions (%d)", len(r.ExtensionsHint)),
			r.ExtensionsHint, cDim(" · "))
	}

	if n := len(r.Vulnerabilities); n > 0 {
		fmt.Fprintf(stdout, "\n  %s   %s\n", cRed(cBold(fmt.Sprintf("⚠ %d known vulnerabilit%s", n, plural(n, "y", "ies")))),
			cDim(severityBreakdown(r.Vulnerabilities)))
		printAdvisories(r.Vulnerabilities, cRed("●"))
	}
	if n := len(r.Maybe); n > 0 {
		fmt.Fprintf(stdout, "\n  %s\n", cYellow(fmt.Sprintf("~ %d possible (version not pinned)", n)))
		if verbose {
			printAdvisories(r.Maybe, cYellow("○"))
		} else {
			fmt.Fprintf(stdout, "   %s\n", cDim("(use -v to list; pin the version to confirm)"))
		}
	}

	if verbose {
		printAssets(r)
	}

	for _, n := range r.Notes {
		printNote(n)
	}
}

// printAssets renders the probed assets: the matched ones (the evidence, full
// path, never truncated) first, then a concise explanation of why the rest
// didn't map — instead of dumping dozens of noisy "served, not in DB" lines.
func printAssets(r *t3finger.VersionResult) {
	var matched []t3finger.FileProbe
	served, absent := 0, 0
	for _, fp := range r.Files {
		switch {
		case fp.Matched:
			matched = append(matched, fp)
		case fp.Status == 200:
			served++
		default:
			absent++
		}
	}

	if len(matched) > 0 {
		fmt.Fprintf(stdout, "\n  %s  %s\n", cBold("matched assets"), cDim("(these pinned the version)"))
		for _, fp := range matched {
			how := "content"
			if fp.ByPath {
				how = "path"
			}
			vs := fmt.Sprintf("%s → %s", cDim(fp.MD5[:8]), verSpan(fp.Versions))
			fmt.Fprintf(stdout, "   %s %s\n      %s  %s\n",
				cGreen("✓"), fp.Path, vs, cDim("("+how+", "+plural(len(fp.Versions), "1 version", fmt.Sprintf("%d versions", len(fp.Versions)))+")"))
		}
	}

	if served > 0 {
		fmt.Fprintf(stdout, "\n  %s %s\n", cYellow(fmt.Sprintf("%d assets served but not in the DB.", served)),
			cDim("Why: their exact bytes aren't catalogued —"))
		fmt.Fprintf(stdout, "     %s\n", cDim("the target likely runs a build newer than the embedded DB, or (composer"))
		fmt.Fprintf(stdout, "     %s\n", cDim("mode) exposes legacy /typo3/sysext/ copies whose content isn't indexed."))
		fmt.Fprintf(stdout, "     %s\n", cDim("Run `t3scan builddb` to refresh, or use `-json` to see every hash."))
	}
	if absent > 0 {
		fmt.Fprintf(stdout, "  %s\n", cDim(fmt.Sprintf("%d probed paths were absent (404).", absent)))
	}
}

// verSpan renders a version list as "lo – hi" (or the single version).
func verSpan(vs []string) string {
	if len(vs) == 0 {
		return "?"
	}
	if len(vs) == 1 {
		return cCyan(vs[0])
	}
	return cCyan(vs[0] + " – " + vs[len(vs)-1])
}

func severityBreakdown(advs []t3finger.Advisory) string {
	order := []string{"critical", "high", "medium", "low"}
	counts := map[string]int{}
	for _, a := range advs {
		s := strings.ToLower(a.Severity)
		if s == "moderate" {
			s = "medium"
		}
		if s == "" {
			s = "medium"
		}
		counts[s]++
	}
	var parts []string
	for _, s := range order {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func printAdvisories(advs []t3finger.Advisory, bullet string) {
	// Align the CVE id column, then show the FULL title (never truncated).
	idw := 0
	for _, a := range advs {
		id := a.CVE
		if id == "" {
			id = a.ID
		}
		if len(id) > idw {
			idw = len(id)
		}
	}
	for _, a := range advs {
		id := a.CVE
		if id == "" {
			id = a.ID
		}
		sev := ""
		if a.Severity != "" {
			sev = cDim(" [" + a.Severity + "]")
		}
		fmt.Fprintf(stdout, "   %s %s%s  %s\n", bullet, cBold(fmt.Sprintf("%-*s", idw, id)), sev, a.Title)
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func confidenceBadge(conf string) string {
	switch conf {
	case "high":
		return cGreen("● high")
	case "medium":
		return cYellow("◐ medium")
	default:
		return cRed("○ low")
	}
}

func renderVersionTable(results []*t3finger.VersionResult) {
	headers := []string{"TARGET", "TYPO3", "CONF", "MODE", "VULNS", "METHOD"}
	rows := [][]string{}
	for _, r := range results {
		rows = append(rows, versionRow(r))
	}
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = len(h)
	}
	for _, row := range rows {
		for i, c := range row {
			if len(c) > w[i] {
				w[i] = len(c)
			}
		}
	}
	printRow := func(cells []string, style func(string) string) {
		var b strings.Builder
		for i, c := range cells {
			cell := c + strings.Repeat(" ", w[i]-len(c))
			if style != nil {
				cell = style(cell)
			}
			b.WriteString(cell)
			if i < len(cells)-1 {
				b.WriteString("  ")
			}
		}
		fmt.Fprintln(stdout, b.String())
	}
	printRow(headers, cBold)
	for _, row := range rows {
		printRow(row, nil)
	}
}

func versionRow(r *t3finger.VersionResult) []string {
	target := strings.TrimPrefix(strings.TrimPrefix(r.Target, "https://"), "http://")
	if len(target) > 40 {
		target = target[:39] + "…"
	}
	if !r.IsTypo3 {
		return []string{target, "not typo3", "-", "-", "-", "-"}
	}
	ver := r.Range
	if ver == "" {
		ver = "unknown"
	}
	mode := string(r.Mode)
	if mode == "" || mode == "unknown" {
		mode = "-"
	}
	vulns := "-"
	if n := len(r.Vulnerabilities); n > 0 {
		vulns = fmt.Sprintf("%d", n)
	} else if n := len(r.Maybe); n > 0 {
		vulns = fmt.Sprintf("~%d", n)
	}
	return []string{target, ver, r.Confidence, mode, vulns, r.Method}
}
