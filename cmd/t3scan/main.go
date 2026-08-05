// t3scan — TYPO3 scanner.
//
// Pre-auth fingerprinting of a TYPO3 CMS website: enumerate the installed
// extensions ("plugins") via the deterministic Composer-mode asset path, and
// detect the core version by hashing served static assets and matching them
// against a database built from official releases.
//
// Usage:
//
//	t3scan <url> [<url> ...]          detect version(s)
//	t3scan -json <url>               machine-readable output
//	t3scan extensions <url>          enumerate installed extensions
//	t3scan buildwordlist [-o file]   refresh the extension list from Packagist
//	t3scan builddb [flags]           (re)build the version fingerprint database
//
// For authorized security testing and asset inventory only.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "extensions", "ext", "enum":
		runExtensions(os.Args[2:])
	case "buildwordlist":
		runBuildWordlist(os.Args[2:])
	case "builddb":
		runBuildDB(os.Args[2:])
	case "buildadvisories":
		runBuildAdvisories(os.Args[2:])
	case "buildextdb":
		runBuildExtDB(os.Args[2:])
	case "buildreleases":
		runBuildReleases(os.Args[2:])
	case "rebuild-database", "rebuilddb":
		runRebuildDatabase(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		runVersion(os.Args[1:])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `t3scan — TYPO3 scanner (pre-auth version + extension fingerprinting)

Usage:
  t3scan [flags] <url> [<url> ...]     detect TYPO3 core version(s) + CVEs
  t3scan scan [flags] <url>            full scan: version + CVEs (+ extensions with -ext)
  t3scan extensions [flags] <url>      enumerate installed extensions
  t3scan buildwordlist [-keys] [-o f]  refresh extension list (Packagist / TER keys)
  t3scan builddb [flags]               (re)build the version fingerprint DB
  t3scan buildextdb [flags]            (re)build the extension-probe DB from TER packages
  t3scan buildadvisories [-o file]     refresh the CVE advisory set

Common flags (detect/scan/extensions): -json  -v  -k  -proxy URL  -t N (threads)  -rate N
Run a subcommand with -h for its full flag list.

For authorized security testing only.
`)
}

// parseFlags parses flags that may be interspersed with positional args (Go's
// flag package stops at the first positional), so `t3scan urls.txt -o out` and
// `t3scan -o out urls.txt` both work. Returns the positional arguments.
func parseFlags(fs *flag.FlagSet, args []string) []string {
	var positionals []string
	for {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positionals = append(positionals, args[0])
		args = args[1:]
	}
	return positionals
}

// gatherTargets collects targets from positional args (each a URL OR a file of
// URLs), an optional -l list file, and stdin (piped, or "-"). So all of these
// work: `t3scan https://x`, `t3scan urls.txt`, `cat urls.txt | t3scan`,
// `t3scan -l urls.txt`.
func gatherTargets(args []string, listFile string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	readLines := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			add(sc.Text())
		}
	}
	for _, a := range args {
		switch {
		case a == "-":
			readLines(os.Stdin)
		case isFile(a):
			fh, err := os.Open(a)
			if err != nil {
				fatal(err)
			}
			readLines(fh)
			fh.Close()
		default:
			add(a)
		}
	}
	switch {
	case listFile == "-":
		readLines(os.Stdin)
	case listFile != "":
		fh, err := os.Open(listFile)
		if err != nil {
			fatal(err)
		}
		defer fh.Close()
		readLines(fh)
	case len(args) == 0 && !stdinIsTTY():
		readLines(os.Stdin)
	}
	return out
}

// isFile reports whether path exists and is a regular file (so a positional
// argument can be a URL list instead of a single target).
func isFile(path string) bool {
	if strings.Contains(path, "://") {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func stderrIsTTY() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, cRed("error:"), err)
	os.Exit(1)
}

// ---- color / styling (respects TTY + NO_COLOR) ----

var useColor = colorEnabled()

func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func sgr(code, s string) string {
	if !useColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func cBold(s string) string   { return sgr("1", s) }
func cDim(s string) string    { return sgr("2", s) }
func cGreen(s string) string  { return sgr("32", s) }
func cYellow(s string) string { return sgr("33", s) }
func cRed(s string) string    { return sgr("31", s) }
func cCyan(s string) string   { return sgr("36", s) }

func kv(label, value string) {
	fmt.Fprintf(stdout, "  %s  %s\n", cDim(fmt.Sprintf("%-16s", label)), value)
}

// termWidth returns the usable terminal width (from $COLUMNS), default 100.
func termWidth() int {
	if s := os.Getenv("COLUMNS"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 20 {
			return n
		}
	}
	return 100
}

// kvWrap prints "label  item · item · …" wrapping onto aligned continuation
// lines so a long list (evidence, deps, hints) never runs off the screen.
func kvWrap(label string, items []string, sep string) {
	if len(items) == 0 {
		return
	}
	const indent = 20 // 2 + 16 label + 2
	width := termWidth() - indent
	if width < 24 {
		width = 24
	}
	var lines []string
	cur := ""
	for _, it := range items {
		add := it
		if cur != "" {
			add = sep + it
		}
		if dispLen(cur)+dispLen(add) > width && cur != "" {
			lines = append(lines, cur)
			cur = it
		} else {
			cur += add
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	fmt.Fprintf(stdout, "  %s  %s\n", cDim(fmt.Sprintf("%-16s", label)), lines[0])
	pad := strings.Repeat(" ", indent)
	for _, l := range lines[1:] {
		fmt.Fprintf(stdout, "%s%s\n", pad, l)
	}
}

// dispLen counts visible runes, ignoring ANSI escapes.
func dispLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		if r == '\x1b' {
			esc = true
			continue
		}
		n++
	}
	return n
}

// printNote word-wraps a free-text note under a "›" bullet with a hanging
// indent, so long explanations never run off the screen.
func printNote(text string) {
	width := termWidth() - 4
	if width < 30 {
		width = 30
	}
	words := strings.Fields(text)
	line := ""
	first := true
	flush := func() {
		if first {
			fmt.Fprintf(stdout, "  %s %s\n", cDim("›"), cDim(line))
			first = false
		} else {
			fmt.Fprintf(stdout, "    %s\n", cDim(line))
		}
		line = ""
	}
	for _, w := range words {
		if line != "" && len(line)+1+len(w) > width {
			flush()
		}
		if line == "" {
			line = w
		} else {
			line += " " + w
		}
	}
	if line != "" {
		flush()
	}
}

// renderBar returns a redraw-in-place progress line with a unicode bar.
func renderBar(label string, done, total int) string {
	if total <= 0 {
		total = 1
	}
	if done > total {
		done = total
	}
	const w = 28
	filled := done * w / total
	bar := cCyan(strings.Repeat("█", filled)) + cDim(strings.Repeat("░", w-filled))
	return fmt.Sprintf("\r\033[K  %s [%s] %3d%%  %d/%d", label, bar, done*100/total, done, total)
}
