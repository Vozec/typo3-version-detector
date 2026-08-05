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
	"fmt"
	"io"
	"os"
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

// gatherTargets collects targets from args, an optional list file, and stdin.
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
	for _, a := range args {
		add(a)
	}
	readLines := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			add(sc.Text())
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
	fmt.Printf("  %s  %s\n", cDim(fmt.Sprintf("%-16s", label)), value)
}
