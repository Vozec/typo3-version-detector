package main

import (
	"flag"
	"fmt"
	"os"
)

// runRebuildDatabase rebuilds every embedded dataset from upstream in one shot:
// the extension wordlists, the CVE advisories, the latest-release snapshot, the
// core version DB, and (unless -skip-extdb) the full extension DB. It writes the
// data files in place; rebuild the binary afterwards to re-embed them. This is
// the in-tool equivalent of `make data` minus the final `go build`.
func runRebuildDatabase(args []string) {
	fs := flag.NewFlagSet("rebuild-database", flag.ExitOnError)
	skipExt := fs.Bool("skip-extdb", false, "skip the heavy full extension DB rebuild (~1h)")
	extOnly := fs.Bool("extdb-only", false, "rebuild ONLY the extension DB")
	dbPath := fs.String("db", "pkg/t3finger/db.json", "core version DB output path")
	extPath := fs.String("extdb", "pkg/t3finger/data/extension-db.json.gz", "extension DB output path")
	minVer := fs.String("min", "10.0.0", "oldest major to include in the core version DB")
	extConc := fs.Int("c", 14, "concurrent downloads for the extension DB build")
	merge := fs.Bool("merge", true, "merge into the existing extension DB (resumable) rather than rebuild from scratch")
	_ = fs.Parse(args)

	step := func(n int, total int, label string) {
		fmt.Fprintf(os.Stderr, "\n%s [%d/%d] %s\n", cCyan("▸ rebuild-database"), n, total, cBold(label))
	}

	extArgs := []string{"buildextdb", "-all", "-c", itoaCLI(*extConc), "-o", *extPath}
	if *merge {
		extArgs = append(extArgs, "-merge")
	}

	if *extOnly {
		step(1, 1, "extension DB (every TER plugin+theme, versions, hashes, deps)")
		runBuildExtDB(extArgs[1:])
		doneRebuild()
		return
	}

	total := 5
	if *skipExt {
		total = 4
	}
	step(1, total, "extension wordlists (Packagist names + TER keys)")
	runBuildWordlist(nil)
	runBuildWordlist([]string{"-keys"})

	step(2, total, "CVE advisory set (TYPO3 core)")
	runBuildAdvisories(nil)

	step(3, total, "latest-stable-per-branch snapshot (get.typo3.org)")
	runBuildReleases(nil)

	step(4, total, fmt.Sprintf("core version DB (releases ≥ %s)", *minVer))
	runBuildDB([]string{"-min", *minVer, "-o", *dbPath})

	if !*skipExt {
		step(5, total, "extension DB (every TER plugin+theme, versions, hashes, deps)")
		runBuildExtDB(extArgs[1:])
	}
	doneRebuild()
}

func doneRebuild() {
	fmt.Fprintf(os.Stderr, "\n%s all datasets rebuilt. Re-embed them with: %s\n",
		cGreen("✓"), cBold("go build -o t3scan ./cmd/t3scan"))
}

func itoaCLI(n int) string { return fmt.Sprintf("%d", n) }
