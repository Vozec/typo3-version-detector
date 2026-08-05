package main

import (
	"flag"
	"fmt"
	"os"
)

// dataset paths (shared by rebuild-database / update-database).
const (
	dbPathDefault  = "pkg/t3finger/db.json"
	extEmbedPath   = "pkg/t3finger/data/extension-db.json.gz"
	extRawPath     = "pkg/t3finger/data/extension-db.raw.json.gz"
	coreMinDefault = "10.0.0"
)

// runRebuildDatabase does a FULL rebuild of every embedded dataset from upstream
// in one shot: extension wordlists, CVE advisories, the latest-release snapshot,
// the core version DB, and the complete extension DB (raw + pruned embed). It
// writes the data files in place; rebuild the binary afterwards to re-embed.
// This is the heavy "build everything once" path — for the cheap daily refresh
// use `update-database`.
func runRebuildDatabase(args []string) {
	fs := flag.NewFlagSet("rebuild-database", flag.ExitOnError)
	skipExt := fs.Bool("skip-extdb", false, "skip the heavy full extension DB rebuild")
	extOnly := fs.Bool("extdb-only", false, "rebuild ONLY the extension DB")
	minVer := fs.String("min", coreMinDefault, "oldest major to include in the core version DB")
	extConc := fs.Int("c", 14, "concurrent downloads for the extension DB build")
	_ = fs.Parse(args)

	extArgs := []string{"-all", "-c", itoaCLI(*extConc), "-o", extEmbedPath, "-raw", extRawPath}
	if *extOnly {
		step(1, 1, "extension DB — FULL build (every TER plugin+theme, all versions)")
		runBuildExtDB(extArgs)
		doneRebuild()
		return
	}
	runDatasets(*minVer, *extConc, extArgs, *skipExt, false)
}

// runUpdateDatabase is the cheap, reusable refresh: it pulls new CVEs, new
// releases, and — incrementally — new extension versions / new plugins, only
// downloading what changed since the last build. Everything else is reused.
func runUpdateDatabase(args []string) {
	fs := flag.NewFlagSet("update-database", flag.ExitOnError)
	skipExt := fs.Bool("skip-extdb", false, "skip the extension DB update (only CVEs + releases + core)")
	extOnly := fs.Bool("extdb-only", false, "update ONLY the extension DB")
	minVer := fs.String("min", coreMinDefault, "oldest major to include in the core version DB")
	extConc := fs.Int("c", 14, "concurrent downloads for the extension DB update")
	_ = fs.Parse(args)

	extArgs := []string{"-all", "-update", "-c", itoaCLI(*extConc), "-o", extEmbedPath, "-raw", extRawPath}
	if *extOnly {
		step(1, 1, "extension DB — incremental (new versions + new plugins only)")
		runBuildExtDB(extArgs)
		doneRebuild()
		return
	}
	runDatasets(*minVer, *extConc, extArgs, *skipExt, true)
}

// runDatasets refreshes wordlists, advisories, releases, the core DB and (unless
// skipped) the extension DB. `incremental` only changes the labels/args for the
// extension step; the other datasets are always rebuilt fresh (they are small).
func runDatasets(minVer string, extConc int, extArgs []string, skipExt, incremental bool) {
	total := 5
	if skipExt {
		total = 4
	}
	extLabel := "extension DB — FULL build (every TER plugin+theme, all versions)"
	if incremental {
		extLabel = "extension DB — incremental (new versions + new plugins only)"
	}

	step(1, total, "extension wordlists (Packagist names + TER keys)")
	runBuildWordlist(nil)
	runBuildWordlist([]string{"-keys"})

	step(2, total, "CVE advisory set (TYPO3 core)")
	runBuildAdvisories(nil)

	step(3, total, "latest-stable-per-branch snapshot (get.typo3.org)")
	runBuildReleases(nil)

	step(4, total, fmt.Sprintf("core version DB (releases ≥ %s)", minVer))
	runBuildDB([]string{"-min", minVer, "-o", dbPathDefault})

	if !skipExt {
		step(5, total, extLabel)
		runBuildExtDB(extArgs)
	}
	doneRebuild()
}

func step(n, total int, label string) {
	fmt.Fprintf(os.Stderr, "\n%s [%d/%d] %s\n", cCyan("▸"), n, total, cBold(label))
}

func doneRebuild() {
	fmt.Fprintf(os.Stderr, "\n%s datasets written. Re-embed them with: %s\n",
		cGreen("✓"), cBold("go build -o t3scan ./cmd/t3scan"))
}

func itoaCLI(n int) string { return fmt.Sprintf("%d", n) }
