package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Vozec/typo3-version-detector/pkg/t3finger"
)

// runBuildExtDB builds (or incrementally updates) the extension fingerprint DB.
//
// It maintains two files:
//   - the RAW working DB (-raw): every hashed public file per version, unpruned.
//     This is the source of truth that makes future updates download-minimal.
//   - the EMBED DB (-o): the raw DB pruned to version-discriminating files only,
//     compiled into the binary.
//
// Without -update it does a full build from TER. With -update it loads the raw
// DB and fetches ONLY new versions / new extensions — the cheap daily refresh.
func runBuildExtDB(args []string) {
	fs := flag.NewFlagSet("buildextdb", flag.ExitOnError)
	out := fs.String("o", "pkg/t3finger/data/extension-db.json.gz", "embedded (pruned) DB output path (.gz = gzip)")
	raw := fs.String("raw", "pkg/t3finger/data/extension-db.raw.json.gz", "raw (unpruned) working DB — source of truth for incremental updates")
	keysFile := fs.String("keys", "", "extension keys to build (one per line); default: bundled seed list")
	all := fs.Bool("all", false, "build for the ENTIRE TER catalogue (~9.3k extensions, all plugins+themes)")
	maxV := fs.Int("maxversions", 0, "hash only the N most-recent versions per extension (0 = all; controls depth)")
	update := fs.Bool("update", false, "incremental: load the raw DB and fetch only new versions / new extensions")
	merge := fs.Bool("merge", false, "alias for -update (kept for compatibility)")
	conc := fs.Int("c", 8, "concurrent downloads")
	hours := fs.Int("timeout-hours", 8, "overall timeout in hours")
	_ = fs.Parse(args)
	incremental := *update || *merge

	var keys []string
	switch {
	case *all:
		keys = t3finger.DefaultExtensionKeys()
	case *keysFile != "":
		var err error
		if keys, err = t3finger.LoadExtensionKeys(*keysFile); err != nil {
			fatal(err)
		}
	default:
		keys = t3finger.SeedExtensionKeys()
	}
	if len(keys) == 0 {
		fatal(fmt.Errorf("no extension keys to build"))
	}

	b := t3finger.NewExtBuilder()
	b.Concurrency = *conc
	b.MaxVersions = *maxV
	b.Progress = func(s string) { fmt.Fprintln(os.Stderr, "[buildextdb] "+s) }

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*hours)*time.Hour)
	defer cancel()

	// Load the existing raw DB for an incremental update (start empty for a full
	// build). New extensions and new versions are the only downloads.
	var existing *t3finger.ExtProbeDB
	if incremental {
		if ex, err := t3finger.LoadExtProbeDBFile(*raw); err == nil && ex != nil && len(ex.Extensions) > 0 {
			existing = ex
			fmt.Fprintf(os.Stderr, "[buildextdb] incremental update from %s (%d extensions known)\n", *raw, len(ex.Extensions))
		} else {
			fmt.Fprintf(os.Stderr, "[buildextdb] no usable raw DB at %s — doing a FULL build instead\n", *raw)
		}
	}

	depth := "all versions"
	if *maxV > 0 {
		depth = fmt.Sprintf("newest %d versions", *maxV)
	}
	mode := "full build"
	if existing != nil {
		mode = "incremental update"
	}
	fmt.Fprintf(os.Stderr, "[buildextdb] %s: %d extensions (%s)…\n", mode, len(keys), depth)

	stamp := time.Now().UTC().Format(time.RFC3339)
	rawDB, stats, err := b.UpdateExtDB(ctx, existing, keys, stamp)
	if err != nil {
		fatal(err)
	}

	// Persist the raw working DB, then the pruned embed DB.
	if err := writeDBFile(*raw, rawDB); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[buildextdb] wrote raw %s (%d extensions)\n", *raw, len(rawDB.Extensions))

	embed := t3finger.PruneForEmbed(rawDB)
	if err := writeDBFile(*out, embed); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[buildextdb] wrote embed %s (%d extensions)\n", *out, len(embed.Extensions))
	fmt.Fprintf(os.Stderr, "[buildextdb] %s → +%d new, %d updated, %d unchanged, %d downloads\n",
		mode, stats.NewExtensions, stats.Updated, stats.Unchanged, stats.Downloads)
	fmt.Fprintln(os.Stderr, "[buildextdb] rebuild the binary to embed: go build ./cmd/t3scan")
}

// writeDBFile marshals a DB to path, gzip-compressing when the name ends in .gz.
func writeDBFile(path string, db *t3finger.ExtProbeDB) error {
	data, err := json.Marshal(db)
	if err != nil {
		return err
	}
	if strings.HasSuffix(path, ".gz") {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		zw.Write(data)
		zw.Close()
		data = buf.Bytes()
	}
	return os.WriteFile(path, data, 0o644)
}
