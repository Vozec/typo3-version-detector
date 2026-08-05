package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Vozec/typo3-version-detector/pkg/t3finger"
)

func runBuildDB(args []string) {
	fs := flag.NewFlagSet("builddb", flag.ExitOnError)
	out := fs.String("o", "pkg/t3finger/db.json", "output path for the database")
	minV := fs.String("min", "", "only include versions >= this (e.g. 10.0.0)")
	maxV := fs.String("max", "", "only include versions <= this")
	only := fs.String("only", "", "comma-separated explicit version list (overrides API)")
	merge := fs.String("i", "", "merge into this existing DB (skips already-covered versions)")
	conc := fs.Int("c", 4, "concurrent downloads")
	full := fs.Bool("full", false, "hash the entire Resources/Public tree (bigger DB, deeper coverage)")
	hours := fs.Int("timeout-hours", 6, "overall timeout in hours")
	_ = fs.Parse(args)

	t3finger.HashFull = *full
	b := t3finger.NewBuilder()
	b.Concurrency = *conc
	b.Progress = func(s string) { fmt.Fprintln(os.Stderr, "[builddb] "+s) }

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*hours)*time.Hour)
	defer cancel()

	var versions []string
	if *only != "" {
		for _, v := range splitCommas(*only) {
			versions = append(versions, v)
		}
	} else {
		fmt.Fprintln(os.Stderr, "[builddb] fetching release list from get.typo3.org…")
		all, err := b.ListReleases(ctx)
		if err != nil {
			fatal(err)
		}
		for _, v := range all {
			if *minV != "" && t3finger.CompareVersions(v, *minV) < 0 {
				continue
			}
			if *maxV != "" && t3finger.CompareVersions(v, *maxV) > 0 {
				continue
			}
			versions = append(versions, v)
		}
	}
	// Incremental merge: load an existing DB and skip versions it already covers.
	var existing *t3finger.DB
	if *merge != "" {
		raw, err := os.ReadFile(*merge)
		if err != nil {
			fatal(fmt.Errorf("read -i DB: %w", err))
		}
		if existing, err = t3finger.Parse(raw); err != nil {
			fatal(err)
		}
		kept := versions[:0]
		skipped := 0
		for _, v := range versions {
			if existing.Has(v) {
				skipped++
				continue
			}
			kept = append(kept, v)
		}
		versions = kept
		fmt.Fprintf(os.Stderr, "[builddb] merging into %s (%d already covered, skipped)\n", *merge, skipped)
	}

	if len(versions) == 0 {
		fatal(fmt.Errorf("no new versions selected"))
	}
	fmt.Fprintf(os.Stderr, "[builddb] hashing %d releases (this downloads ~25MB each)…\n", len(versions))

	stamp := time.Now().UTC().Format(time.RFC3339)
	db, err := b.Build(ctx, versions, stamp)
	if err != nil {
		fatal(err)
	}
	if existing != nil {
		existing.Merge(db)
		db = existing
		db.BuiltAt = stamp
	}

	data, err := json.Marshal(db)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[builddb] wrote %s (%d versions, %d discriminating paths, %d KB)\n",
		*out, len(db.Versions), len(db.Files), len(data)/1024)
	fmt.Fprintln(os.Stderr, "[builddb] rebuild the binary to embed: go build ./cmd/t3scan")
}

func splitCommas(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		if c != ' ' {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
