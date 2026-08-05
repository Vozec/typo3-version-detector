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

func runBuildExtDB(args []string) {
	fs := flag.NewFlagSet("buildextdb", flag.ExitOnError)
	out := fs.String("o", "pkg/t3finger/data/extension-db.json.gz", "output path (.gz = gzip)")
	keysFile := fs.String("keys", "", "extension keys to build (one per line); default: bundled seed list")
	all := fs.Bool("all", false, "build for the ENTIRE TER catalogue (~9.3k extensions, all plugins+themes)")
	maxV := fs.Int("maxversions", 0, "hash only the N most-recent versions per extension (0 = all; controls depth)")
	merge := fs.Bool("merge", false, "merge into the existing DB at -o instead of replacing")
	conc := fs.Int("c", 8, "concurrent downloads")
	hours := fs.Int("timeout-hours", 8, "overall timeout in hours")
	_ = fs.Parse(args)

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

	depth := "all versions"
	if *maxV > 0 {
		depth = fmt.Sprintf("newest %d versions", *maxV)
	}
	fmt.Fprintf(os.Stderr, "[buildextdb] building probes+hashes+deps for %d extensions (%s)…\n", len(keys), depth)
	stamp := time.Now().UTC().Format(time.RFC3339)
	db, err := b.BuildExtProbeDB(ctx, keys, stamp)
	if err != nil {
		fatal(err)
	}

	if *merge {
		if existing, err := t3finger.LoadExtProbeDBFile(*out); err == nil && existing.Extensions != nil {
			for k, v := range db.Extensions {
				existing.Extensions[k] = v
			}
			existing.BuiltAt = stamp
			db = existing
		}
	}

	data, err := json.Marshal(db)
	if err != nil {
		fatal(err)
	}
	if strings.HasSuffix(*out, ".gz") {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		zw.Write(data)
		zw.Close()
		data = buf.Bytes()
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[buildextdb] wrote %s (%d extensions, %d KB on disk)\n", *out, len(db.Extensions), len(data)/1024)
	fmt.Fprintln(os.Stderr, "[buildextdb] rebuild the binary to embed: go build ./cmd/t3scan")
}
