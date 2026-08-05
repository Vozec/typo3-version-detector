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

func runBuildReleases(args []string) {
	fs := flag.NewFlagSet("buildreleases", flag.ExitOnError)
	out := fs.String("o", "pkg/t3finger/data/releases.json", "output path")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Fprintln(os.Stderr, "[buildreleases] fetching the release feed from get.typo3.org…")
	rel, err := t3finger.FetchReleases(ctx)
	if err != nil {
		fatal(err)
	}
	data, err := json.Marshal(rel)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[buildreleases] wrote %s (%d branches, latest %s)\n", *out, len(rel.Branches), rel.Latest)
	fmt.Fprintln(os.Stderr, "[buildreleases] rebuild the binary to embed: go build ./cmd/t3scan")
}
