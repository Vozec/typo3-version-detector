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

func runBuildAdvisories(args []string) {
	fs := flag.NewFlagSet("buildadvisories", flag.ExitOnError)
	out := fs.String("o", "pkg/t3finger/data/advisories.json", "output path for the advisory set")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fmt.Fprintln(os.Stderr, "[buildadvisories] fetching TYPO3 core advisories from Packagist…")
	db, err := t3finger.FetchAdvisories(ctx)
	if err != nil {
		fatal(err)
	}
	data, err := json.MarshalIndent(db, "", "")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[buildadvisories] wrote %s (%d advisories)\n", *out, len(db.Advisories))
	fmt.Fprintln(os.Stderr, "[buildadvisories] rebuild the binary to embed: go build ./cmd/t3scan")
}
