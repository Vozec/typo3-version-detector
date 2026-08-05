package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Vozec/typo3-scanner/pkg/t3finger"
)

func runBuildWordlist(args []string) {
	fs := flag.NewFlagSet("buildwordlist", flag.ExitOnError)
	keys := fs.Bool("keys", false, "fetch legacy extension KEYS from TER instead of Packagist names")
	out := fs.String("o", "", "output path (default: the bundled file for the chosen list)")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	var (
		names []string
		err   error
		dst   = *out
		label string
	)
	if *keys {
		fmt.Fprintln(os.Stderr, "[buildwordlist] fetching TYPO3 extension keys from TER…")
		names, err = t3finger.FetchExtensionKeys(ctx)
		if dst == "" {
			dst = "pkg/t3finger/data/extension-keys.txt"
		}
		label = "keys"
	} else {
		fmt.Fprintln(os.Stderr, "[buildwordlist] fetching TYPO3 extension names from Packagist…")
		names, err = t3finger.FetchExtensionList(ctx)
		if dst == "" {
			dst = "pkg/t3finger/data/extensions.txt"
		}
		label = "packages"
	}
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(dst, []byte(strings.Join(names, "\n")+"\n"), 0o644); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[buildwordlist] wrote %s (%d %s)\n", dst, len(names), label)
	fmt.Fprintln(os.Stderr, "[buildwordlist] rebuild the binary to embed: go build ./cmd/t3scan")
}
