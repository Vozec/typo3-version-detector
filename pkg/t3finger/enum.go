package t3finger

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// How Composer-mode TYPO3 (>= 11.4) exposes each installed package:
//
//	/_assets/<md5("/vendor/<vendor>/<package>/")>/
//
// The leading AND trailing slash are part of the hashed string. That directory
// answers 403 when the package is installed and 404 when it is not, so
// enumeration is one offline md5 plus one request per candidate.
//
// A 403 alone is not proof: a removed package can leave a dangling symlink that
// still answers 403 while every file beneath it 404s. Each hit is therefore
// retested against a few well-known subpaths and reported confirmed/unconfirmed.

// confirmPaths are probed under a hit to tell a real install from a dangling
// symlink. These directories/files ship in most extensions' Resources/Public.
var confirmPaths = []string{
	"Icons/", "Css/", "JavaScript/", "Images/", "Fonts/",
	"Icons/Extension.svg", "Icons/Extension.gif", "Icons/Extension.png",
}

// Extension is one enumerated package result.
type Extension struct {
	Package   string `json:"package"`            // vendor/name (composer) or ext key (legacy)
	Confirmed bool   `json:"confirmed"`          // a subpath under it also responded
	Evidence  string `json:"evidence,omitempty"` // the subpath/URL that confirmed it
	AssetURL  string `json:"assetUrl,omitempty"` // the /_assets/<md5>/ URL that hit (composer)
	Location  string `json:"location,omitempty"` // where it was found (legacy path)
	Status    int    `json:"status"`             // HTTP status of the hit
	// Version and VersionSource are populated by legacy enumeration when a
	// version-bearing file (composer.json, ext_emconf.php, …) is web-readable.
	Version       string `json:"version,omitempty"`
	VersionSource string `json:"versionSource,omitempty"`
	// ComposerName is the Packagist name (vendor/pkg) read from composer.json,
	// used to look the extension up in the advisory feed.
	ComposerName string `json:"composerName,omitempty"`
	// VersionSources lists how the version was determined ("ext_emconf.php",
	// "static-file hash", …) when more than one method agreed.
	VersionExact bool `json:"versionExact,omitempty"` // pinned by static-file hash
	// VersionCandidates is the full candidate set when Version is a range (from
	// static-file hashing) — used for accurate per-candidate CVE assessment.
	VersionCandidates []string `json:"versionCandidates,omitempty"`
	// Requires is the extension's declared dependencies (from the probe DB).
	Requires map[string]string `json:"requires,omitempty"`
	// Vulns lists known advisories affecting this extension version (with -cve).
	Vulns []Advisory `json:"vulnerabilities,omitempty"`
	// VulnsPossible lists advisories for the package when the version is unknown
	// (composer-mode enumeration) — the extension has known CVEs, but whether
	// this install is affected depends on its (unreadable) version.
	VulnsPossible []Advisory `json:"vulnerabilitiesPossible,omitempty"`
}

// ExtResult is the full extension-enumeration report.
type ExtResult struct {
	Target        string      `json:"target"`
	Probed        int         `json:"probed"`
	Errors        int         `json:"errors"`
	Baseline      Baseline    `json:"baseline"`
	Extensions    []Extension `json:"extensions"`
	NotEnumerable bool        `json:"notEnumerable"` // control probe itself looked like a hit
	Notes         []string    `json:"notes,omitempty"`
}

// Baseline records what "not installed" looks like, calibrated per target
// instead of assuming 404 (some setups answer differently).
type Baseline struct {
	Status int  `json:"status"`
	Size   int  `json:"size"`
	OK     bool `json:"ok"`
}

// AssetURL returns the deterministic /_assets/<md5>/ URL for a package. A bare
// Packagist name ("vendor/pkg") is wrapped as "/vendor/<name>/"; a value that
// already starts with "/" is hashed verbatim (with an enforced trailing slash).
func AssetURL(base, pkg string) string {
	path := pkg
	if !strings.HasPrefix(path, "/") {
		path = "/vendor/" + pkg + "/"
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	sum := md5.Sum([]byte(path))
	return base + "/_assets/" + hex.EncodeToString(sum[:]) + "/"
}

// EnumerateExtensions probes each candidate package against the target and
// returns the ones whose asset directory responds differently from a
// known-absent control. Progress, if non-nil, is called with (done, total).
func (f *Fingerprinter) EnumerateExtensions(ctx context.Context, target string, packages []string, progress func(done, total int)) (*ExtResult, error) {
	base, err := normalizeBase(target)
	if err != nil {
		return nil, err
	}
	res := &ExtResult{Target: base, Probed: len(packages)}

	// Calibrate the "not installed" response with a package that cannot exist.
	cs, csz, ok := f.head(ctx, AssetURL(base, "zzz-no-such-vendor/zzz-no-such-package-"+randToken()))
	if !ok {
		return nil, errNoControl
	}
	res.Baseline = Baseline{Status: cs, Size: csz, OK: true}
	// A control that already answers 403/200 with a body means the host answers
	// every /_assets/<x>/ the same way (blanket rule / SPA catch-all): the
	// technique cannot discriminate here.
	if cs != 404 {
		// The host answers every /_assets/<x>/ the same way (blanket rule / SPA
		// catch-all): the technique can't discriminate, so don't sweep thousands
		// of packages producing all-garbage hits — report and return.
		res.NotEnumerable = true
		res.Notes = append(res.Notes,
			"control probe returned HTTP "+itoa(cs)+" (expected 404): host answers /_assets/<hash>/ uniformly; extension enumeration is unreliable here — skipped")
		return res, nil
	}

	type hit struct {
		pkg    string
		status int
	}
	var (
		hits   []hit
		mu     sync.Mutex
		errors int64
		done   int64
		wg     sync.WaitGroup
		sem    = make(chan struct{}, f.conc())
	)

	for _, pkg := range packages {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" || strings.HasPrefix(pkg, "#") {
			atomic.AddInt64(&done, 1)
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(pkg string) {
			defer wg.Done()
			defer func() { <-sem }()
			st, sz, ok := f.head(ctx, AssetURL(base, pkg))
			// Baseline is a clean 404 (verified above); an installed package
			// answers 403. Discriminate on STATUS only — the host's 404 body size
			// varies by URL (it echoes the hash), so a size compare flags random
			// absent packages as hits.
			if !ok {
				atomic.AddInt64(&errors, 1)
			} else if st != cs {
				_ = sz
				mu.Lock()
				hits = append(hits, hit{pkg, st})
				mu.Unlock()
			}
			n := atomic.AddInt64(&done, 1)
			if progress != nil {
				progress(int(n), len(packages))
			}
		}(pkg)
	}
	wg.Wait()
	res.Errors = int(errors)

	// Confirm each hit: a real install answers on at least one known subpath;
	// a dangling symlink 404s everywhere beneath.
	sort.Slice(hits, func(i, j int) bool { return hits[i].pkg < hits[j].pkg })
	for _, h := range hits {
		assetURL := AssetURL(base, h.pkg)
		ext := Extension{Package: h.pkg, AssetURL: assetURL, Status: h.status}
		for _, sub := range confirmPaths {
			st, sz, ok := f.head(ctx, assetURL+sub)
			if ok && (st != cs || sz != csz) {
				ext.Confirmed = true
				ext.Evidence = sub
				break
			}
		}
		res.Extensions = append(res.Extensions, ext)
	}
	return res, nil
}
