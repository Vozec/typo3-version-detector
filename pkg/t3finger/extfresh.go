package t3finger

import (
	"context"
	"encoding/json"
	"strings"
)

// topExtVersion returns the highest concrete version detected for an extension:
// the last (highest) static-hash candidate, else the metadata Version if it is a
// single concrete value (not a "lo – hi" range).
func topExtVersion(e *Extension) string {
	if n := len(e.VersionCandidates); n > 0 {
		return e.VersionCandidates[n-1]
	}
	if e.Version != "" && !strings.Contains(e.Version, " ") {
		return e.Version
	}
	return ""
}

// annotateExtFreshness fills Latest (from the DB snapshot) and Outdated for one
// extension. Called after the version is determined. entry may be nil.
func (f *Fingerprinter) annotateExtFreshness(e *Extension, entry *ExtEntry) {
	if e.Latest == "" && entry != nil {
		e.Latest = entry.Latest
		if e.Latest != "" {
			e.LatestSource = "db"
		}
	}
	e.recomputeOutdated()
}

// recomputeOutdated sets Outdated from the current top-version vs Latest.
func (e *Extension) recomputeOutdated() {
	e.Outdated = false
	if e.Latest == "" {
		return
	}
	if top := topExtVersion(e); top != "" {
		e.Outdated = CompareVersions(top, e.Latest) < 0
	}
}

// RefreshExtensionLatestLive queries Packagist for the current newest stable
// version of every enumerated extension that has a Packagist name, overriding
// the DB snapshot's Latest and recomputing Outdated. Used by --live-versions so
// a stale embedded DB never hides that a plugin has a newer release.
func (f *Fingerprinter) RefreshExtensionLatestLive(ctx context.Context, res *ExtResult) {
	if res == nil {
		return
	}
	// Dedupe by composer name so two hits for the same package hit the API once.
	cache := map[string]string{}
	for i := range res.Extensions {
		e := &res.Extensions[i]
		name := e.ComposerName
		if name == "" && strings.Contains(e.Package, "/") {
			name = e.Package
		}
		if name == "" {
			continue
		}
		latest, done := cache[name]
		if !done {
			latest = f.fetchPackagistLatest(ctx, name)
			cache[name] = latest
		}
		if latest != "" {
			e.Latest, e.LatestSource = latest, "live"
			e.recomputeOutdated()
		}
	}
}

// fetchPackagistLatest returns the newest non-dev version of a Packagist package
// from the p2 metadata endpoint (versions are listed newest-first), or "".
func (f *Fingerprinter) fetchPackagistLatest(ctx context.Context, name string) string {
	if !strings.Contains(name, "/") {
		return ""
	}
	r, err := f.get(ctx, "https://repo.packagist.org/p2/"+name+".json")
	if err != nil || r == nil || r.Status != 200 || len(r.Body) == 0 {
		return ""
	}
	var doc struct {
		Packages map[string][]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(r.Body, &doc); err != nil {
		return ""
	}
	for _, versions := range doc.Packages {
		for _, v := range versions {
			ver := strings.TrimPrefix(v.Version, "v")
			// The list is newest-first; take the first real (non-dev) release.
			if ver == "" || strings.Contains(strings.ToLower(ver), "dev") {
				continue
			}
			return ver
		}
	}
	return ""
}
