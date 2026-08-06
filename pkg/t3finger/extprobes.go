package t3finger

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sort"
)

// The extension DB is large, so it is embedded gzip-compressed.
//
//go:embed data/extension-db.json.gz
var embeddedExtDB []byte

// ExtEntry is the full record for one extension (a plugin, a theme/sitepackage,
// or any TER package — themes are just extensions):
//   - Composer/Latest/Versions: identity and coverage.
//   - Requires: its declared dependencies (from composer.json).
//   - Probes: web-servable files that prove it is installed (presence).
//   - Files: for each web-servable path, md5 -> versions that ship that exact
//     content — the per-version static-file diff used to pin the INSTALLED
//     version of the extension by hashing what the target serves.
type ExtEntry struct {
	Composer string                         `json:"composer,omitempty"`
	Author   string                         `json:"author,omitempty"` // authorname from the TER index
	Owner    string                         `json:"owner,omitempty"`  // ownerusername (TER account owning the key)
	Latest   string                         `json:"latest,omitempty"`
	Versions []string                       `json:"versions,omitempty"`
	Requires map[string]string              `json:"requires,omitempty"`
	Probes   []string                       `json:"probes"`
	Files    map[string]map[string][]string `json:"files,omitempty"`

	anyHash map[string]map[string]bool `json:"-"`
}

// ExtProbe is the legacy alias kept for the builder's simpler output; the rich
// entry supersedes it. (Files/Requires may be empty for breadth-only builds.)
type ExtProbe = ExtEntry

// ExtProbeDB maps extension key -> its full record.
type ExtProbeDB struct {
	BuiltAt    string              `json:"builtAt,omitempty"`
	Extensions map[string]ExtEntry `json:"extensions"`

	composerIdx map[string]string   `json:"-"` // composer name -> canonical key
	assetIdx    map[string]string   `json:"-"` // md5("/vendor/<composer>/") -> canonical key
	candIdx     map[string][]string `json:"-"` // composer name -> ALL keys claiming it
	assetComp   map[string]string   `json:"-"` // md5("/vendor/<composer>/") -> composer name
}

// ensureIndexes builds the composer-name and asset-hash reverse indexes once,
// DETERMINISTICALLY. The TER catalogue contains junk/fork extensions that
// declare another package's composer name (e.g. a "local_dummy" claiming
// "georgringer/news"), so a naive last-writer-wins map is non-deterministic and
// can resolve a real package to the impostor. On a collision we keep the entry
// with the most versions (the real, maintained one); ties break to the
// lexicographically smallest key.
func (d *ExtProbeDB) ensureIndexes() {
	if d.composerIdx != nil {
		return
	}
	keys := make([]string, 0, len(d.Extensions))
	for k := range d.Extensions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	comp := make(map[string]string, len(keys))
	best := make(map[string]int, len(keys))
	cand := make(map[string][]string, len(keys))
	for _, k := range keys {
		e := d.Extensions[k]
		if e.Composer == "" {
			continue
		}
		cand[e.Composer] = append(cand[e.Composer], k)
		if _, ok := comp[e.Composer]; !ok || len(e.Versions) > best[e.Composer] {
			comp[e.Composer] = k
			best[e.Composer] = len(e.Versions)
		}
	}
	// Order each candidate list canonical-first (most versions, then key), so
	// callers can present alternatives with the likeliest real package leading.
	for composer, ks := range cand {
		sort.SliceStable(ks, func(i, j int) bool {
			ni, nj := len(d.Extensions[ks[i]].Versions), len(d.Extensions[ks[j]].Versions)
			if ni != nj {
				return ni > nj
			}
			return ks[i] < ks[j]
		})
		cand[composer] = ks
	}
	asset := make(map[string]string, len(comp))
	assetComp := make(map[string]string, len(comp))
	for composer, key := range comp {
		h := hex.EncodeToString(md5Sum("/vendor/" + composer + "/"))
		asset[h] = key
		assetComp[h] = composer
	}
	d.composerIdx, d.assetIdx, d.candIdx, d.assetComp = comp, asset, cand, assetComp
}

func md5Sum(s string) []byte { sum := md5.Sum([]byte(s)); return sum[:] }

// CandidatesForComposer returns every extension key that declares the given
// composer name — more than one when forks/dummies squat the same name. Ordered
// canonical-first (most versions). Empty if the name is unknown.
func (d *ExtProbeDB) CandidatesForComposer(name string) []string {
	d.ensureIndexes()
	return d.candIdx[name]
}

// ComposerForAssetHash returns the composer name behind a /_assets/<md5>/ hash.
func (d *ExtProbeDB) ComposerForAssetHash(md5hex string) string {
	d.ensureIndexes()
	return d.assetComp[md5hex]
}

// ByComposer returns the entry for a Packagist name (vendor/pkg), or nil. Used
// to version-fingerprint a composer-mode extension whose key we don't have.
func (d *ExtProbeDB) ByComposer(name string) *ExtEntry {
	d.ensureIndexes()
	if key, ok := d.composerIdx[name]; ok {
		e := d.Extensions[key]
		return &e
	}
	return nil
}

// IdentifyAssetHash reverses a composer-mode /_assets/<md5>/ directory hash back
// to the installed extension it belongs to, using a precomputed table of
// md5("/vendor/<composer>/") over the whole catalogue. This turns a hash already
// present in the target's HTML into a certain, zero-extra-request identification
// (the site is literally serving that package's asset). ok=false if unknown.
func (d *ExtProbeDB) IdentifyAssetHash(md5hex string) (key, composer string, ok bool) {
	d.ensureIndexes()
	if k, found := d.assetIdx[md5hex]; found {
		return k, d.Extensions[k].Composer, true
	}
	return "", "", false
}

// KeyForComposer returns the TER extension key for a Packagist name, or "".
func (d *ExtProbeDB) KeyForComposer(name string) string {
	d.ensureIndexes()
	return d.composerIdx[name]
}

// LoadExtProbeDB returns the embedded extension DB (decompressing it).
func LoadExtProbeDB() *ExtProbeDB {
	db := &ExtProbeDB{Extensions: map[string]ExtEntry{}}
	if raw := gunzipMaybe(embeddedExtDB); len(raw) > 0 {
		_ = json.Unmarshal(raw, db)
	}
	if db.Extensions == nil {
		db.Extensions = map[string]ExtEntry{}
	}
	return db
}

// ParseExtProbeDB reads a DB from JSON or gzipped-JSON bytes.
func ParseExtProbeDB(b []byte) (*ExtProbeDB, error) {
	db := &ExtProbeDB{Extensions: map[string]ExtEntry{}}
	raw := gunzipMaybe(b)
	if len(raw) == 0 {
		return db, nil
	}
	if err := json.Unmarshal(raw, db); err != nil {
		return nil, err
	}
	if db.Extensions == nil {
		db.Extensions = map[string]ExtEntry{}
	}
	return db, nil
}

// LoadExtProbeDBFile loads a DB from a file path (json or json.gz).
func LoadExtProbeDBFile(path string) (*ExtProbeDB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseExtProbeDB(b)
}

// gunzipMaybe returns the decompressed bytes if b is gzip, else b unchanged.
func gunzipMaybe(b []byte) []byte {
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		if zr, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
			if out, err := io.ReadAll(zr); err == nil {
				return out
			}
		}
		return nil
	}
	return b
}

// Keys returns the extension keys in the DB, sorted.
func (d *ExtProbeDB) Keys() []string {
	out := make([]string, 0, len(d.Extensions))
	for k := range d.Extensions {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Empty reports whether the DB has no entries.
func (d *ExtProbeDB) Empty() bool { return d == nil || len(d.Extensions) == 0 }

// VersionForHash returns the versions of extension `key` whose file `path` has
// content md5 == md5hex (exact per-version static-file match).
func (e *ExtEntry) VersionForHash(path, md5hex string) []string {
	if e.Files == nil {
		return nil
	}
	if m, ok := e.Files[path]; ok {
		if vs, ok := m[md5hex]; ok {
			return vs
		}
	}
	return nil
}

// AnyHash returns versions of this extension shipping a file (any path) with the
// given content md5 — for when the served path can't be mapped exactly.
func (e *ExtEntry) AnyHash(md5hex string) []string {
	if e.anyHash == nil {
		idx := map[string]map[string]bool{}
		for _, buckets := range e.Files {
			for h, vs := range buckets {
				m := idx[h]
				if m == nil {
					m = map[string]bool{}
					idx[h] = m
				}
				for _, v := range vs {
					m[v] = true
				}
			}
		}
		e.anyHash = idx
	}
	m := e.anyHash[md5hex]
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Sort(byVersion(out))
	return out
}

// DiscriminatingFiles returns the paths whose content varies across versions —
// the files worth hashing on a live target to pin the extension's version.
func (e *ExtEntry) DiscriminatingFiles() []string {
	var out []string
	for path, buckets := range e.Files {
		if len(buckets) > 1 {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

// DiscriminatingFilesRanked returns discriminating paths ordered by how much
// they narrow the version — most hash-buckets (changes most often) first, so
// probing a few pins the version tightly. Ties broken by shortest path (stable,
// usually top-level assets that are reliably served).
func (e *ExtEntry) DiscriminatingFilesRanked() []string {
	type pc struct {
		path    string
		buckets int
	}
	var ranked []pc
	for path, buckets := range e.Files {
		if len(buckets) > 1 {
			ranked = append(ranked, pc{path, len(buckets)})
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].buckets != ranked[j].buckets {
			return ranked[i].buckets > ranked[j].buckets
		}
		if len(ranked[i].path) != len(ranked[j].path) {
			return len(ranked[i].path) < len(ranked[j].path)
		}
		return ranked[i].path < ranked[j].path
	})
	out := make([]string, len(ranked))
	for i, r := range ranked {
		out[i] = r.path
	}
	return out
}
