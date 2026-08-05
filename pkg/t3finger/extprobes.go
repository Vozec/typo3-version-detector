package t3finger

import (
	"bytes"
	"compress/gzip"
	_ "embed"
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
