package t3finger

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

//go:embed db.json
var embeddedDB []byte

// DB is the version-fingerprint database. For each publicly-served asset path,
// it maps the file's md5 hex digest to the list of TYPO3 core versions that
// ship that exact byte content. Files whose content varies across releases are
// the discriminators; identical-everywhere files still confirm a stock install.
type DB struct {
	// Files: servedPath -> md5 -> []version
	Files map[string]map[string][]string `json:"files"`
	// Versions is the full ordered list of versions covered by the DB.
	Versions []string `json:"versions"`
	// BuiltAt is a free-form build stamp (set by `t3scan builddb`).
	BuiltAt string `json:"builtAt,omitempty"`

	// anyHash is a lazily-built md5->versions reverse index (not serialized).
	anyHash map[string]map[string]bool `json:"-"`
}

func emptyDB() *DB {
	return &DB{Files: map[string]map[string][]string{}}
}

// LoadEmbedded returns the database compiled into the binary.
func LoadEmbedded() (*DB, error) { return Parse(embeddedDB) }

// Parse loads a DB from JSON bytes.
func Parse(b []byte) (*DB, error) {
	if len(b) == 0 {
		return emptyDB(), nil
	}
	var db DB
	if err := json.Unmarshal(b, &db); err != nil {
		return nil, fmt.Errorf("parse db: %w", err)
	}
	if db.Files == nil {
		db.Files = map[string]map[string][]string{}
	}
	return &db, nil
}

// Empty reports whether the DB has no fingerprints.
func (d *DB) Empty() bool { return d == nil || len(d.Files) == 0 }

// Newest returns the highest version the DB covers, or "".
func (d *DB) Newest() string {
	if d == nil || len(d.Versions) == 0 {
		return ""
	}
	return d.Versions[len(d.Versions)-1]
}

// Has reports whether the DB already covers version v.
func (d *DB) Has(v string) bool {
	for _, x := range d.Versions {
		if x == v {
			return true
		}
	}
	return false
}

// Merge folds src into d: every (path, md5) → version mapping from src is added,
// version lists are de-duplicated and sorted, and the covered-version set is
// unioned. Used for incremental DB builds.
func (d *DB) Merge(src *DB) {
	if src == nil {
		return
	}
	if d.Files == nil {
		d.Files = map[string]map[string][]string{}
	}
	for path, buckets := range src.Files {
		m := d.Files[path]
		if m == nil {
			m = map[string][]string{}
			d.Files[path] = m
		}
		for h, vs := range buckets {
			seen := toSet(m[h])
			for _, v := range vs {
				if !seen[v] {
					m[h] = append(m[h], v)
					seen[v] = true
				}
			}
			sort.Sort(byVersion(m[h]))
		}
	}
	seen := toSet(d.Versions)
	for _, v := range src.Versions {
		if !seen[v] {
			d.Versions = append(d.Versions, v)
			seen[v] = true
		}
	}
	sort.Sort(byVersion(d.Versions))
	d.anyHash = nil // invalidate lazy index
}

// DiscriminatingPaths returns served paths whose content varies across versions
// (more than one hash bucket) — the files worth probing because they narrow the
// version. Sorted for determinism.
func (d *DB) DiscriminatingPaths() []string {
	var out []string
	for path, buckets := range d.Files {
		if len(buckets) > 1 {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

// PresenceDiscriminatingPaths returns paths that exist in only SOME covered
// versions (added or removed across releases) — their mere presence/absence
// bounds the version even when their content never varies. These complement the
// content-discriminating paths for add/remove-boundary narrowing.
func (d *DB) PresenceDiscriminatingPaths() []string {
	total := len(d.Versions)
	if total == 0 {
		return nil
	}
	var out []string
	for path := range d.Files {
		if n := len(d.VersionsHavingFile(path)); n > 0 && n < total {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

// AllPaths returns every served path known to the DB, sorted.
func (d *DB) AllPaths() []string {
	out := make([]string, 0, len(d.Files))
	for p := range d.Files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// VersionsForAnyHash returns versions that ship a file — at ANY path — whose
// content md5 equals md5hex. Used when the request path can't be mapped to a
// DB path (composer mode). Unexported cache is built on first use.
func (d *DB) VersionsForAnyHash(md5hex string) []string {
	if d.anyHash == nil {
		idx := map[string]map[string]bool{}
		for _, buckets := range d.Files {
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
		d.anyHash = idx
	}
	m := d.anyHash[md5hex]
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

// VersionsForHash returns the versions matching a (servedPath, md5) pair.
func (d *DB) VersionsForHash(servedPath, md5hex string) []string {
	if m, ok := d.Files[servedPath]; ok {
		if vs, ok := m[md5hex]; ok {
			out := append([]string(nil), vs...)
			sort.Sort(byVersion(out))
			return out
		}
	}
	return nil
}

// VersionsHavingFile returns the union of all versions in which servedPath
// exists (any content). Used for presence-based narrowing.
func (d *DB) VersionsHavingFile(servedPath string) []string {
	m, ok := d.Files[servedPath]
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, vs := range m {
		for _, v := range vs {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Sort(byVersion(out))
	return out
}

// byVersion sorts dotted semver-ish strings numerically.
type byVersion []string

func (s byVersion) Len() int           { return len(s) }
func (s byVersion) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byVersion) Less(i, j int) bool { return CompareVersions(s[i], s[j]) < 0 }

// CompareVersions compares "a.b.c" strings numerically. Missing parts = 0.
func CompareVersions(a, b string) int {
	pa, pb := splitVer(a), splitVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVer(v string) [3]int {
	var out [3]int
	part, cur := 0, 0
	seen := false
	for i := 0; i < len(v) && part < 3; i++ {
		c := v[i]
		if c >= '0' && c <= '9' {
			cur = cur*10 + int(c-'0')
			seen = true
		} else if c == '.' {
			out[part] = cur
			part++
			cur, seen = 0, false
		} else {
			break // stop at first non-numeric/non-dot suffix (e.g. "-dev")
		}
	}
	if seen && part < 3 {
		out[part] = cur
	}
	return out
}
