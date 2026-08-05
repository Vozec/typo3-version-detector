package t3finger

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Builder constructs a version-fingerprint DB by downloading official TYPO3
// release tarballs and hashing the static files they serve.
type Builder struct {
	Concurrency int
	Progress    func(string)
	HTTP        *http.Client
}

// NewBuilder returns a Builder with sane defaults.
func NewBuilder() *Builder {
	return &Builder{
		Concurrency: 4,
		HTTP:        &http.Client{Timeout: 5 * time.Minute},
	}
}

func (b *Builder) log(format string, a ...any) {
	if b.Progress != nil {
		b.Progress(fmt.Sprintf(format, a...))
	}
}

// Release is one entry from the get.typo3.org release API.
type Release struct {
	Version string `json:"version"`
	Type    string `json:"type"`
	ELTS    bool   `json:"elts"`
}

// ListReleases returns every public (non-ELTS) release version, newest first is
// not guaranteed — callers should sort. ELTS releases are gated behind a paywall
// and cannot be downloaded, so they are skipped.
func (b *Builder) ListReleases(ctx context.Context) ([]string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://get.typo3.org/api/v1/release/", nil)
	req.Header.Set("User-Agent", "t3scan-builddb/1.0")
	resp, err := b.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("release API: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var rels []Release
	if err := json.Unmarshal(body, &rels); err != nil {
		return nil, fmt.Errorf("release API: parse: %w", err)
	}
	var out []string
	for _, r := range rels {
		if r.ELTS || r.Version == "" {
			continue
		}
		// Skip pre-releases / dev tags; keep plain a.b.c.
		if splitVer(r.Version) == [3]int{} && r.Version != "0.0.0" {
			continue
		}
		out = append(out, r.Version)
	}
	sort.Sort(byVersion(out))
	return out, nil
}

// Build downloads each version, hashes its public static files, and assembles a
// DB. Files whose content is identical across every version are pruned (they
// carry no signal); everything else is kept for path-based (legacy) and
// content-based (composer) matching.
func (b *Builder) Build(ctx context.Context, versions []string, stamp string) (*DB, error) {
	type verFiles struct {
		version string
		files   map[string]string // path -> md5
		err     error
	}
	results := make([]verFiles, len(versions))

	var wg sync.WaitGroup
	sem := make(chan struct{}, b.Concurrency)
	var done int
	var mu sync.Mutex
	for i, v := range versions {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, v string) {
			defer wg.Done()
			defer func() { <-sem }()
			files, err := b.hashVersion(ctx, v)
			results[i] = verFiles{version: v, files: files, err: err}
			mu.Lock()
			done++
			n := done
			mu.Unlock()
			if err != nil {
				b.log("[%d/%d] %s FAILED: %v", n, len(versions), v, err)
			} else {
				b.log("[%d/%d] %s: %d files", n, len(versions), v, len(files))
			}
		}(i, v)
	}
	wg.Wait()

	// Accumulate: path -> md5 -> versions.
	db := &DB{Files: map[string]map[string][]string{}, BuiltAt: stamp}
	var covered []string
	for _, r := range results {
		if r.err != nil || len(r.files) == 0 {
			continue
		}
		covered = append(covered, r.version)
		for path, sum := range r.files {
			m := db.Files[path]
			if m == nil {
				m = map[string][]string{}
				db.Files[path] = m
			}
			m[sum] = append(m[sum], r.version)
		}
	}
	sort.Sort(byVersion(covered))
	db.Versions = covered

	b.prune(db)
	return db, nil
}

// prune drops paths that never discriminate (a single hash bucket spanning all
// covered versions) unless they are curated DefaultProbes, and sorts version
// lists. This keeps the DB compact while retaining every signal-bearing file.
func (b *Builder) prune(db *DB) {
	keepAlways := toSet(DefaultProbes)
	total := len(db.Versions)
	for path, buckets := range db.Files {
		// Sort each bucket's version list.
		for h := range buckets {
			sort.Sort(byVersion(buckets[h]))
		}
		if keepAlways[path] {
			continue
		}
		// Single bucket covering (nearly) every version ⇒ no signal.
		if len(buckets) == 1 {
			for _, vs := range buckets {
				if len(vs) >= total {
					delete(db.Files, path)
				}
			}
		}
	}
}

// hashVersion downloads and streams one release tarball, returning path->md5 for
// each hashable static file. Nothing is written to disk.
func (b *Builder) hashVersion(ctx context.Context, version string) (map[string]string, error) {
	url := "https://cdn.typo3.com/typo3/" + version + "/typo3_src-" + version + ".tar.gz"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "t3scan-builddb/1.0")
	resp, err := b.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download %s: HTTP %d", version, resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	out := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Strip the leading "typo3_src-<v>/" directory.
		name := hdr.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		if !hashable(name) {
			continue
		}
		h := md5.New()
		if _, err := io.Copy(h, io.LimitReader(tr, 16<<20)); err != nil {
			return nil, err
		}
		out[name] = hex.EncodeToString(h.Sum(nil))
	}
	return out, nil
}

// HashFull, when set on a build, hashes the entire Resources/Public tree
// (deep). Off by default: only depth-1 public files are hashed, which keeps the
// embedded DB compact while retaining the high-signal, per-patch-changing
// files (backend.css, top-level backend JS, icons.json, the ckeditor bundle).
var HashFull = false

// hashable reports whether a tarball path is a static file worth fingerprinting.
func hashable(name string) bool {
	for _, p := range DefaultProbes {
		if name == p {
			return true
		}
	}
	if !strings.HasPrefix(name, "typo3/sysext/") {
		return false
	}
	const marker = "/Resources/Public/"
	i := strings.Index(name, marker)
	if i < 0 {
		return false
	}
	switch {
	case strings.HasSuffix(name, ".js"),
		strings.HasSuffix(name, ".css"),
		strings.HasSuffix(name, ".json"),
		strings.HasSuffix(name, ".svg"):
	default:
		return false
	}
	if HashFull {
		return true
	}
	// backend and core are the sysexts whose /_assets/<md5>/ prefix a composer
	// scan can actually reach (their assets are on the login page), so their
	// FULL depth is worth hashing — the deep files (form-engine/**, code-editor,
	// dompurify, …) change per-patch and split bands the shallow files can't.
	if strings.HasPrefix(name, "typo3/sysext/backend/") || strings.HasPrefix(name, "typo3/sysext/core/") {
		return true
	}
	// Everything else: at most one directory level under Resources/Public/, so
	// Css/backend.css and JavaScript/modal.js qualify but the deep
	// Contrib/@ckeditor/** and translation trees (which balloon the DB) do not.
	rest := name[i+len(marker):]
	return strings.Count(rest, "/") <= 1
}
