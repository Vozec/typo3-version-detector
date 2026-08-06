package t3finger

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ExtBuilder builds the extension DB by downloading real extension packages from
// the TYPO3 Extension Repository (TER) and recording, per extension: its
// dependencies, presence-probe files, and the content hash of every web-servable
// static file across versions (the per-version diff used to fingerprint the
// installed version of a plugin/theme).
type ExtBuilder struct {
	Concurrency int
	MaxVersions int // most-recent versions to hash per extension (0 = all)
	Progress    func(string)
	HTTP        *http.Client
}

// NewExtBuilder returns an ExtBuilder with sane defaults. The HTTP client uses a
// large idle-connection pool so high -c concurrency reuses keep-alive
// connections instead of churning a new TCP+TLS handshake per download.
func NewExtBuilder() *ExtBuilder {
	tr := &http.Transport{
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 512,
		IdleConnTimeout:     90 * time.Second,
	}
	return &ExtBuilder{Concurrency: 8, MaxVersions: 0, HTTP: &http.Client{Timeout: 120 * time.Second, Transport: tr}}
}

// fetch GETs a URL with retries on throttling (429) and transient 5xx/network
// errors, so a high-concurrency build does not silently drop versions when TER
// rate-limits. Returns the body and whether it ultimately succeeded (HTTP 200).
func (b *ExtBuilder) fetch(ctx context.Context, url string, limit int64) ([]byte, bool) {
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			// linear-ish backoff: 0.5s, 1s, 1.5s, 2s
			select {
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			case <-ctx.Done():
				return nil, false
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, false
		}
		req.Header.Set("User-Agent", "t3scan-buildextdb/1.0")
		resp, err := b.HTTP.Do(req)
		if err != nil {
			continue // network error → retry
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			continue // throttled / transient → retry
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, false // 404 etc. → definitive miss, no retry
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
		resp.Body.Close()
		if err != nil {
			continue
		}
		return body, true
	}
	return nil, false
}

func (b *ExtBuilder) log(f string, a ...any) {
	if b.Progress != nil {
		b.Progress(fmt.Sprintf(f, a...))
	}
}

var (
	reExtBlock   = regexp.MustCompile(`(?s)<extension extensionkey="([^"]+)">(.*?)</extension>`)
	reVerBlock   = regexp.MustCompile(`(?s)<version version="([^"]+)">(.*?)</version>`)
	reComposerJS = regexp.MustCompile(`"name"\s*:\s*"([a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*)"`)
	reAuthorName = regexp.MustCompile(`<authorname>([^<]*)</authorname>`)
	reAuthorCo   = regexp.MustCompile(`<authorcompany>([^<]*)</authorcompany>`)
	reOwnerUser  = regexp.MustCompile(`<ownerusername>([^<]*)</ownerusername>`)
)

// allVersions downloads the TER catalogue and returns key -> sorted version list.
func (b *ExtBuilder) allVersions(ctx context.Context) (map[string][]string, error) {
	vers, _, err := b.catalogue(ctx)
	return vers, err
}

// CatMeta is the catalogue metadata for one extension key (identity that lives
// in the TER index itself, so it is fetched without any per-version download).
type CatMeta struct {
	Author string // authorname (fall back to authorcompany)
	Owner  string // ownerusername — the TER account that owns the key
}

// catalogue downloads the TER extensions index and returns, per key, its sorted
// version list and its metadata (author/owner from the newest version block).
func (b *ExtBuilder) catalogue(ctx context.Context) (map[string][]string, map[string]CatMeta, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, terExtensionsURL, nil)
	req.Header.Set("User-Agent", "t3scan-buildextdb/1.0")
	resp, err := b.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("TER: HTTP %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	defer gz.Close()
	data, err := io.ReadAll(io.LimitReader(gz, 256<<20))
	if err != nil {
		return nil, nil, err
	}
	vers := map[string][]string{}
	meta := map[string]CatMeta{}
	for _, em := range reExtBlock.FindAllSubmatch(data, -1) {
		key := string(em[1])
		var vs []string
		for _, vm := range reVerBlock.FindAllSubmatch(em[2], -1) {
			vs = append(vs, string(vm[1]))
		}
		sort.Sort(byVersion(vs))
		vers[key] = vs
		meta[key] = CatMeta{Author: lastNonEmpty(reAuthorName, em[2], reAuthorCo), Owner: lastNonEmpty(reOwnerUser, em[2], nil)}
	}
	return vers, meta, nil
}

// lastNonEmpty returns the last non-empty capture of re in block (the newest
// version's value; the index lists versions oldest-first), falling back to the
// last capture of `alt` if every primary match is blank.
func lastNonEmpty(re *regexp.Regexp, block []byte, alt *regexp.Regexp) string {
	pick := func(r *regexp.Regexp) string {
		out := ""
		for _, m := range r.FindAllSubmatch(block, -1) {
			if v := strings.TrimSpace(string(m[1])); v != "" {
				out = v
			}
		}
		return out
	}
	if v := pick(re); v != "" {
		return v
	}
	if alt != nil {
		return pick(alt)
	}
	return ""
}

// CatalogueAuthors downloads the TER index and returns key -> author/owner meta.
// Used to enrich an existing DB without re-downloading any package.
func (b *ExtBuilder) CatalogueAuthors(ctx context.Context) (map[string]CatMeta, error) {
	_, meta, err := b.catalogue(ctx)
	return meta, err
}

// BuildExtProbeDB builds full records for the given extension keys.
func (b *ExtBuilder) BuildExtProbeDB(ctx context.Context, keys []string, stamp string) (*ExtProbeDB, error) {
	b.log("resolving versions from TER…")
	catalogue, err := b.allVersions(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]*ExtEntry, len(keys))
	names := make([]string, len(keys))
	var wg sync.WaitGroup
	sem := make(chan struct{}, b.Concurrency)
	var done, found, dl int
	var mu sync.Mutex

	for i, key := range keys {
		vers := catalogue[key]
		if len(vers) == 0 {
			continue
		}
		// Newest-first, capped.
		ordered := append([]string(nil), vers...)
		for l, r := 0, len(ordered)-1; l < r; l, r = l+1, r-1 {
			ordered[l], ordered[r] = ordered[r], ordered[l]
		}
		if b.MaxVersions > 0 && len(ordered) > b.MaxVersions {
			ordered = ordered[:b.MaxVersions]
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, key string, ordered []string) {
			defer wg.Done()
			defer func() { <-sem }()
			e, n := b.buildOne(ctx, key, ordered)
			mu.Lock()
			done++
			dl += n
			if e != nil && len(e.Probes) > 0 {
				results[i], names[i] = e, key
				found++
			}
			cur := done
			mu.Unlock()
			if cur%50 == 0 {
				b.log("%d/%d extensions, %d built, %d version-downloads", cur, len(keys), found, dl)
			}
		}(i, key, ordered)
	}
	wg.Wait()

	db := &ExtProbeDB{BuiltAt: stamp, Extensions: map[string]ExtEntry{}}
	for i, e := range results {
		if e != nil {
			pruneEntry(e) // this entry-point yields a compact (embeddable) DB
			db.Extensions[names[i]] = *e
		}
	}
	b.log("done: %d extensions", len(db.Extensions))
	return db, nil
}

// buildOne downloads the given versions of one extension and assembles its
// record (probes, dependencies, per-version file hashes). Returns the entry and
// how many version-zips were downloaded.
func (b *ExtBuilder) buildOne(ctx context.Context, key string, versions []string) (*ExtEntry, int) {
	e := &ExtEntry{Files: map[string]map[string][]string{}}
	downloads := 0
	var latestNames []string

	for _, v := range versions {
		names, composer, requires, hashes, ok := b.hashVersion(ctx, key, v)
		if !ok {
			continue
		}
		downloads++
		e.Versions = append(e.Versions, v)
		// The first successful (newest) version defines identity + probes + deps.
		if e.Latest == "" {
			e.Latest = v
			e.Composer = composer
			e.Requires = requires
			latestNames = names
		}
		for path, sum := range hashes {
			m := e.Files[path]
			if m == nil {
				m = map[string][]string{}
				e.Files[path] = m
			}
			m[sum] = append(m[sum], v)
		}
	}
	if len(e.Versions) == 0 {
		return nil, downloads
	}
	sort.Sort(byVersion(e.Versions))
	e.Probes = selectProbeFiles(latestNames)
	// NOTE: buildOne returns an UNPRUNED entry (every hashed public file). The
	// caller decides: BuildExtProbeDB prunes for a compact embed DB; the raw
	// working DB keeps everything so incremental updates stay correct.
	return e, downloads
}

// hashVersion downloads one version zip and returns its file names, composer
// name, requires, and path->md5 for web-servable static files.
func (b *ExtBuilder) hashVersion(ctx context.Context, key, version string) (names []string, composer string, requires map[string]string, hashes map[string]string, ok bool) {
	url := "https://extensions.typo3.org/extension/download/" + key + "/" + version + "/zip"
	raw, ok := b.fetch(ctx, url, 96<<20)
	if !ok {
		return nil, "", nil, nil, false
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, "", nil, nil, false
	}
	hashes = map[string]string{}
	for _, zf := range zr.File {
		name := strings.TrimPrefix(zf.Name, "./")
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		names = append(names, name)
		if name == "composer.json" {
			if rc, err := zf.Open(); err == nil {
				body, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
				rc.Close()
				if m := reComposerJS.FindSubmatch(body); m != nil && composer == "" {
					composer = string(m[1])
				}
				requires = parseRequires(body)
			}
		}
		if hashableExtFile(name) {
			if rc, err := zf.Open(); err == nil {
				h := md5.New()
				io.Copy(h, io.LimitReader(rc, 8<<20))
				rc.Close()
				hashes[name] = hex.EncodeToString(h.Sum(nil))
			}
		}
	}
	return names, composer, requires, hashes, true
}

// pruneEntry drops file paths whose content is identical across every covered
// version (no version signal), keeping the embedded DB compact. Probe files are
// kept regardless. Operates in place; call on a clone to preserve the raw entry.
func pruneEntry(e *ExtEntry) {
	total := len(e.Versions)
	keep := map[string]bool{}
	for _, p := range e.Probes {
		keep[p] = true
	}
	for path, buckets := range e.Files {
		for h := range buckets {
			sort.Sort(byVersion(buckets[h]))
		}
		if keep[path] {
			continue
		}
		if len(buckets) == 1 {
			for _, vs := range buckets {
				if len(vs) >= total {
					delete(e.Files, path)
				}
			}
		}
	}
	if len(e.Files) == 0 {
		e.Files = nil
	}
}

// hashableExtFile reports whether a path inside an extension is a web-servable
// static file worth fingerprinting for version diffing.
func hashableExtFile(name string) bool {
	if strings.Contains(name, "/Tests/") || strings.Contains(name, "/Documentation/") || strings.Contains(name, "node_modules") {
		return false
	}
	if !strings.Contains(name, "Resources/Public/") {
		return false
	}
	switch {
	case strings.HasSuffix(name, ".js"),
		strings.HasSuffix(name, ".css"),
		strings.HasSuffix(name, ".svg"),
		strings.HasSuffix(name, ".png"),
		strings.HasSuffix(name, ".gif"),
		strings.HasSuffix(name, ".json"),
		strings.HasSuffix(name, ".map"):
		return true
	}
	return false
}

// parseRequires extracts the composer "require" map (dependencies).
func parseRequires(body []byte) map[string]string {
	var doc struct {
		Require map[string]string `json:"require"`
	}
	if json.Unmarshal(body, &doc) == nil && len(doc.Require) > 0 {
		return doc.Require
	}
	return nil
}

// selectProbeFiles picks up to 4 web-servable, stable presence-marker files,
// most-reliable first.
func selectProbeFiles(names []string) []string {
	isPublic := func(n string) bool {
		if strings.Contains(n, "/Tests/") || strings.Contains(n, "/Documentation/") || strings.Contains(n, "node_modules") {
			return false
		}
		return strings.Contains(n, "Resources/Public/")
	}
	ext := func(n, e string) bool { return strings.HasSuffix(strings.ToLower(n), e) }
	assetExt := func(n string) bool {
		return ext(n, ".svg") || ext(n, ".png") || ext(n, ".gif") || ext(n, ".ico") || ext(n, ".css") || ext(n, ".js")
	}
	var out []string
	add := func(n string) {
		for _, x := range out {
			if x == n {
				return
			}
		}
		out = append(out, n)
	}
	for _, n := range names {
		if strings.HasSuffix(n, "Resources/Public/Icons/Extension.svg") {
			add(n)
			break
		}
	}
	var icons, publics []string
	for _, n := range names {
		if !isPublic(n) || !assetExt(n) {
			continue
		}
		if strings.Contains(n, "Resources/Public/Icons/") {
			icons = append(icons, n)
		}
		publics = append(publics, n)
	}
	sort.Slice(icons, func(i, j int) bool { return len(icons[i]) < len(icons[j]) })
	sort.Slice(publics, func(i, j int) bool { return len(publics[i]) < len(publics[j]) })
	if len(icons) > 0 {
		add(icons[0])
	}
	if len(publics) > 0 {
		add(publics[0])
	}
	for _, cand := range []string{"ext_icon.svg", "ext_icon.gif", "ext_icon.png"} {
		for _, n := range names {
			if n == cand {
				add(n)
			}
		}
	}
	for _, n := range names {
		if n == "ext_emconf.php" {
			add(n)
		}
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}
