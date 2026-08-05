package t3finger

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// reImportmap captures the JSON of a backend ES-module importmap. TYPO3 12+
// renders one on /typo3/; its module URLs are the richest composer-mode version
// signal (dozens of core JS files, added/removed/renamed each release).
var reImportmap = regexp.MustCompile(`(?is)<script[^>]+type=["']importmap["'][^>]*>(.*?)</script>`)

// extractImportmapURLs returns the module URLs from an importmap script block.
func extractImportmapURLs(body []byte) []string {
	m := reImportmap.FindSubmatch(body)
	if m == nil {
		return nil
	}
	var doc struct {
		Imports map[string]string `json:"imports"`
	}
	if err := json.Unmarshal(m[1], &doc); err != nil {
		return nil
	}
	out := make([]string, 0, len(doc.Imports))
	seen := map[string]bool{}
	for _, u := range doc.Imports {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// Mode is the install layout of a TYPO3 target.
type Mode string

const (
	ModeComposer Mode = "composer" // TYPO3 >= 11 default: core under vendor/, assets under /_assets/<md5>/
	ModeLegacy   Mode = "legacy"   // classic layout: typo3/sysext/** web-served
	ModeUnknown  Mode = "unknown"
)

// FileProbe is the outcome of hashing one served file.
type FileProbe struct {
	Path     string   `json:"path"`
	Status   int      `json:"status"`
	MD5      string   `json:"md5,omitempty"`
	Size     int      `json:"size,omitempty"`
	Matched  bool     `json:"matched"`
	Versions []string `json:"versions,omitempty"`
	ByPath   bool     `json:"byPath,omitempty"` // matched on exact path (legacy) vs content-only
}

// VersionResult is the full version-detection report for one target.
type VersionResult struct {
	Target     string      `json:"target"`
	IsTypo3    bool        `json:"isTypo3"`
	Mode       Mode        `json:"mode"`
	BasePath   string      `json:"basePath,omitempty"`
	Version    string      `json:"version,omitempty"`      // best single answer, when confident
	Range      string      `json:"versionRange,omitempty"` // human summary
	Candidates []string    `json:"candidates,omitempty"`
	Confidence string      `json:"confidence"` // high | medium | low
	Method     string      `json:"method,omitempty"`
	Markers    []string    `json:"markers,omitempty"` // is-TYPO3 evidence
	Files      []FileProbe `json:"files,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
	// LatestInBranch is the newest stable release of the detected version's
	// branch (e.g. 13.4.35 for a 13.4.x target); NewestOverall is the newest
	// stable TYPO3 release overall. Outdated is set when the target is behind
	// its branch's latest patch. Sourced from the get.typo3.org release feed.
	LatestInBranch string `json:"latestInBranch,omitempty"`
	NewestOverall  string `json:"newestOverall,omitempty"`
	Outdated       bool   `json:"outdated,omitempty"`
	// ExtensionsHint lists extension keys passively discovered in the served
	// HTML (from typo3conf/ext/<key>/ asset URLs) — free, no enumeration needed.
	ExtensionsHint []string `json:"extensionsHint,omitempty"`
	// Findings holds security-relevant pre-auth observations (exposed install
	// tool, debug mode, XML sitemap, host-header disclosure, …).
	Findings []Finding `json:"findings,omitempty"`

	// conflict is set when two probes' version sets were disjoint (contradictory
	// evidence) — caps confidence so a post-conflict singleton isn't "high".
	conflict bool `json:"-"`
	// Vulnerabilities lists published core advisories affecting the detected
	// version. Maybe holds advisories affecting only some candidates when the
	// version is a range (uncertain until the version is pinned).
	Vulnerabilities []Advisory `json:"vulnerabilities,omitempty"`
	Maybe           []Advisory `json:"maybeVulnerable,omitempty"`
}

// Detect fingerprints the TYPO3 version of rawURL.
func (f *Fingerprinter) Detect(ctx context.Context, rawURL string) (*VersionResult, error) {
	base, err := normalizeBase(rawURL)
	if err != nil {
		return nil, err
	}
	res := &VersionResult{Target: base, Mode: ModeUnknown}

	// 1. Identify TYPO3 + install mode + base path, harvesting asset URLs.
	assets := f.identify(ctx, base, res)

	// Calibrate a soft-404 / catch-all fingerprint: a bogus static-asset URL
	// that must not exist. If the host answers it with a 200 body, that body is
	// its generic catch-all page — any probe returning the same bytes is that
	// page, not a real asset, and must be ignored so it can never false-match.
	cal := f.calibrate(ctx, base, res.BasePath)

	// 2. Content-based exact reads (legacy installs, or exposed docroot files).
	exact := f.exactVersionReads(ctx, base, res)

	// 3. Hash static assets and intersect candidate version sets.
	//    - legacy: probe curated + DB-discriminating paths directly under base.
	//    - composer/any: hash the harvested asset URLs by content only.
	var (
		inter    map[string]bool
		interSet bool
	)
	narrow := func(vs []string) {
		if len(vs) == 0 {
			return
		}
		s := toSet(vs)
		if !interSet {
			inter, interSet = s, true
			return
		}
		merged := map[string]bool{}
		for v := range inter {
			if s[v] {
				merged[v] = true
			}
		}
		if len(merged) == 0 {
			// Disjoint evidence — keep the accumulated set but flag the conflict
			// so a resulting singleton can't be reported as high confidence.
			res.conflict = true
			return
		}
		inter = merged
	}

	// Legacy path-probing hits typo3/sysext/** directly — pointless in composer
	// mode (vendor/ is hidden, every such path 404s), where it would waste ~80
	// requests per target. There we rely on discovered/importmap assets instead.
	var legacy []FileProbe
	if res.Mode != ModeComposer {
		legacy = f.hashLegacyProbes(ctx, base, res, cal)
		for _, fp := range legacy {
			if fp.Matched {
				narrow(fp.Versions)
			}
		}
	}
	discovered := f.hashDiscoveredAssets(ctx, base, assets, res, cal)
	for _, fp := range discovered {
		if fp.Matched {
			narrow(fp.Versions)
		}
	}
	// Active composer probing: once a package's /_assets/<md5>/ prefix is known
	// (from a matched harvested asset), construct and probe EVERY discriminating
	// file that package ships — including ones the HTML never links — to split a
	// band the linked assets can't (e.g. color-picker.js / event-handler.js
	// changing mid-patch-range). This is the main composer-mode precision lever.
	if res.Mode == ModeComposer && interSet {
		var current []string
		for v := range inter {
			current = append(current, v)
		}
		for _, fp := range f.activeComposerProbe(ctx, base, discovered, current, res) {
			if fp.Matched {
				narrow(fp.Versions)
			}
		}
	}

	// Presence-based narrowing (add/remove boundaries). When the host cleanly
	// 404s a bogus asset (cal.status == 404), a served (200) core file that we
	// could NOT content-match still bounds the version: candidate ⊆ the versions
	// that ship that path. This bands the major even for a patch newer than the
	// DB or a themed/hardened target (e.g. kebab-case modal.js ⇒ ≥12, CamelCase
	// Modal.js ⇒ ≤11). Gated on a clean host so a per-path catch-all can't misfire.
	if cal.status == 404 {
		presenceNarrowed := false
		for _, fp := range legacy {
			if fp.Matched || fp.Status != 200 || !strings.HasPrefix(fp.Path, "typo3/") {
				continue
			}
			if having := f.DB.VersionsHavingFile(fp.Path); len(having) > 0 {
				narrow(having)
				presenceNarrowed = true
			}
		}
		if presenceNarrowed {
			res.Notes = append(res.Notes, "version bounded by which core files are present/absent (add/remove boundaries), not only content hashes")
		}

		// Absence narrowing — LEGACY installs only. There the whole typo3/sysext
		// tree is genuinely web-served, so a 404 for a DB-known path means the
		// file truly does not exist in that version: candidate ⊆ the versions
		// that DO NOT ship it. NOT applied in composer/unknown mode, where a 404
		// merely reflects vendor/ being hidden and would wrongly exclude
		// everything. Requires a stock file already confirmed (a content match),
		// so a custom theme dropping a file can't cause a false exclusion.
		if res.Mode == ModeLegacy && stockConfirmed(legacy) {
			all := toSet(f.DB.Versions)
			for _, fp := range legacy {
				if fp.Status != 404 || !strings.HasPrefix(fp.Path, "typo3/") {
					continue
				}
				having := toSet(f.DB.VersionsHavingFile(fp.Path))
				if len(having) == 0 {
					continue
				}
				var comp []string
				for v := range all {
					if !having[v] {
						comp = append(comp, v)
					}
				}
				if len(comp) > 0 {
					narrow(comp)
				}
			}
		}
	}

	if interSet {
		for v := range inter {
			res.Candidates = append(res.Candidates, v)
		}
		sort.Sort(byVersion(res.Candidates))
	}

	// Behavioural confirmation + major-version boundary (eID handlers), and
	// security-relevant recon (install tool, debug mode, sitemap, host header).
	f.probeBehavioral(ctx, base, res)
	f.probeRecon(ctx, base, res)

	f.summarize(res, exact)
	f.annotateFreshness(res)
	f.assessVulnerabilities(res)
	return res, nil
}

// annotateFreshness marks how far the detected version is behind the latest
// stable release of its branch (and the newest overall).
func (f *Fingerprinter) annotateFreshness(res *VersionResult) {
	if f.Releases == nil {
		return
	}
	res.NewestOverall = f.Releases.Latest
	// The best (highest) version we detected — a band's top, or the pinned one.
	top := res.Version
	if top == "" && len(res.Candidates) > 0 {
		top = res.Candidates[len(res.Candidates)-1]
	}
	if top == "" {
		return
	}
	if latest := f.Releases.LatestForBranch(top); latest != "" {
		res.LatestInBranch = latest
		res.Outdated = CompareVersions(top, latest) < 0
	}
}

// assessVulnerabilities maps the detected version (or candidate range) to
// published core advisories. When the version is pinned, matching advisories are
// certain; for a range, an advisory affecting ALL candidates is certain and one
// affecting only SOME is reported as "maybe".
func (f *Fingerprinter) assessVulnerabilities(res *VersionResult) {
	if f.Advisories == nil || len(f.Advisories.Advisories) == 0 {
		return
	}
	// Assessment set: the pinned version, else every candidate.
	var set []string
	switch {
	case res.Version != "":
		set = []string{res.Version}
	case len(res.Candidates) > 0:
		set = res.Candidates
	default:
		return
	}
	for _, a := range f.Advisories.Advisories {
		hit, miss := 0, 0
		for _, v := range set {
			if a.Affects(v) {
				hit++
			} else {
				miss++
			}
		}
		switch {
		case hit == len(set):
			res.Vulnerabilities = append(res.Vulnerabilities, a)
		case hit > 0 && miss > 0:
			res.Maybe = append(res.Maybe, a)
		}
	}
	SortBySeverity(res.Vulnerabilities)
	SortBySeverity(res.Maybe)
}

// DetectMode does a light identify pass and reports the install layout, so the
// extension enumerator can pick the right technique (Composer /_assets/ vs
// legacy /typo3conf/ext/). Returns ModeUnknown if it can't tell.
func (f *Fingerprinter) DetectMode(ctx context.Context, target string) (Mode, error) {
	base, err := normalizeBase(target)
	if err != nil {
		return ModeUnknown, err
	}
	res := &VersionResult{Target: base, Mode: ModeUnknown}
	f.identify(ctx, base, res)
	return res.Mode, nil
}

// identify fetches the identify pages, sets IsTypo3/Mode/BasePath, and returns
// the set of absolute asset URLs discovered in the HTML.
func (f *Fingerprinter) identify(ctx context.Context, base string, res *VersionResult) []string {
	seen := map[string]bool{}
	var assets []string
	addAsset := func(raw, pageURL string) {
		abs := resolveURL(pageURL, raw)
		if abs != "" && !seen[abs] {
			seen[abs] = true
			assets = append(assets, abs)
		}
	}

	markers := map[string]bool{}
	hints := map[string]bool{}
	for _, page := range identifyPages {
		full := base + page
		r, err := f.get(ctx, full)
		if err != nil || r == nil {
			continue
		}
		body := r.Body
		// Passively harvest extension keys referenced in the HTML (free, no
		// enumeration): typo3conf/ext/<key>/… and EXT:<key> resource paths.
		for _, m := range reExtKeyInPath.FindAllSubmatch(body, -1) {
			hints[string(m[1])] = true
		}
		// TYPO3 session/install cookies are a strong marker even when the HTML
		// carries no "powered by" comment or generator tag.
		for _, sc := range r.Header.Values("Set-Cookie") {
			low := strings.ToLower(sc)
			switch {
			case strings.HasPrefix(low, "fe_typo_user"):
				markers["fe_typo_user cookie"] = true
				res.IsTypo3 = true
			case strings.HasPrefix(low, "be_typo_user"):
				markers["be_typo_user cookie"] = true
				res.IsTypo3 = true
			case strings.HasPrefix(low, "typo3installtool") || strings.HasPrefix(low, "typo3_install"):
				markers["Typo3InstallTool cookie"] = true
				res.IsTypo3 = true
			}
		}
		if rePoweredBy.Match(body) {
			markers["powered-by-typo3 comment"] = true
			res.IsTypo3 = true
		}
		if reGenerator.Match(body) {
			markers["<meta generator=TYPO3 CMS>"] = true
			res.IsTypo3 = true
		}
		if reBackendHint.Match(body) || r.Status == 401 || r.Status == 403 {
			if page == "/typo3/" || page == "/typo3/index.php" {
				markers["typo3 backend endpoint"] = true
				res.IsTypo3 = true
			}
		}
		// Asset-path leakage → mode + base path.
		if m := reAssetComposer.FindAllSubmatch(body, -1); m != nil {
			res.Mode = ModeComposer
			markers["/_assets/<md5>/ (composer mode)"] = true
			res.IsTypo3 = true
		}
		if m := reAssetLegacy.FindAllSubmatch(body, -1); m != nil {
			if res.Mode != ModeComposer {
				res.Mode = ModeLegacy
			}
			markers["typo3conf/typo3/sysext asset paths"] = true
			res.IsTypo3 = true
			if res.BasePath == "" {
				res.BasePath = deriveBasePath(string(m[0][1]))
			}
		}
		for _, mm := range reAnyAsset.FindAllSubmatch(body, -1) {
			addAsset(string(mm[1]), r.finalURL(full))
		}
		// The backend importmap (on /typo3/) lists dozens of core JS module URLs
		// that aren't href/src — harvest them: their content pins the version far
		// more tightly than the handful of FE assets (esp. in composer mode).
		if imps := extractImportmapURLs(body); len(imps) > 0 {
			markers["backend importmap (ES modules)"] = true
			res.IsTypo3 = true
			for _, u := range imps {
				addAsset(u, r.finalURL(full))
			}
		}
	}

	// A random path: default TYPO3 error page contains "TYPO3 CMS".
	if r, err := f.get(ctx, base+"/"+randToken()+"-notfound"); err == nil && r != nil {
		if r.Status == 404 && reTypo3CMS.Match(r.Body) {
			markers["TYPO3 CMS 404 page"] = true
			res.IsTypo3 = true
		}
	}

	for m := range markers {
		res.Markers = append(res.Markers, m)
	}
	sort.Strings(res.Markers)
	for k := range hints {
		res.ExtensionsHint = append(res.ExtensionsHint, k)
	}
	sort.Strings(res.ExtensionsHint)
	return assets
}

// exactVersionReads tries to read an exact version straight from an exposed
// file (best possible signal). Returns the version string, or "".
func (f *Fingerprinter) exactVersionReads(ctx context.Context, base string, res *VersionResult) string {
	// composer.lock at docroot pins typo3/cms-core exactly.
	if r, err := f.getProbe(ctx, base+"/composer.lock"); err == nil && r != nil && r.Status == 200 {
		if m := reLockCmsCore.FindSubmatch(r.Body); m != nil {
			res.IsTypo3 = true
			res.Notes = append(res.Notes, "read exact version from exposed /composer.lock (typo3/cms-core)")
			return string(m[1])
		}
	}
	// docroot composer.json → require constraint (coarse, note only).
	if r, err := f.getProbe(ctx, base+"/composer.json"); err == nil && r != nil && r.Status == 200 {
		if strings.Contains(string(r.Body), "typo3/cms-core") || strings.Contains(string(r.Body), "typo3/cms-") {
			res.IsTypo3 = true
			res.Notes = append(res.Notes, "site /composer.json is exposed (declares typo3/cms-* dependency)")
		}
	}
	// core sysext ext_emconf.php (legacy) — exact core version.
	if r, err := f.getProbe(ctx, base+"/typo3/sysext/core/ext_emconf.php"); err == nil && r != nil && r.Status == 200 {
		if m := reEmconfVersion.FindSubmatch(r.Body); m != nil {
			res.IsTypo3 = true
			res.Notes = append(res.Notes, "read exact version from typo3/sysext/core/ext_emconf.php")
			return string(m[1])
		}
	}
	return ""
}

// calib holds the soft-404 / catch-all fingerprint of a target.
type calib struct {
	status int
	md5    string // md5 of the catch-all body, "" if the host cleanly 404s
}

// isCatchAll reports whether a probe outcome is just the host's generic page.
func (c calib) isCatchAll(status int, md5hex string) bool {
	return c.md5 != "" && md5hex == c.md5
}

// calibrate fetches a bogus static-asset path and records its response so real
// asset probes can be told apart from a 200 catch-all / soft-404 page.
func (f *Fingerprinter) calibrate(ctx context.Context, base, basePath string) calib {
	prefix := base
	if basePath != "" {
		prefix = base + "/" + strings.Trim(basePath, "/")
	}
	bogus := prefix + "/typo3/sysext/core/Resources/Public/" + randToken() + "-nope.css"
	r, err := f.getProbe(ctx, bogus)
	if err != nil || r == nil {
		return calib{}
	}
	c := calib{status: r.Status}
	if r.Status == 200 && len(r.Body) > 0 {
		sum := md5.Sum(r.Body)
		c.md5 = hex.EncodeToString(sum[:])
	}
	return c
}

// hashLegacyProbes hashes curated + DB-discriminating paths directly under the
// base (works for legacy installs, where typo3/sysext/** is web-served).
func (f *Fingerprinter) hashLegacyProbes(ctx context.Context, base string, res *VersionResult, cal calib) []FileProbe {
	paths := f.legacyProbePaths()
	prefix := base
	if res.BasePath != "" {
		prefix = base + "/" + strings.Trim(res.BasePath, "/")
	}

	out := make([]FileProbe, len(paths))
	var wg sync.WaitGroup
	sem := make(chan struct{}, f.conc())
	for i, p := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			fp := FileProbe{Path: p}
			r, err := f.getProbe(ctx, prefix+"/"+p)
			if err == nil && r != nil {
				fp.Status = r.Status
				// A real static asset is a direct 200 that isn't an HTML page.
				// A 3xx (redirect to a page) or an HTML body is NOT the asset.
				if r.Status == 200 && len(r.Body) > 0 && r.isAsset() {
					sum := md5.Sum(r.Body)
					fp.MD5 = hex.EncodeToString(sum[:])
					fp.Size = len(r.Body)
					if !cal.isCatchAll(r.Status, fp.MD5) {
						if vs := f.DB.VersionsForHash(p, fp.MD5); len(vs) > 0 {
							fp.Matched, fp.Versions, fp.ByPath = true, vs, true
						}
					} else {
						fp.Status = -1 // mark as catch-all so it's dropped below
					}
				} else if r.Status == 200 && !r.isAsset() {
					fp.Status = -1 // HTML page, not the asset → drop from the report
				}
			}
			out[i] = fp
		}(i, p)
	}
	wg.Wait()

	// Show only served/matched probes in the report, but return the FULL set —
	// the 404s are needed for absence narrowing in Detect.
	for _, fp := range out {
		if fp.Status == 200 || fp.Matched {
			res.Files = append(res.Files, fp)
		}
	}
	return out
}

var reAssetsPrefix = regexp.MustCompile(`^(.*/_assets/[0-9a-f]{32}/)(.+)$`)

// activeComposerProbe maps each /_assets/<md5>/ prefix that produced a match to
// its sysext, then probes ALL of that sysext's discriminating files under the
// prefix (path-exact matches) — catching discriminators the HTML never links.
func (f *Fingerprinter) activeComposerProbe(ctx context.Context, base string, discovered []FileProbe, current []string, res *VersionResult) []FileProbe {
	if f.DB.Empty() || len(current) < 2 {
		return nil // already pinned, nothing to split
	}
	band := toSet(current)
	// Map each /_assets/<md5>/ prefix to its sysext (typo3/sysext/backend/) — using
	// the matched asset's CONTENT md5 to disambiguate a sub-path that several
	// sysexts share (e.g. a JS filename present in both backend and t3skin).
	prefixSysext := map[string]string{}
	for _, fp := range discovered {
		if !fp.Matched || fp.MD5 == "" {
			continue
		}
		m := reAssetsPrefix.FindStringSubmatch(fp.Path)
		if m == nil {
			continue
		}
		pfx, sub := m[1], m[2]
		if _, ok := prefixSysext[pfx]; ok {
			continue
		}
		if sysext := f.dbSysextForAsset(sub, fp.MD5); sysext != "" {
			prefixSysext[pfx] = sysext
		}
	}
	if len(prefixSysext) == 0 {
		return nil
	}

	// Build the probe list: ONLY files that actually split the current candidate
	// band, ranked by how finely they split it (most distinct hashes within the
	// band first). This targets the exact discriminators — e.g. color-picker.js
	// splitting 13.4.27 from 13.4.28+ — instead of high-churn-overall files.
	type probe struct {
		url, dbpath string
		score       int
	}
	var probes []probe
	seen := map[string]bool{}
	for pfx, sysext := range prefixSysext {
		for _, dbpath := range f.DB.DiscriminatingUnderRanked(sysext) {
			sub := afterResourcesPublic(dbpath)
			if sub == "" {
				continue
			}
			score := f.DB.splitPower(dbpath, band)
			if score < 2 {
				continue // doesn't split the band
			}
			u := base + pfx + sub
			if seen[u] {
				continue
			}
			seen[u] = true
			probes = append(probes, probe{u, dbpath, score})
		}
	}
	if os.Getenv("T3DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[dbg] prefixSysext=%v probes=%d\n", prefixSysext, len(probes))
	}
	sort.Slice(probes, func(i, j int) bool { return probes[i].score > probes[j].score })
	const cap = 24
	if len(probes) > cap {
		probes = probes[:cap]
	}

	out := make([]FileProbe, len(probes))
	var wg sync.WaitGroup
	sem := make(chan struct{}, f.conc())
	for i, p := range probes {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p probe) {
			defer wg.Done()
			defer func() { <-sem }()
			fp := FileProbe{Path: compactAssetPath(p.url)}
			r, err := f.getProbe(ctx, p.url)
			if err == nil && r != nil && r.Status == 200 && len(r.Body) > 0 && r.isAsset() {
				sum := md5.Sum(r.Body)
				fp.MD5 = hex.EncodeToString(sum[:])
				fp.Status = 200
				if vs := f.DB.VersionsForHash(p.dbpath, fp.MD5); len(vs) > 0 {
					fp.Matched, fp.Versions, fp.ByPath = true, vs, true
				}
			}
			out[i] = fp
		}(i, p)
	}
	wg.Wait()
	for _, fp := range out {
		if fp.Matched {
			res.Files = append(res.Files, fp)
		}
	}
	return out
}

// dbSysextForAsset finds the sysext whose "Resources/Public/<sub>" file has the
// given content md5 — uniquely identifying the package behind an /_assets/<md5>/
// prefix even when several sysexts ship a file with the same sub-path.
func (f *Fingerprinter) dbSysextForAsset(sub, md5hex string) string {
	if f.subIndex == nil {
		f.subIndex = map[string]string{} // sub -> "p1|p2|..." (all full DB paths)
		for p := range f.DB.Files {
			if i := strings.Index(p, "Resources/Public/"); i >= 0 {
				key := p[i+len("Resources/Public/"):]
				if f.subIndex[key] == "" {
					f.subIndex[key] = p
				} else {
					f.subIndex[key] += "|" + p
				}
			}
		}
	}
	for _, p := range strings.Split(f.subIndex[sub], "|") {
		if p == "" {
			continue
		}
		if len(f.DB.VersionsForHash(p, md5hex)) > 0 {
			if i := strings.Index(p, "Resources/Public/"); i >= 0 {
				return p[:i]
			}
		}
	}
	return ""
}

// hashDiscoveredAssets hashes each harvested asset URL and matches by content
// only (path-independent) — the composer-mode path (/_assets/<md5>/) can't be
// mapped to a DB path, but the file's bytes still identify the version.
func (f *Fingerprinter) hashDiscoveredAssets(ctx context.Context, base string, assets []string, res *VersionResult, cal calib) []FileProbe {
	if len(assets) == 0 || f.DB.Empty() {
		return nil
	}
	// Only bother with same-host assets; prioritise the ones the DB can match
	// (depth-1 JS/CSS files whose basename the DB knows) and cap the count so a
	// large importmap doesn't explode into hundreds of requests.
	host := hostOf(base)
	known := f.dbBasenames()
	var priority, rest []string
	seen := map[string]bool{}
	for _, a := range assets {
		if hostOf(a) != host || seen[a] {
			continue
		}
		seen[a] = true
		if bn := baseNameNoQuery(a); known[bn] {
			priority = append(priority, a)
		} else {
			rest = append(rest, a)
		}
	}
	const maxAssets = 40
	targets := append(priority, rest...)
	if len(targets) > maxAssets {
		targets = targets[:maxAssets]
	}
	if len(targets) == 0 {
		return nil
	}

	out := make([]FileProbe, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, f.conc())
	for i, a := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, a string) {
			defer wg.Done()
			defer func() { <-sem }()
			fp := FileProbe{Path: compactAssetPath(a)}
			r, err := f.getProbe(ctx, a)
			if err == nil && r != nil {
				fp.Status = r.Status
				if r.Status == 200 && len(r.Body) > 0 && r.isAsset() {
					sum := md5.Sum(r.Body)
					fp.MD5 = hex.EncodeToString(sum[:])
					fp.Size = len(r.Body)
					if !cal.isCatchAll(r.Status, fp.MD5) {
						if vs := f.DB.VersionsForAnyHash(fp.MD5); len(vs) > 0 {
							fp.Matched, fp.Versions = true, vs
						}
					}
				}
			}
			out[i] = fp
		}(i, a)
	}
	wg.Wait()

	var kept []FileProbe
	for _, fp := range out {
		if fp.Matched {
			res.Files = append(res.Files, fp)
			kept = append(kept, fp)
		}
	}
	return kept
}

// legacyProbePaths is DefaultProbes plus any DB path that discriminates and is
// not already covered — so a fuller DB extends coverage automatically. Capped
// to keep the request count bounded.
func (f *Fingerprinter) legacyProbePaths() []string {
	out := append([]string(nil), DefaultProbes...)
	seen := toSet(DefaultProbes)
	add := func(paths []string, limit int) {
		n := 0
		for _, p := range paths {
			if n >= limit {
				break
			}
			if !seen[p] {
				out = append(out, p)
				seen[p] = true
				n++
			}
		}
	}
	// Content-discriminating paths (hash varies) narrow by content; a bounded
	// set of presence-discriminating paths (added/removed across releases) power
	// the add/remove-boundary narrowing. Ranked by discriminating power so the
	// probe budget hits the files that change most.
	add(f.DB.DiscriminatingPathsRanked(), 40)
	add(f.DB.PresenceDiscriminatingPaths(), 24)
	return out
}

// summarize turns the gathered evidence into a verdict.
func (f *Fingerprinter) summarize(res *VersionResult, exact string) {
	if res.Mode == ModeUnknown && res.IsTypo3 {
		// If we saw a backend but no asset leakage, leave unknown.
	}

	if exact != "" {
		res.Version = exact
		res.Range = exact
		res.Confidence = "high"
		res.Method = "exact file read"
		return
	}

	switch len(res.Candidates) {
	case 0:
		res.Confidence = "low"
		if res.IsTypo3 {
			res.Method = "markers only"
			res.Range = "unknown"
			res.Notes = append(res.Notes, "confirmed TYPO3 but no asset hash matched the DB — the DB may not cover this version (run `t3scan builddb`), or a composer-mode install exposes no hashable core assets")
		} else {
			res.Method = "none"
			res.Range = "not TYPO3"
		}
	case 1:
		res.Version = res.Candidates[0]
		res.Range = res.Candidates[0]
		res.Method = "asset hash (unique match)"
		if res.conflict {
			// Some probe's version set was disjoint from the rest — the lone
			// survivor is not trustworthy as an exact answer.
			res.Confidence = "low"
			res.Notes = append(res.Notes, "contradictory asset evidence (disjoint version sets) — the single candidate may be a custom/overridden asset; treat as approximate")
		} else {
			res.Confidence = "high"
		}
	default:
		lo, hi := res.Candidates[0], res.Candidates[len(res.Candidates)-1]
		res.Range = lo + " – " + hi
		matched := 0
		for _, fp := range res.Files {
			if fp.Matched {
				matched++
			}
		}
		if matched > 0 {
			res.Method = "asset hash (intersection)"
		} else {
			res.Method = "file presence (add/remove boundaries)"
		}
		// If the whole candidate set shares a minor, report that minor.
		if minor := commonMinor(res.Candidates); minor != "" {
			res.Range = minor + ".x (" + lo + " – " + hi + ")"
		}
		if matched >= 2 {
			res.Confidence = "medium"
		} else {
			res.Confidence = "low"
		}
		// Explain WHY it's a band, not a single version.
		if matched > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("version is a %d-release band because the assets the target serves are byte-identical across %s–%s (TYPO3 didn't change them in those patches) — no exposed asset discriminates further", len(res.Candidates), lo, hi))
		}
		// If the range butts up against the newest version the DB knows, the
		// real target may be a patch released after the DB was built.
		if newest := f.DB.Newest(); newest != "" && hi == newest {
			res.Notes = append(res.Notes, "range top ("+hi+") is the newest version in the DB — the target may be an even newer patch; run `t3scan builddb` to refresh")
		}
	}
}

// ---- helpers ----

// stockConfirmed reports whether at least one probe content-matched the DB,
// proving the target runs stock core files (gates absence narrowing).
func stockConfirmed(probes []FileProbe) bool {
	for _, fp := range probes {
		if fp.Matched {
			return true
		}
	}
	return false
}

func toSet(vs []string) map[string]bool {
	m := make(map[string]bool, len(vs))
	for _, v := range vs {
		m[v] = true
	}
	return m
}

func intersectKeep(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for v := range a {
		if b[v] {
			out[v] = true
		}
	}
	if len(out) == 0 {
		return a // a custom/overridden asset shouldn't collapse the set to nothing
	}
	return out
}

func commonMinor(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	minorOf := func(v string) string {
		p := splitVer(v)
		return itoa(p[0]) + "." + itoa(p[1])
	}
	first := minorOf(vs[0])
	for _, v := range vs[1:] {
		if minorOf(v) != first {
			return ""
		}
	}
	return first
}

// resolveURL resolves a possibly-relative asset ref against the page URL.
func resolveURL(pageURL, ref string) string {
	pu, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return pu.ResolveReference(ru).String()
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// dbBasenames returns the set of file basenames the version DB knows, so
// harvested asset URLs whose basename matches (and are therefore content-
// matchable) can be probed first.
func (f *Fingerprinter) dbBasenames() map[string]bool {
	if f.dbBase != nil {
		return f.dbBase
	}
	m := map[string]bool{}
	for p := range f.DB.Files {
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			m[p[i+1:]] = true
		} else {
			m[p] = true
		}
	}
	f.dbBase = m
	return m
}

// baseNameNoQuery returns the last path segment of a URL, without query/fragment.
func baseNameNoQuery(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		p := u.Path
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			return p[i+1:]
		}
		return p
	}
	return raw
}

// deriveBasePath extracts an install sub-path from a leaked asset URL, e.g.
// "/sub/typo3conf/ext/x/y.js" → "sub". Empty for a root install.
func deriveBasePath(assetURL string) string {
	u, err := url.Parse(assetURL)
	p := assetURL
	if err == nil && u.Path != "" {
		p = u.Path
	}
	for _, marker := range []string{"/typo3conf/", "/typo3/sysext/", "/typo3temp/", "/fileadmin/", "/typo3/"} {
		if i := strings.Index(p, marker); i > 0 {
			return strings.Trim(p[:i], "/")
		}
	}
	return ""
}

func compactAssetPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Path
}

// finalURL returns the response's final URL if known, else the requested one.
func (r *httpResult) finalURL(requested string) string {
	if r.URL != nil {
		return r.URL.String()
	}
	return requested
}
