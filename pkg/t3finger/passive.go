package t3finger

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

var (
	// reAssetHash pulls the 32-hex directory hash out of any /_assets/<md5>/ URL.
	reAssetHash = regexp.MustCompile(`/_assets/([0-9a-f]{32})/`)
	// rePassiveLegacyKey pulls the extension key out of a typo3conf/ext/<key>/ path.
	rePassiveLegacyKey = regexp.MustCompile(`typo3conf/ext/([a-z0-9_]+)/`)
)

// passivePages are the few pages fetched to harvest already-exposed signals.
var passivePages = []string{"/", "/typo3/"}

// PassiveExtensions finds installed extensions WITHOUT brute force, from signals
// the target already exposes:
//
//   - composer-mode /_assets/<md5>/ URLs in the HTML, reversed against the
//     catalogue — certain, since the site is serving that package's own asset;
//   - legacy /typo3conf/ext/<key>/ paths — the key is written in the URL;
//   - an exposed /composer.lock — the full package list with EXACT versions;
//   - legacy typo3conf/PackageStates.php — the active-extension list.
//
// Each hit is confirmed and records how it was found. Versions are filled in
// from composer.lock when available, and otherwise pinned by hashing the
// package's public files (composer hits, reusing the /_assets/<md5>/ prefix).
// This is the cheap first pass; brute force is only needed afterwards for
// backend-only extensions that expose no public asset.
func (f *Fingerprinter) PassiveExtensions(ctx context.Context, target string) (*ExtResult, error) {
	base, err := normalizeBase(target)
	if err != nil {
		return nil, err
	}
	res := &ExtResult{Target: base}
	byID := map[string]*Extension{} // dedupe by TER key (unique) or composer/key

	idOf := func(e Extension) string {
		if e.Key != "" {
			return "K:" + e.Key // unique — keeps ambiguous siblings distinct
		}
		if e.ComposerName != "" {
			return "c:" + e.ComposerName
		}
		return "p:" + e.Package
	}
	upsert := func(e Extension) *Extension {
		id := idOf(e)
		if id == "" {
			return nil
		}
		if ex, ok := byID[id]; ok {
			if ex.Evidence == "" {
				ex.Evidence = e.Evidence
			}
			return ex
		}
		byID[id] = &e
		return &e
	}

	lockVer := map[string]string{} // composer name -> exact version from composer.lock

	// --- 1) HTML harvest: composer asset hashes + legacy keys ---------------
	seenComposer := map[string]bool{}
	for _, page := range passivePages {
		r, err := f.get(ctx, base+page)
		res.Probed++
		if err != nil || r == nil || len(r.Body) == 0 {
			continue
		}
		body := r.Body
		for _, m := range reAssetHash.FindAllSubmatch(body, -1) {
			composer := f.ExtProbes.ComposerForAssetHash(string(m[1]))
			if composer == "" || seenComposer[composer] {
				continue // unmappable hash (core / unknown), or already resolved
			}
			seenComposer[composer] = true
			// Collision-aware: resolve which key is really installed by hashing
			// the served files; may return several flagged Ambiguous. Confirmation
			// still requires the asset to actually serve — a stale HTML reference
			// to a /_assets/ dir that now 404s does not count as installed.
			for _, e := range f.resolveComposerAsset(ctx, base, composer, "HTML") {
				upsert(e)
			}
		}
		for _, m := range rePassiveLegacyKey.FindAllSubmatch(body, -1) {
			key := string(m[1])
			e := Extension{
				Package:   key,
				Key:       key,
				Confirmed: true,
				Status:    200,
				Location:  "typo3conf/ext/" + key + "/",
				Evidence:  "HTML typo3conf/ext/" + key + "/",
			}
			if entry, ok := f.ExtProbes.Extensions[key]; ok {
				e.ComposerName = entry.Composer
			}
			upsert(e)
		}
	}

	// --- 2) composer.lock: the whole inventory + exact versions -------------
	if r, err := f.getProbe(ctx, base+"/composer.lock"); err == nil && r != nil && r.Status == 200 && len(r.Body) > 0 {
		res.Probed++
		for _, p := range parseComposerLock(r.Body) {
			lockVer[p.name] = p.version
			e := Extension{
				Package:       p.name,
				ComposerName:  p.name,
				Key:           f.ExtProbes.KeyForComposer(p.name),
				Confirmed:     true,
				Status:        200,
				Version:       p.version,
				VersionSource: "composer.lock",
				Evidence:      "exposed /composer.lock",
			}
			ex := upsert(e)
			// composer.lock is authoritative for the version — override a fuzzy
			// hash range on an already-found hit with the exact value.
			if ex != nil && (ex.Version == "" || strings.Contains(ex.Version, " ")) {
				ex.Version, ex.VersionSource, ex.VersionExact, ex.VersionCandidates = p.version, "composer.lock", false, nil
			}
		}
	}

	// --- 3) legacy PackageStates.php: the active-extension list -------------
	for _, path := range []string{"/typo3conf/PackageStates.php", "/PackageStates.php"} {
		r, err := f.getProbe(ctx, base+path)
		if err != nil || r == nil || r.Status != 200 || len(r.Body) == 0 {
			continue
		}
		res.Probed++
		for _, key := range parsePackageStates(r.Body) {
			e := Extension{
				Package:   key,
				Key:       key,
				Confirmed: true,
				Status:    200,
				Location:  "typo3conf/ext/" + key + "/",
				Evidence:  "exposed PackageStates.php",
			}
			if entry, ok := f.ExtProbes.Extensions[key]; ok {
				e.ComposerName = entry.Composer
			}
			upsert(e)
		}
		break
	}

	// --- 3.5) resolve collisions with composer.lock's exact version ---------
	f.disambiguateByLock(byID, lockVer)

	// --- 4) fill Key/Link/Author + Latest/Outdated for everything found -----
	for _, e := range byID {
		f.finalizeExt(e)
		res.Extensions = append(res.Extensions, *e)
	}
	sort.Slice(res.Extensions, func(i, j int) bool {
		if res.Extensions[i].Package != res.Extensions[j].Package {
			return res.Extensions[i].Package < res.Extensions[j].Package
		}
		return res.Extensions[i].Key < res.Extensions[j].Key
	})
	return res, nil
}

// lockPkg is one package parsed out of a composer.lock.
type lockPkg struct {
	name    string
	version string
}

// parseComposerLock returns the TYPO3 extensions (plugins/themes) declared in a
// composer.lock: packages of a TYPO3 extension type, or otherwise known to the
// catalogue. The core framework itself is handled by version detection.
func parseComposerLock(body []byte) []lockPkg {
	var doc struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var out []lockPkg
	for _, p := range doc.Packages {
		if !strings.Contains(p.Name, "/") {
			continue
		}
		if !strings.HasPrefix(p.Type, "typo3-cms-") {
			continue // keep it to TYPO3 extensions/frameworks, not every PHP dep
		}
		if p.Name == "typo3/cms-core" {
			continue // core version is detected separately
		}
		out = append(out, lockPkg{name: p.Name, version: strings.TrimPrefix(p.Version, "v")})
	}
	return out
}

// rePkgStateKey matches "'<key>' => [ 'packagePath' => 'typo3conf/ext/<key>/' ]"
// entries in a PackageStates.php, capturing the key and its package path.
var rePkgStateKey = regexp.MustCompile(`'([a-z0-9_]+)'\s*=>\s*(?:array\s*\(|\[)\s*'packagePath'\s*=>\s*'([^']*)'`)

// parsePackageStates returns the keys of INSTALLED extensions (those under
// typo3conf/ext/) listed in a PackageStates.php — core sysexts are skipped.
func parsePackageStates(body []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range rePkgStateKey.FindAllSubmatch(body, -1) {
		key, path := string(m[1]), string(m[2])
		if !strings.Contains(path, "typo3conf/ext/") {
			continue // sysext / core — not an installed extension
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	return out
}
