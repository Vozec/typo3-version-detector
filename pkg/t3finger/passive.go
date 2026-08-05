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
	byID := map[string]*Extension{} // dedupe by composer name (composer) or key (legacy)

	upsert := func(e Extension) *Extension {
		id := e.ComposerName
		if id == "" {
			id = e.Package
		}
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

	// --- 1) HTML harvest: composer asset hashes + legacy keys ---------------
	for _, page := range passivePages {
		r, err := f.get(ctx, base+page)
		res.Probed++
		if err != nil || r == nil || len(r.Body) == 0 {
			continue
		}
		body := r.Body
		for _, m := range reAssetHash.FindAllSubmatch(body, -1) {
			h := string(m[1])
			key, composer, ok := f.ExtProbes.IdentifyAssetHash(h)
			if !ok {
				continue // an /_assets/ hash we can't map (core, or unknown package)
			}
			e := Extension{
				Package:      composer,
				ComposerName: composer,
				Confirmed:    true,
				Status:       200,
				AssetURL:     base + "/_assets/" + h + "/",
				Evidence:     "HTML /_assets/" + h[:8] + "…",
			}
			if entry, ok := f.ExtProbes.Extensions[key]; ok {
				e.Requires = entry.Requires
			}
			upsert(e)
		}
		for _, m := range rePassiveLegacyKey.FindAllSubmatch(body, -1) {
			key := string(m[1])
			e := Extension{
				Package:   key,
				Confirmed: true,
				Status:    200,
				Location:  "typo3conf/ext/" + key + "/",
				Evidence:  "HTML typo3conf/ext/" + key + "/",
			}
			if entry, ok := f.ExtProbes.Extensions[key]; ok {
				e.ComposerName = entry.Composer
				e.Requires = entry.Requires
			}
			upsert(e)
		}
	}

	// --- 2) composer.lock: the whole inventory + exact versions -------------
	if r, err := f.getProbe(ctx, base+"/composer.lock"); err == nil && r != nil && r.Status == 200 && len(r.Body) > 0 {
		res.Probed++
		for _, p := range parseComposerLock(r.Body) {
			e := Extension{
				Package:       p.name,
				ComposerName:  p.name,
				Confirmed:     true,
				Status:        200,
				Version:       p.version,
				VersionSource: "composer.lock",
				Evidence:      "exposed /composer.lock",
			}
			if key := f.ExtProbes.KeyForComposer(p.name); key != "" {
				if entry, ok := f.ExtProbes.Extensions[key]; ok {
					e.Requires = entry.Requires
					e.AssetURL = AssetURL(base, p.name)
				}
			}
			ex := upsert(e)
			if ex != nil && ex.Version == "" { // enrich a hash-only hit with the exact version
				ex.Version, ex.VersionSource = p.version, "composer.lock"
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
				Confirmed: true,
				Status:    200,
				Location:  "typo3conf/ext/" + key + "/",
				Evidence:  "exposed PackageStates.php",
			}
			if entry, ok := f.ExtProbes.Extensions[key]; ok {
				e.ComposerName = entry.Composer
				e.Requires = entry.Requires
			}
			upsert(e)
		}
		break
	}

	// --- 4) version + freshness for what we found (no metadata version yet) -
	for _, e := range byID {
		if e.Version == "" && e.AssetURL != "" {
			if entry := f.ExtProbes.ByComposer(e.ComposerName); entry != nil {
				if cands := f.extVersionComposer(ctx, e.AssetURL, entry); len(cands) > 0 {
					e.VersionCandidates = cands
					e.VersionSource, e.VersionExact = "static-file hash", true
					if len(cands) == 1 {
						e.Version = cands[0]
					} else {
						e.Version = cands[0] + " – " + cands[len(cands)-1]
					}
				}
			}
		}
		f.annotateExtFreshness(e, f.ExtProbes.ByComposer(e.ComposerName))
		res.Extensions = append(res.Extensions, *e)
	}
	sort.Slice(res.Extensions, func(i, j int) bool { return res.Extensions[i].Package < res.Extensions[j].Package })
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
