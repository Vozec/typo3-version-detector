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

// Legacy (non-composer) installs expose extensions directly on disk:
//
//	/typo3conf/ext/<key>/   third-party & local extensions
//	/typo3/sysext/<key>/    bundled system extensions
//
// A directory root usually 404s for BOTH present and absent extensions (TYPO3
// serves its 404 page, no dir listing), so enumeration probes a known MARKER
// FILE that every extension ships instead. ext_emconf.php is the classic
// universal manifest and also carries the version, so one request per key both
// detects the extension and reads its version. The marker is auto-selected per
// host: the first candidate whose bogus-key response is a clean 404 wins (some
// hosts block composer.json with 403, or serve ext_emconf.php, etc.).

// legacyLocations are the two on-disk roots, tried in order.
var legacyLocations = []string{"typo3conf/ext/", "typo3/sysext/"}

// universalMarkers are files present in virtually every legacy extension, in
// order of universality. ext_emconf.php is mandatory for TER / Extension-Manager
// installs; ext_localconf.php and ext_tables.php ship with almost all extensions
// that add runtime config or TCA; composer.json with all modern ones. The
// enumerator auto-selects the first of these that a host serves cleanly (some
// hosts block one type — e.g. composer.json 403 — but serve another), so a
// single reliable request per key detects any extension.
var universalMarkers = []string{
	"ext_emconf.php",
	"ext_localconf.php",
	"ext_tables.php",
	"composer.json",
}

// genericMarkers are the fallback probe files for a key not in the probe DB,
// used only when NO universal marker is reliable on the host.
var genericMarkers = []string{
	"ext_emconf.php",
	"Resources/Public/Icons/Extension.svg",
	"ext_icon.svg",
	"ext_icon.gif",
}

// maxProbeFilesPerKey bounds how many files we try per key per location, to keep
// request volume (and spam) low. The probe DB lists the most-reliable file(s)
// first, so 2 is plenty.
const maxProbeFilesPerKey = 2

// probeFilesFor returns the files to probe for a key. When ext_emconf.php is a
// reliable marker on this host (its bogus-key response is a clean 404), a single
// request per key suffices for EVERY extension — so the full TER catalogue can
// be enumerated cheaply. Only when the host blocks ext_emconf.php do we fall
// back to the per-extension public files recorded in the probe DB (or generic
// markers), which are served even when metadata is blocked.
func (f *Fingerprinter) probeFilesFor(key, marker string) []string {
	if marker != "" {
		return []string{marker}
	}
	if f.ExtProbes != nil {
		if p, ok := f.ExtProbes.Extensions[key]; ok && len(p.Probes) > 0 {
			return p.Probes
		}
	}
	return genericMarkers
}

// EnumerateExtensionsLegacy detects each extension by requesting a file it
// actually ships (from the probe DB, or generic markers) under the legacy roots.
// A 200 ⇒ installed. Versions come from the probe DB and/or ext_emconf.php.
func (f *Fingerprinter) EnumerateExtensionsLegacy(ctx context.Context, target string, keys []string, progress func(done, total int)) (*ExtResult, error) {
	base, err := normalizeBase(target)
	if err != nil {
		return nil, err
	}
	res := &ExtResult{Target: base, Probed: len(keys)}

	// Per location, auto-select the first universal marker whose bogus-key
	// response is a clean 404 — that marker cleanly separates present (200) from
	// absent (404) on THIS host, whichever file type it happens to serve/block.
	// Robust to transient throttling at startup: several tries per marker, and if
	// nothing yields a clean 404 we still record the best-observed baseline so
	// enumeration proceeds (via the per-extension probe DB) instead of aborting.
	baseline := map[string]Baseline{}
	marker := map[string]string{}
	for _, loc := range legacyLocations {
		var fallback *Baseline
		for _, cand := range universalMarkers {
			var b *Baseline
			for i := 0; i < 3; i++ {
				st, sz, ok := f.head(ctx, base+"/"+loc+"zzz-no-such-ext-"+randToken()+"/"+cand)
				if !ok {
					continue
				}
				cur := Baseline{Status: st, Size: sz, OK: true}
				if b == nil || (b.Status != 404 && st == 404) {
					b = &cur
				}
				if st == 404 {
					break // clean answer, no need to retry
				}
			}
			if b == nil {
				continue
			}
			if b.Status == 404 { // reliable marker found → fast path
				baseline[loc] = *b
				marker[loc] = cand
				if !res.Baseline.OK {
					res.Baseline = *b
				}
				break
			}
			if fallback == nil { // remember a non-404 answer as a last resort
				fallback = b
			}
		}
		// No clean-404 marker on this location: keep a baseline anyway (only for
		// the primary location) so the DB-driven public-file probes still run.
		if _, ok := baseline[loc]; !ok && loc == "typo3conf/ext/" && fallback != nil {
			baseline[loc] = *fallback
			if !res.Baseline.OK {
				res.Baseline = *fallback
			}
		}
	}
	if marker["typo3conf/ext/"] == "" {
		res.NotEnumerable = true
		res.Notes = append(res.Notes, "no universal marker (ext_emconf.php/ext_localconf.php/ext_tables.php/composer.json) returned a clean 404 for a bogus key — the host blocks/throttles or catch-alls these paths; using per-extension public-file probes from the DB (lower --rate if this looks like throttling)")
	}
	if !res.Baseline.OK {
		return nil, errNoControl
	}
	// Reliable single-request enumeration is possible where a marker was chosen.
	// Third-party extensions ("plugins") live in typo3conf/ext/; skip the
	// typo3/sysext/ pass when its marker is reliable (bundled core exts only).
	primaryMarker := marker["typo3conf/ext/"]
	probeLocs := legacyLocations
	if primaryMarker != "" {
		probeLocs = []string{"typo3conf/ext/"}
		res.Notes = append(res.Notes, "probe marker: typo3conf/ext/<key>/"+primaryMarker+" (auto-selected)")
	}

	type hit struct {
		key, loc, file string
		status         int
	}
	var (
		hits   []hit
		mu     sync.Mutex
		errors int64
		done   int64
		wg     sync.WaitGroup
		sem    = make(chan struct{}, f.conc())
	)

	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" || strings.HasPrefix(key, "#") {
			atomic.AddInt64(&done, 1)
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(key string) {
			defer wg.Done()
			defer func() { <-sem }()
			var got *hit
		loop:
			for _, loc := range probeLocs {
				bl, ok := baseline[loc]
				if !ok {
					continue
				}
				// Prefer the auto-selected universal marker for this location (one
				// request); only where none was reliable do we fall back to the
				// per-extension public files from the probe DB.
				files := f.probeFilesFor(key, marker[loc])
				if len(files) > maxProbeFilesPerKey {
					files = files[:maxProbeFilesPerKey]
				}
				for _, file := range files {
					st, sz, ok := f.head(ctx, base+"/"+loc+key+"/"+file)
					if !ok {
						atomic.AddInt64(&errors, 1)
						continue
					}
					if st == 200 && !(bl.Status == 200 && sz == bl.Size) {
						got = &hit{key: key, loc: loc, file: file, status: st}
						break loop
					}
				}
			}
			if got != nil {
				mu.Lock()
				hits = append(hits, *got)
				mu.Unlock()
			}
			n := atomic.AddInt64(&done, 1)
			if progress != nil {
				progress(int(n), len(keys))
			}
		}(key)
	}
	wg.Wait()
	res.Errors = int(errors)

	// Enrich hits: composer name + dependencies from the DB, and the EXACT
	// installed version — first from static-file hashes (works even when
	// metadata files are blocked), then from ext_emconf.php/composer.json.
	sort.Slice(hits, func(i, j int) bool { return hits[i].key < hits[j].key })
	for _, h := range hits {
		extBase := base + "/" + h.loc + h.key + "/"
		ext := Extension{
			Package:   h.key,
			Location:  h.loc + h.key + "/",
			Status:    h.status,
			Confirmed: true,
			Evidence:  h.file,
		}
		var entry *ExtEntry
		if f.ExtProbes != nil {
			if p, ok := f.ExtProbes.Extensions[h.key]; ok {
				entry = &p
				ext.ComposerName = p.Composer
				ext.Requires = p.Requires
			}
		}
		// 1) Version by static-file hash diff (DB-driven, metadata-independent).
		if entry != nil {
			if v := f.extVersionByHash(ctx, extBase, entry); v != "" {
				ext.Version, ext.VersionSource, ext.VersionExact = v, "static-file hash", true
			}
		}
		// 2) Fall back to metadata files for the version.
		if ext.Version == "" {
			if r, err := f.get(ctx, extBase+"ext_emconf.php"); err == nil && r != nil && r.Status == 200 {
				if v := firstSub(reEmconfVersion, r.Body); v != "" {
					ext.Version, ext.VersionSource = v, "ext_emconf.php"
				}
			}
		}
		if ext.Version == "" {
			if r, err := f.get(ctx, extBase+"composer.json"); err == nil && r != nil && r.Status == 200 {
				if v := firstSub(reComposerVersion, r.Body); v != "" {
					ext.Version, ext.VersionSource = v, "composer.json"
				}
				if ext.ComposerName == "" {
					if m := reComposerName.FindSubmatch(r.Body); m != nil {
						ext.ComposerName = string(m[1])
					}
				}
			}
		}
		res.Extensions = append(res.Extensions, ext)
	}
	return res, nil
}

// extVersionByHash pins an extension's installed version by hashing the
// discriminating static files the DB knows for it and intersecting the matching
// version sets. Probes at most a few files to stay light.
func (f *Fingerprinter) extVersionByHash(ctx context.Context, extBase string, entry *ExtEntry) string {
	disc := entry.DiscriminatingFilesRanked()
	if len(disc) == 0 {
		return ""
	}
	const maxFiles = 8
	if len(disc) > maxFiles {
		disc = disc[:maxFiles]
	}
	var inter map[string]bool
	interSet := false
	for _, path := range disc {
		r, err := f.get(ctx, extBase+path)
		if err != nil || r == nil || r.Status != 200 || len(r.Body) == 0 {
			continue
		}
		sum := md5.Sum(r.Body)
		vs := entry.VersionForHash(path, hex.EncodeToString(sum[:]))
		if len(vs) == 0 {
			continue
		}
		set := toSet(vs)
		if !interSet {
			inter, interSet = set, true
		} else {
			inter = intersectKeep(inter, set)
		}
	}
	if !interSet || len(inter) == 0 {
		return ""
	}
	var cands []string
	for v := range inter {
		cands = append(cands, v)
	}
	sort.Sort(byVersion(cands))
	if len(cands) == 1 {
		return cands[0]
	}
	// Multiple candidates: report the tight range (newest wins for CVE safety).
	return cands[0] + " – " + cands[len(cands)-1]
}

// AnnotateExtensionCVEs looks up known advisories for every enumerated
// extension that has both a Packagist name and a version, and fills in
// Extension.Vulns. It performs a single batched request to the advisory feed.
func (f *Fingerprinter) AnnotateExtensionCVEs(ctx context.Context, res *ExtResult) error {
	// A found extension is identified by its composer name — read from
	// composer.json (legacy) or already the Package field (composer-mode enum,
	// which uses vendor/name directly).
	byName := map[string][]*Extension{}
	for i := range res.Extensions {
		e := &res.Extensions[i]
		name := e.ComposerName
		if name == "" && strings.Contains(e.Package, "/") {
			name = e.Package
		}
		if name != "" {
			byName[name] = append(byName[name], e)
		}
	}
	if len(byName) == 0 {
		return nil
	}
	pkgs := make([]string, 0, len(byName))
	for p := range byName {
		pkgs = append(pkgs, p)
	}
	dbs, err := FetchAdvisoriesFor(ctx, pkgs)
	if err != nil {
		return err
	}
	for name, exts := range byName {
		db := dbs[name]
		if db == nil {
			continue
		}
		for _, e := range exts {
			if e.Version != "" {
				e.Vulns = db.For(e.Version) // version known → certain matches
			} else {
				e.VulnsPossible = append([]Advisory(nil), db.Advisories...) // version unknown → all, possible
			}
		}
	}
	return nil
}

func firstSub(re interface{ FindSubmatch([]byte) [][]byte }, b []byte) string {
	if m := re.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}
