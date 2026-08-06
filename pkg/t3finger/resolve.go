package t3finger

import (
	"context"
	"encoding/hex"
	"strings"
)

// terLink is the canonical TER extension page for a key (unique per key, even
// when several keys share a composer name; the page shows author + versions).
func terLink(key string) string {
	if key == "" {
		return ""
	}
	return "https://extensions.typo3.org/extension/" + key
}

// setComposerVersion records a version (or range) pinned by static-file hashing.
func setComposerVersion(e *Extension, cands []string) {
	e.VersionCandidates = cands
	e.VersionSource, e.VersionExact = "static-file hash", true
	if len(cands) == 1 {
		e.Version = cands[0]
	} else {
		e.Version = cands[0] + " – " + cands[len(cands)-1]
	}
}

// entryFor resolves the DB entry for an Extension, preferring its exact TER key
// (unique) over the composer name (which may be shared). It backfills e.Key.
func (f *Fingerprinter) entryFor(e *Extension) *ExtEntry {
	if f.ExtProbes == nil {
		return nil
	}
	if e.Key != "" {
		if v, ok := f.ExtProbes.Extensions[e.Key]; ok {
			return &v
		}
	}
	if e.ComposerName != "" {
		if entry := f.ExtProbes.ByComposer(e.ComposerName); entry != nil {
			if e.Key == "" {
				e.Key = f.ExtProbes.KeyForComposer(e.ComposerName)
			}
			return entry
		}
	}
	if e.Package != "" && !strings.Contains(e.Package, "/") {
		if v, ok := f.ExtProbes.Extensions[e.Package]; ok {
			e.Key = e.Package
			return &v
		}
	}
	return nil
}

// finalizeExt fills Key/Link/Author/Owner/Requires and Latest/Outdated on an
// Extension whose identity + version are already set. Safe to call more than
// once (it never overwrites a value that is already present).
func (f *Fingerprinter) finalizeExt(e *Extension) {
	entry := f.entryFor(e)
	if entry != nil {
		if e.Author == "" {
			e.Author = entry.Author
		}
		if e.Owner == "" {
			e.Owner = entry.Owner
		}
		if e.Requires == nil {
			e.Requires = entry.Requires
		}
	}
	if e.Link == "" && e.Key != "" {
		e.Link = terLink(e.Key)
	}
	f.annotateExtFreshness(e, entry)
}

// disambiguateByLock resolves collisions that the served files could not: when
// composer.lock pins an exact version for a shared composer name and only ONE of
// the ambiguous candidates has that version in its history, that candidate is
// the installed one — clear its Ambiguous flag and drop the losing siblings.
func (f *Fingerprinter) disambiguateByLock(byID map[string]*Extension, lockVer map[string]string) {
	if len(lockVer) == 0 || f.ExtProbes == nil {
		return
	}
	groups := map[string][]*Extension{}
	for _, e := range byID {
		if e.Ambiguous {
			groups[e.ComposerName] = append(groups[e.ComposerName], e)
		}
	}
	for composer, sibs := range groups {
		ver := lockVer[composer]
		if ver == "" || len(sibs) < 2 {
			continue
		}
		var winner *Extension
		n := 0
		for _, e := range sibs {
			if entry, ok := f.ExtProbes.Extensions[e.Key]; ok && containsStr(entry.Versions, ver) {
				winner, n = e, n+1
			}
		}
		if n != 1 || winner == nil {
			continue // 0 or several candidates ship it → genuinely undecidable
		}
		winner.Ambiguous = false
		winner.Version, winner.VersionSource = ver, "composer.lock"
		winner.VersionExact, winner.VersionCandidates = false, nil
		winner.Evidence = "composer.lock — v" + ver + " unique to this key"
		for _, e := range sibs {
			if e != winner {
				delete(byID, "K:"+e.Key)
			}
		}
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// resolveComposerAsset turns a composer name (behind a /_assets/<md5>/ path) into
// the installed extension(s). When one key owns the name it returns a single
// confirmed Extension with its version pinned by hashing the served public
// files. When several keys share the name (forks/dummies), it hashes the served
// files against EACH candidate — only the one whose files are actually present
// matches. If exactly one matches it is returned resolved; if none or several
// match, ALL plausible candidates are returned flagged Ambiguous (only one is
// truly installed) with their authors + links so a human can tell them apart.
func (f *Fingerprinter) resolveComposerAsset(ctx context.Context, base, composer, evidence string) []Extension {
	if composer == "" || f.ExtProbes == nil {
		return nil
	}
	cands := f.ExtProbes.CandidatesForComposer(composer)
	h := hex.EncodeToString(md5Sum("/vendor/" + composer + "/"))
	assetURL := base + "/_assets/" + h + "/"
	if evidence == "" {
		evidence = "HTML /_assets/" + h[:8] + "…"
	}
	mk := func(key string) Extension {
		return Extension{
			Package: composer, ComposerName: composer, Key: key,
			Confirmed: true, Status: 200, AssetURL: assetURL, Evidence: evidence,
		}
	}

	// Single owner — the common case.
	if len(cands) <= 1 {
		key := ""
		if len(cands) == 1 {
			key = cands[0]
		}
		e := mk(key)
		if key != "" {
			entry := f.ExtProbes.Extensions[key]
			if vs := f.extVersionComposer(ctx, assetURL, &entry); len(vs) > 0 {
				setComposerVersion(&e, vs)
			}
		}
		f.finalizeExt(&e)
		return []Extension{e}
	}

	// Collision: probe each candidate's own files against the target.
	var all, matched []Extension
	for _, key := range cands {
		e := mk(key)
		entry := f.ExtProbes.Extensions[key]
		hit := false
		if vs := f.extVersionComposer(ctx, assetURL, &entry); len(vs) > 0 {
			setComposerVersion(&e, vs)
			hit = true
		}
		f.finalizeExt(&e)
		all = append(all, e)
		if hit {
			matched = append(matched, e)
		}
	}
	if len(matched) == 1 {
		return matched // static files singled one out
	}
	pick := all // 0 matched → show every candidate
	if len(matched) > 1 {
		pick = matched // shared files → the ones that matched
	}
	for i := range pick {
		pick[i].Ambiguous = true
	}
	return pick
}
