package t3finger

import "context"

// probeBehavioral issues a few cheap behavioral requests that confirm TYPO3 and
// bound the major version independently of asset hashes — so it works on
// hardened sites with stripped HTML / custom themes. It uses eID handlers:
// dumpFile/tx_cms_showpic exist in every supported release (a strong pre-auth
// TYPO3 marker), while requirejs/adminPanel_save were removed in 13.0 (a clean
// major boundary). Narrows res.Candidates in place. ~5 requests.
func (f *Fingerprinter) probeBehavioral(ctx context.Context, base string, res *VersionResult) {
	// Baseline: an unregistered eID (its status is the host's "unknown eID").
	bogus := -1
	if r, err := f.getProbe(ctx, base+"/index.php?eID="+randToken()); err == nil && r != nil {
		bogus = r.Status
	}
	registered := func(name string) bool {
		r, err := f.getProbe(ctx, base+"/index.php?eID="+name)
		// Registered ⇒ the handler answered differently from an unknown eID
		// (403 access-denied / 410 gone / 400 bad-params) rather than a plain 404.
		return err == nil && r != nil && r.Status != bogus && r.Status != 0
	}

	confirmed := false
	for _, name := range eidAlways {
		if registered(name) {
			confirmed = true
		}
	}
	if confirmed {
		res.IsTypo3 = true
		res.Markers = appendUniq(res.Markers, "eID handlers (dumpFile/tx_cms_showpic)")
	}

	removedPresent := false
	for _, name := range eidRemovedIn13 {
		if registered(name) {
			removedPresent = true
			break
		}
	}
	var floor, ceil string
	switch {
	case removedPresent:
		ceil = "12.999.999" // requirejs/adminPanel_save present ⇒ ≤ 12
		res.Markers = appendUniq(res.Markers, "eID requirejs present (≤ 12)")
	case confirmed:
		floor = "13.0.0" // confirmed TYPO3 but the ≤12 eID is gone ⇒ ≥ 13
		res.Markers = appendUniq(res.Markers, "eID requirejs absent (≥ 13)")
	}

	if floor != "" || ceil != "" {
		before := len(res.Candidates)
		res.Candidates = filterRange(res.Candidates, floor, ceil)
		if len(res.Candidates) < before {
			res.Notes = append(res.Notes, "candidate set narrowed by a behavioural eID version boundary")
		}
	}
}

// filterRange keeps candidates within [floor, ceil] (either may be ""). It never
// returns empty — an eID boundary that contradicts every candidate is more
// likely an odd build than proof, so the original set is kept in that case.
func filterRange(cands []string, floor, ceil string) []string {
	var out []string
	for _, v := range cands {
		if floor != "" && CompareVersions(v, floor) < 0 {
			continue
		}
		if ceil != "" && CompareVersions(v, ceil) > 0 {
			continue
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return cands
	}
	return out
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
