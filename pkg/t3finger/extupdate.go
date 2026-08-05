package t3finger

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
)

// UpdateStats summarizes an incremental extension-DB update.
type UpdateStats struct {
	Extensions    int `json:"extensions"`    // total in the resulting DB
	NewExtensions int `json:"newExtensions"` // keys built for the first time
	Updated       int `json:"updated"`       // existing keys that gained versions
	Unchanged     int `json:"unchanged"`     // existing keys already up to date
	Downloads     int `json:"downloads"`     // version zips fetched this run
}

// UpdateExtDB brings an extension DB up to date with the live TER catalogue,
// downloading ONLY the (extension, version) pairs it does not already have:
//
//   - a plugin with a new release   -> just its new versions are fetched & merged
//   - a brand-new plugin            -> built from scratch
//   - an unchanged plugin           -> skipped entirely (zero downloads)
//
// Pass existing == nil (or an empty DB) for a full build. The returned DB is the
// UNPRUNED working "raw" DB (every hashed public file, so the next update stays
// correct); call PruneForEmbed on it to get the compact DB embedded in the
// binary. New CVEs are orthogonal — they live in the advisory DB and are
// refreshed with buildadvisories, not here.
//
// This is the single reusable entry point behind `buildextdb` and
// `update-database`; the same code path does the one-time full build and every
// incremental refresh thereafter.
func (b *ExtBuilder) UpdateExtDB(ctx context.Context, existing *ExtProbeDB, keys []string, stamp string) (*ExtProbeDB, UpdateStats, error) {
	b.log("resolving versions from TER…")
	catalogue, err := b.allVersions(ctx)
	if err != nil {
		return nil, UpdateStats{}, err
	}

	out := &ExtProbeDB{BuiltAt: stamp, Extensions: map[string]ExtEntry{}}
	if existing != nil {
		for k, v := range existing.Extensions {
			out.Extensions[k] = v // carry every existing entry forward
		}
	}

	const (
		kindUnchanged = iota
		kindNew
		kindUpdated
	)
	type change struct {
		key   string
		entry *ExtEntry // nil for unchanged
		dl    int
		kind  int
	}
	results := make([]change, len(keys))

	var (
		wg   sync.WaitGroup
		sem  = make(chan struct{}, b.effConc())
		done int64
	)
	for i, key := range keys {
		cat := catalogue[key]
		if len(cat) == 0 {
			continue // key not in TER (or removed) — leave any existing entry as-is
		}
		wanted := reversedCap(cat, b.MaxVersions) // newest-first, depth-capped
		var have *ExtEntry
		if existing != nil {
			if e, ok := existing.Extensions[key]; ok {
				have = &e
			}
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, key string, wanted []string, have *ExtEntry) {
			defer wg.Done()
			defer func() { <-sem }()
			var c change
			c.key = key
			switch {
			case have == nil: // brand-new extension
				e, n := b.buildOne(ctx, key, wanted)
				c.entry, c.dl, c.kind = e, n, kindNew
			default:
				missing := missingVersions(wanted, have.Versions)
				if len(missing) == 0 {
					c.kind = kindUnchanged
				} else {
					e, n := b.mergeNewVersions(ctx, key, *have, missing)
					c.entry, c.dl, c.kind = e, n, kindUpdated
				}
			}
			results[i] = c
			cur := atomic.AddInt64(&done, 1)
			if cur%50 == 0 {
				b.log("%d/%d extensions scanned", cur, len(keys))
			}
		}(i, key, wanted, have)
	}
	wg.Wait()

	var stats UpdateStats
	for _, c := range results {
		if c.key == "" {
			continue
		}
		stats.Downloads += c.dl
		switch c.kind {
		case kindNew:
			if c.entry != nil && len(c.entry.Probes) > 0 {
				out.Extensions[c.key] = *c.entry
				stats.NewExtensions++
			}
		case kindUpdated:
			if c.entry != nil {
				out.Extensions[c.key] = *c.entry
				stats.Updated++
			}
		case kindUnchanged:
			stats.Unchanged++
		}
	}
	stats.Extensions = len(out.Extensions)
	b.log("update: %d total, +%d new, %d updated, %d unchanged, %d downloads",
		stats.Extensions, stats.NewExtensions, stats.Updated, stats.Unchanged, stats.Downloads)
	return out, stats, nil
}

// mergeNewVersions downloads the given (missing) versions of an existing
// extension and merges their hashes into a CLONE of `have`, refreshing the
// identity (Latest/Composer/Requires/Probes) if a newer version was added.
func (b *ExtBuilder) mergeNewVersions(ctx context.Context, key string, have ExtEntry, missing []string) (*ExtEntry, int) {
	e := cloneEntry(have)
	dl := 0
	newestV := ""
	var newestNames []string
	var newestComposer string
	var newestReq map[string]string
	for _, v := range missing {
		names, composer, requires, hashes, ok := b.hashVersion(ctx, key, v)
		if !ok {
			continue
		}
		dl++
		e.Versions = append(e.Versions, v)
		for path, sum := range hashes {
			m := e.Files[path]
			if m == nil {
				m = map[string][]string{}
				e.Files[path] = m
			}
			m[sum] = append(m[sum], v)
		}
		if newestV == "" || CompareVersions(v, newestV) > 0 {
			newestV, newestNames, newestComposer, newestReq = v, names, composer, requires
		}
	}
	sort.Sort(byVersion(e.Versions))
	if n := len(e.Versions); n > 0 {
		e.Latest = e.Versions[n-1]
	}
	// If the newest overall version is one we just downloaded, refresh identity
	// (deps/composer/probes) from it — the newest release defines the record.
	if newestV != "" && newestV == e.Latest {
		if newestComposer != "" {
			e.Composer = newestComposer
		}
		if newestReq != nil {
			e.Requires = newestReq
		}
		e.Probes = selectProbeFiles(newestNames)
	}
	for _, buckets := range e.Files {
		for h := range buckets {
			sort.Sort(byVersion(buckets[h]))
		}
	}
	return &e, dl
}

// PruneForEmbed returns a compact copy of a raw DB with version-invariant files
// dropped — the form embedded in the binary. The input is left untouched.
func PruneForEmbed(raw *ExtProbeDB) *ExtProbeDB {
	out := &ExtProbeDB{BuiltAt: raw.BuiltAt, Extensions: make(map[string]ExtEntry, len(raw.Extensions))}
	for k, e := range raw.Extensions {
		ce := cloneEntry(e)
		pruneEntry(&ce)
		out.Extensions[k] = ce
	}
	return out
}

// cloneEntry deep-copies an entry so mutating the copy never touches the source
// (existing raw entries are shared by reference into the update).
func cloneEntry(e ExtEntry) ExtEntry {
	c := e
	c.Versions = append([]string(nil), e.Versions...)
	c.Probes = append([]string(nil), e.Probes...)
	if e.Requires != nil {
		c.Requires = make(map[string]string, len(e.Requires))
		for k, v := range e.Requires {
			c.Requires[k] = v
		}
	}
	if e.Files != nil {
		c.Files = make(map[string]map[string][]string, len(e.Files))
		for p, buckets := range e.Files {
			nb := make(map[string][]string, len(buckets))
			for h, vs := range buckets {
				nb[h] = append([]string(nil), vs...)
			}
			c.Files[p] = nb
		}
	}
	c.anyHash = nil
	return c
}

// missingVersions returns the entries of `want` not present in `have`.
func missingVersions(want, have []string) []string {
	set := make(map[string]bool, len(have))
	for _, v := range have {
		set[v] = true
	}
	var out []string
	for _, v := range want {
		if !set[v] {
			out = append(out, v)
		}
	}
	return out
}

// reversedCap returns versions newest-first, capped to the newest maxV (0 = all).
func reversedCap(vers []string, maxV int) []string {
	ordered := append([]string(nil), vers...)
	for l, r := 0, len(ordered)-1; l < r; l, r = l+1, r-1 {
		ordered[l], ordered[r] = ordered[r], ordered[l]
	}
	if maxV > 0 && len(ordered) > maxV {
		ordered = ordered[:maxV]
	}
	return ordered
}

func (b *ExtBuilder) effConc() int {
	if b.Concurrency <= 0 {
		return 8
	}
	return b.Concurrency
}
