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
// Downloads run through a SINGLE global worker pool over every (extension,
// version) pair, so Concurrency requests are always in flight regardless of how
// the versions are distributed across extensions. This matters because each TER
// zip is tiny but costs a full request round-trip: the build is latency-bound,
// so flat global concurrency — not per-extension goroutines — is what makes it
// fast and removes the long tail of version-heavy plugins.
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

	// 1) Plan: for each key decide what (if anything) to download.
	type plan struct {
		key   string
		have  *ExtEntry // cloned existing entry (nil for a new extension)
		isNew bool
		toGet []string // versions to fetch
	}
	var plans []plan
	var stats UpdateStats
	for _, key := range keys {
		cat := catalogue[key]
		if len(cat) == 0 {
			continue // not in TER (or removed) — leave any existing entry as-is
		}
		wanted := reversedCap(cat, b.MaxVersions) // newest-first, depth-capped
		var have *ExtEntry
		isNew := true
		if existing != nil {
			if e, ok := existing.Extensions[key]; ok {
				hc := cloneEntry(e)
				have, isNew = &hc, false
			}
		}
		var toGet []string
		if isNew {
			toGet = wanted
		} else {
			toGet = missingVersions(wanted, have.Versions)
		}
		if !isNew && len(toGet) == 0 {
			stats.Unchanged++
			continue
		}
		plans = append(plans, plan{key: key, have: have, isNew: isNew, toGet: toGet})
	}

	// 2) Flatten to a single task list of (plan, version) downloads.
	type task struct {
		pi int
		v  string
	}
	var tasks []task
	for pi := range plans {
		for _, v := range plans[pi].toGet {
			tasks = append(tasks, task{pi, v})
		}
	}

	// 3) Global worker pool: download + hash every task concurrently.
	type vres struct {
		names    []string
		composer string
		requires map[string]string
		hashes   map[string]string
		ok       bool
	}
	res := make([]vres, len(tasks))
	total := len(tasks)
	b.log("downloading %d version zips across %d extensions (%d workers)…", total, len(plans), b.effConc())

	var (
		wg   sync.WaitGroup
		idx  = make(chan int)
		done int64
	)
	for w := 0; w < b.effConc(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				t := tasks[i]
				names, composer, requires, hashes, ok := b.hashVersion(ctx, plans[t.pi].key, t.v)
				res[i] = vres{names, composer, requires, hashes, ok}
				if n := atomic.AddInt64(&done, 1); n%500 == 0 {
					b.log("%d/%d version-downloads", n, total)
				}
			}
		}()
	}
	for i := range tasks {
		idx <- i
	}
	close(idx)
	wg.Wait()

	// 4) Assemble each plan's entry from its version results.
	byPlan := make([][]int, len(plans))
	for i, t := range tasks {
		byPlan[t.pi] = append(byPlan[t.pi], i)
	}
	for pi := range plans {
		p := &plans[pi]
		var e *ExtEntry
		if p.isNew {
			e = &ExtEntry{Files: map[string]map[string][]string{}}
		} else {
			e = p.have
		}
		newestV := ""
		var newestNames []string
		var newestComposer string
		var newestReq map[string]string
		dl := 0
		for _, i := range byPlan[pi] {
			r := res[i]
			if !r.ok {
				continue
			}
			dl++
			v := tasks[i].v
			e.Versions = append(e.Versions, v)
			for path, sum := range r.hashes {
				m := e.Files[path]
				if m == nil {
					m = map[string][]string{}
					e.Files[path] = m
				}
				m[sum] = append(m[sum], v)
			}
			if newestV == "" || CompareVersions(v, newestV) > 0 {
				newestV, newestNames, newestComposer, newestReq = v, r.names, r.composer, r.requires
			}
		}
		stats.Downloads += dl
		if len(e.Versions) == 0 {
			continue
		}
		sort.Sort(byVersion(e.Versions))
		e.Latest = e.Versions[len(e.Versions)-1]
		for _, buckets := range e.Files {
			for h := range buckets {
				sort.Sort(byVersion(buckets[h]))
			}
		}
		// The newest release defines identity. For a new extension that is always
		// the newest downloaded; for an update, only refresh when the newest
		// overall version is one we actually fetched this run.
		if p.isNew || newestV == e.Latest {
			if newestComposer != "" {
				e.Composer = newestComposer
			}
			if newestReq != nil {
				e.Requires = newestReq
			}
			if len(newestNames) > 0 {
				e.Probes = selectProbeFiles(newestNames)
			}
		}
		if p.isNew {
			if len(e.Probes) > 0 {
				out.Extensions[p.key] = *e
				stats.NewExtensions++
			}
		} else {
			out.Extensions[p.key] = *e
			stats.Updated++
		}
	}

	stats.Extensions = len(out.Extensions)
	b.log("update: %d total, +%d new, %d updated, %d unchanged, %d downloads",
		stats.Extensions, stats.NewExtensions, stats.Updated, stats.Unchanged, stats.Downloads)
	return out, stats, nil
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
