package t3finger

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

//go:embed data/releases.json
var embeddedReleases []byte

// Releases tracks the latest stable release per TYPO3 branch (major.minor), so a
// detected version can be flagged as up-to-date or behind. Sourced from the
// official get.typo3.org release feed.
type Releases struct {
	Latest   string            `json:"latest"`   // newest stable version overall
	Branches map[string]string `json:"branches"` // "13.4" -> "13.4.33"
}

// LoadReleases returns the embedded release snapshot.
func LoadReleases() *Releases {
	var r Releases
	if err := json.Unmarshal(embeddedReleases, &r); err != nil {
		return &Releases{Branches: map[string]string{}}
	}
	if r.Branches == nil {
		r.Branches = map[string]string{}
	}
	return &r
}

// BranchOf returns the "major.minor" branch of a version (e.g. "13.4.33" -> "13.4").
func BranchOf(version string) string {
	p := splitVer(version)
	return fmt.Sprintf("%d.%d", p[0], p[1])
}

// LatestForBranch returns the latest known patch of a version's branch, or "".
func (r *Releases) LatestForBranch(version string) string {
	if r == nil {
		return ""
	}
	return r.Branches[BranchOf(version)]
}

// FetchReleases downloads the current release feed and computes the latest
// stable (non-development) release per branch. Used by `t3scan buildreleases`.
func FetchReleases(ctx context.Context) (*Releases, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://get.typo3.org/api/v1/release/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "t3scan/1.0 (+typo3-version-detector)")
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("release feed: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var feed []struct {
		Version string `json:"version"`
		Type    string `json:"type"`
	}
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("release feed: parse: %w", err)
	}
	out := &Releases{Branches: map[string]string{}}
	for _, e := range feed {
		if e.Version == "" || e.Type == "development" {
			continue
		}
		if splitVer(e.Version) == [3]int{} {
			continue
		}
		br := BranchOf(e.Version)
		if cur, ok := out.Branches[br]; !ok || CompareVersions(e.Version, cur) > 0 {
			out.Branches[br] = e.Version
		}
		if out.Latest == "" || CompareVersions(e.Version, out.Latest) > 0 {
			out.Latest = e.Version
		}
	}
	return out, nil
}
