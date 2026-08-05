package t3finger

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

//go:embed data/advisories.json
var embeddedAdvisories []byte

// Advisory is one published TYPO3 core security advisory.
type Advisory struct {
	ID       string `json:"id"`       // TYPO3-CORE-SA-YYYY-NNN
	CVE      string `json:"cve"`      // CVE-YYYY-NNNNN (may be empty)
	Title    string `json:"title"`    //
	Affected string `json:"affected"` // composer constraint, e.g. ">=11.0.0,<11.5.51|>=12.0.0,<12.4.46"
	Link     string `json:"link"`     //
	Severity string `json:"severity"` // may be empty
}

// AdvisoryDB is the embedded set of core advisories.
type AdvisoryDB struct {
	Package    string     `json:"package"`
	Advisories []Advisory `json:"advisories"`
}

// LoadAdvisories returns the advisories compiled into the binary.
func LoadAdvisories() *AdvisoryDB {
	var db AdvisoryDB
	if err := json.Unmarshal(embeddedAdvisories, &db); err != nil {
		return &AdvisoryDB{}
	}
	return &db
}

// Affects reports whether version v falls within this advisory's affected range.
func (a Advisory) Affects(v string) bool {
	return matchConstraint(a.Affected, v)
}

// For returns every advisory that affects version v, most severe first.
func (db *AdvisoryDB) For(v string) []Advisory {
	if v == "" {
		return nil
	}
	var out []Advisory
	for _, a := range db.Advisories {
		if a.Affects(v) {
			out = append(out, a)
		}
	}
	SortBySeverity(out)
	return out
}

// severityRank orders severities most-severe first (lower rank = worse).
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium", "moderate":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// SortBySeverity orders advisories most-severe first, newest ID breaking ties.
func SortBySeverity(advs []Advisory) {
	sort.SliceStable(advs, func(i, j int) bool {
		ri, rj := severityRank(advs[i].Severity), severityRank(advs[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return advs[i].ID > advs[j].ID
	})
}

// matchConstraint evaluates a Composer version constraint of the shape used by
// the Packagist advisory feed: OR-groups separated by '|', each an AND-list of
// comparator atoms separated by ','. Supported operators: <, <=, >, >=, =, ==.
func matchConstraint(constraint, v string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return false
	}
	for _, group := range strings.Split(constraint, "|") {
		if matchAndGroup(strings.TrimSpace(group), v) {
			return true
		}
	}
	return false
}

func matchAndGroup(group, v string) bool {
	if group == "" {
		return false
	}
	for _, atom := range strings.Split(group, ",") {
		if !matchAtom(strings.TrimSpace(atom), v) {
			return false
		}
	}
	return true
}

func matchAtom(atom, v string) bool {
	op, rest := "", atom
	switch {
	case strings.HasPrefix(atom, ">="):
		op, rest = ">=", atom[2:]
	case strings.HasPrefix(atom, "<="):
		op, rest = "<=", atom[2:]
	case strings.HasPrefix(atom, "=="):
		op, rest = "=", atom[2:]
	case strings.HasPrefix(atom, ">"):
		op, rest = ">", atom[1:]
	case strings.HasPrefix(atom, "<"):
		op, rest = "<", atom[1:]
	case strings.HasPrefix(atom, "="):
		op, rest = "=", atom[1:]
	case strings.HasPrefix(atom, "^"):
		return matchCaret(atom[1:], v)
	case strings.HasPrefix(atom, "~"):
		return matchTilde(atom[1:], v)
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "v"))
	// Fail CLOSED: an atom with no recognized operator, or whose version isn't
	// numeric, must not silently match every version (that produced false CVE
	// positives on the extension advisory feed's caret/tilde/`*` constraints).
	if op == "" || !startsNumeric(rest) {
		return false
	}
	c := CompareVersions(v, rest)
	switch op {
	case ">=":
		return c >= 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case "<":
		return c < 0
	case "=":
		return c == 0
	}
	return false
}

func startsNumeric(s string) bool {
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// matchCaret evaluates a Composer caret range "^x.y.z": >= x.y.z and < next
// breaking version (bump the left-most non-zero component).
func matchCaret(base, v string) bool {
	base = strings.TrimPrefix(strings.TrimSpace(base), "v")
	if !startsNumeric(base) {
		return false
	}
	p := splitVer(base)
	var upper [3]int
	switch {
	case p[0] > 0:
		upper = [3]int{p[0] + 1, 0, 0}
	case p[1] > 0:
		upper = [3]int{0, p[1] + 1, 0}
	default:
		upper = [3]int{0, 0, p[2] + 1}
	}
	return CompareVersions(v, base) >= 0 && cmpVer(splitVer(v), upper) < 0
}

// matchTilde evaluates "~x.y" (>= x.y, < x.(y+1)) and "~x.y.z" (>= x.y.z, < x.(y+1)).
func matchTilde(base, v string) bool {
	base = strings.TrimPrefix(strings.TrimSpace(base), "v")
	if !startsNumeric(base) {
		return false
	}
	p := splitVer(base)
	upper := [3]int{p[0], p[1] + 1, 0}
	return CompareVersions(v, base) >= 0 && cmpVer(splitVer(v), upper) < 0
}

func cmpVer(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// FetchAdvisoriesFor queries the Packagist advisory feed for the given packages
// and returns advisoryDBs keyed by package name. Used to map enumerated
// extensions (with a composer name + version) to their known CVEs.
func FetchAdvisoriesFor(ctx context.Context, packages []string) (map[string]*AdvisoryDB, error) {
	if len(packages) == 0 {
		return map[string]*AdvisoryDB{}, nil
	}
	q := make([]string, 0, len(packages))
	for _, p := range packages {
		q = append(q, "packages[]="+url.QueryEscape(p))
	}
	u := "https://packagist.org/api/security-advisories/?" + strings.Join(q, "&")
	c := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "t3scan/1.0 (+typo3-version-detector)")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("advisories: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var raw struct {
		Advisories map[string][]struct {
			AdvisoryID       string `json:"advisoryId"`
			CVE              string `json:"cve"`
			Title            string `json:"title"`
			AffectedVersions string `json:"affectedVersions"`
			Link             string `json:"link"`
			Severity         string `json:"severity"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("advisories: parse: %w", err)
	}
	out := map[string]*AdvisoryDB{}
	for pkg, list := range raw.Advisories {
		db := &AdvisoryDB{Package: pkg}
		for _, a := range list {
			db.Advisories = append(db.Advisories, Advisory{
				ID: a.AdvisoryID, CVE: a.CVE,
				Title:    strings.ReplaceAll(a.Title, "&amp;", "&"),
				Affected: a.AffectedVersions, Link: a.Link, Severity: a.Severity,
			})
		}
		out[pkg] = db
	}
	return out, nil
}

// packagistAdvisoriesURL returns published advisories for a package.
const packagistAdvisoriesURL = "https://packagist.org/api/security-advisories/?packages[]=typo3/cms-core"

// FetchAdvisories downloads the current TYPO3 core advisories from Packagist.
// Used by `t3scan buildadvisories` to refresh the embedded set.
func FetchAdvisories(ctx context.Context) (*AdvisoryDB, error) {
	c := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, packagistAdvisoriesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "t3scan/1.0 (+typo3-version-detector)")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("advisories: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var raw struct {
		Advisories map[string][]struct {
			AdvisoryID       string `json:"advisoryId"`
			CVE              string `json:"cve"`
			Title            string `json:"title"`
			AffectedVersions string `json:"affectedVersions"`
			Link             string `json:"link"`
			Severity         string `json:"severity"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("advisories: parse: %w", err)
	}
	db := &AdvisoryDB{Package: "typo3/cms-core"}
	seen := map[string]bool{}
	for _, list := range raw.Advisories {
		for _, a := range list {
			key := a.AdvisoryID
			if key == "" {
				key = a.CVE + a.Title
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			db.Advisories = append(db.Advisories, Advisory{
				ID:       a.AdvisoryID,
				CVE:      a.CVE,
				Title:    strings.ReplaceAll(a.Title, "&amp;", "&"),
				Affected: a.AffectedVersions,
				Link:     a.Link,
				Severity: a.Severity,
			})
		}
	}
	sort.Slice(db.Advisories, func(i, j int) bool { return db.Advisories[i].ID < db.Advisories[j].ID })
	return db, nil
}
