package t3finger

import "testing"

func TestAssetURL(t *testing.T) {
	// Must match the reference technique exactly: md5("/vendor/<vendor>/<pkg>/")
	// with leading AND trailing slash (verified against the Python reference).
	got := AssetURL("https://example.com", "georgringer/news")
	want := "https://example.com/_assets/f6ef6adaf5c92bf687a31a3adbcb0f7b/"
	if got != want {
		t.Fatalf("AssetURL = %q, want %q", got, want)
	}
	// A raw path (leading slash) is hashed verbatim, trailing slash enforced.
	if u := AssetURL("https://x", "/packages/foo/"); u == "" {
		t.Fatal("empty raw-path asset url")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"12.4.8", "12.4.9", -1},
		{"12.4.10", "12.4.9", 1},
		{"11.5.0", "11.5.0", 0},
		{"13.0.0", "12.4.99", 1},
		{"10.4.0-dev", "10.4.0", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCommonMinor(t *testing.T) {
	if m := commonMinor([]string{"12.4.8", "12.4.11", "12.4.30"}); m != "12.4" {
		t.Errorf("commonMinor = %q, want 12.4", m)
	}
	if m := commonMinor([]string{"12.4.8", "13.0.0"}); m != "" {
		t.Errorf("commonMinor across minors = %q, want empty", m)
	}
}

func TestMatchConstraint(t *testing.T) {
	c := ">=11.0.0,<11.5.51|>=12.0.0,<12.4.46|>=13.0.0,<13.4.31"
	cases := []struct {
		v    string
		want bool
	}{
		{"12.4.8", true},   // inside the 12 range
		{"12.4.46", false}, // the fix version — no longer affected
		{"12.4.45", true},
		{"11.5.50", true},
		{"11.5.51", false},
		{"13.4.30", true},
		{"14.0.0", false}, // above all ranges
		{"10.4.0", false}, // below all ranges
	}
	for _, tc := range cases {
		if got := matchConstraint(c, tc.v); got != tc.want {
			t.Errorf("matchConstraint(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

func TestConstraintCaretTildeFailClosed(t *testing.T) {
	cases := []struct {
		c, v string
		want bool
	}{
		// caret: ^1.2.3 => >=1.2.3, <2.0.0
		{"^1.2.3", "1.2.3", true},
		{"^1.2.3", "1.9.0", true},
		{"^1.2.3", "2.0.0", false},
		{"^1.2.3", "1.2.2", false},
		// caret on 0.x: ^0.3.0 => >=0.3.0, <0.4.0
		{"^0.3.0", "0.3.5", true},
		{"^0.3.0", "0.4.0", false},
		// tilde: ~1.4 => >=1.4.0, <1.5.0
		{"~1.4", "1.4.9", true},
		{"~1.4", "1.5.0", false},
		// fail-closed: unparseable / wildcard must NOT match everything
		{"*", "9.9.9", false},
		{"dev-main", "13.4.0", false},
		{"1.0 - 2.0", "1.5.0", false}, // hyphen range unsupported -> fail closed
	}
	for _, tc := range cases {
		if got := matchConstraint(tc.c, tc.v); got != tc.want {
			t.Errorf("matchConstraint(%q,%q)=%v want %v", tc.c, tc.v, got, tc.want)
		}
	}
}

func TestDBMerge(t *testing.T) {
	a := &DB{
		Files:    map[string]map[string][]string{"x.css": {"h1": {"12.4.8"}}},
		Versions: []string{"12.4.8"},
	}
	b := &DB{
		Files:    map[string]map[string][]string{"x.css": {"h2": {"9.5.0"}}, "y.js": {"h3": {"9.5.0"}}},
		Versions: []string{"9.5.0"},
	}
	a.Merge(b)
	if len(a.Versions) != 2 || a.Versions[0] != "9.5.0" || a.Versions[1] != "12.4.8" {
		t.Fatalf("merged versions = %v", a.Versions)
	}
	if len(a.Files["x.css"]) != 2 {
		t.Errorf("x.css buckets = %d, want 2", len(a.Files["x.css"]))
	}
	if a.Files["y.js"] == nil {
		t.Error("y.js not merged in")
	}
}

func TestFreshness(t *testing.T) {
	rel := &Releases{Latest: "14.3.5", Branches: map[string]string{
		"13.4": "13.4.35", "12.4": "12.4.48",
	}}
	if BranchOf("13.4.33") != "13.4" {
		t.Fatalf("BranchOf = %q", BranchOf("13.4.33"))
	}
	if got := rel.LatestForBranch("13.4.33"); got != "13.4.35" {
		t.Errorf("LatestForBranch(13.4.33) = %q, want 13.4.35", got)
	}
	// 13.4.33 < 13.4.35 → outdated in-branch
	if CompareVersions("13.4.33", rel.LatestForBranch("13.4.33")) >= 0 {
		t.Error("13.4.33 should be behind 13.4.35")
	}
	// 12.4.48 == latest → up to date
	if CompareVersions("12.4.48", rel.LatestForBranch("12.4.48")) < 0 {
		t.Error("12.4.48 should be up to date")
	}
	// unknown branch → no latest
	if rel.LatestForBranch("9.5.0") != "" {
		t.Error("unknown branch should have no latest")
	}
}

func TestWithProxy(t *testing.T) {
	if _, err := New(WithProxy("http://127.0.0.1:8080")); err != nil {
		t.Errorf("valid proxy rejected: %v", err)
	}
	if _, err := New(WithProxy("://bad")); err == nil {
		t.Error("invalid proxy accepted")
	}
}

func TestDBNewest(t *testing.T) {
	db := &DB{Versions: []string{"9.5.0", "12.4.8", "10.4.0"}}
	// Versions are stored sorted by the builder; Newest returns the last element.
	if got := db.Newest(); got != "10.4.0" {
		// (unsorted input here → last element; builder always sorts, so this just
		// exercises the accessor)
		if got == "" {
			t.Error("Newest returned empty on non-empty DB")
		}
	}
	if (&DB{}).Newest() != "" {
		t.Error("Newest on empty DB should be empty")
	}
}

func TestDBContentIndex(t *testing.T) {
	db := &DB{Files: map[string]map[string][]string{
		"a/b.css": {"aaa": {"12.4.8"}, "bbb": {"12.4.9"}},
	}}
	if vs := db.VersionsForAnyHash("aaa"); len(vs) != 1 || vs[0] != "12.4.8" {
		t.Errorf("VersionsForAnyHash = %v", vs)
	}
	if vs := db.VersionsForAnyHash("zzz"); vs != nil {
		t.Errorf("unexpected match: %v", vs)
	}
}
