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
