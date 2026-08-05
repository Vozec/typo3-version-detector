package t3finger

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDetectExactLegacy spins up an in-process server that mimics a legacy
// TYPO3 install exposing its core ext_emconf.php, and asserts the full pipeline:
// is-TYPO3, exact version read, and CVE mapping — all without any network.
func TestDetectExactLegacy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Set-Cookie", "fe_typo_user=abc; path=/")
			w.Write([]byte(`<html><head><meta name="generator" content="TYPO3 CMS"></head>` +
				`<body>This website is powered by TYPO3</body></html>`))
		case r.URL.Path == "/typo3/sysext/core/ext_emconf.php":
			w.Write([]byte("<?php $EM_CONF[$_EXTKEY] = ['title'=>'Core','version'=>'11.5.0'];"))
		default:
			http.NotFound(w, r) // clean 404 host
		}
	}))
	defer srv.Close()

	f, err := New()
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsTypo3 {
		t.Fatal("expected IsTypo3=true")
	}
	if res.Version != "11.5.0" {
		t.Fatalf("version = %q, want 11.5.0", res.Version)
	}
	if res.Confidence != "high" || res.Method != "exact file read" {
		t.Errorf("confidence/method = %q/%q, want high/exact file read", res.Confidence, res.Method)
	}
	if !hasMarker(res.Markers, "fe_typo_user") {
		t.Errorf("expected fe_typo_user cookie marker, got %v", res.Markers)
	}
	if len(res.Vulnerabilities) == 0 {
		t.Error("expected known CVEs for 11.5.0")
	}
}

// TestDetectNotTypo3 asserts a plain non-TYPO3 host is reported as such.
func TestDetectNotTypo3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>hello world</body></html>"))
	}))
	defer srv.Close()

	f, _ := New()
	res, err := f.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsTypo3 {
		t.Errorf("false positive: %v", res.Markers)
	}
}

// TestAbsenceNarrowingLegacy checks that, in a legacy install, a stock file
// that content-matches plus a DB-known file that 404s tightens the candidate set
// to versions that HAVE the matched file but LACK the absent one.
func TestAbsenceNarrowingLegacy(t *testing.T) {
	sum := md5.Sum([]byte("STOCKCSS"))
	stockHash := hex.EncodeToString(sum[:])

	// Tiny DB: backend.css (a DefaultProbe) content-matches all three versions;
	// only-new.js exists only in 12.4.3 (presence-discriminating, one hash).
	db := &DB{
		Files: map[string]map[string][]string{
			"typo3/sysext/backend/Resources/Public/Css/backend.css": {
				stockHash: {"12.4.1", "12.4.2", "12.4.3"},
			},
			"typo3/sysext/backend/Resources/Public/JavaScript/only-new.js": {
				"bbbbbbbb": {"12.4.3"},
			},
		},
		Versions: []string{"12.4.1", "12.4.2", "12.4.3"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			// legacy asset-path leakage → Mode = legacy
			w.Write([]byte(`<html><body>powered by TYPO3 <img src="/typo3conf/ext/x/a.png"></body></html>`))
		case "/typo3/sysext/backend/Resources/Public/Css/backend.css":
			w.Write([]byte("STOCKCSS"))
		default:
			http.NotFound(w, r) // only-new.js 404s, bogus asset 404s (clean host)
		}
	}))
	defer srv.Close()

	f, _ := New(WithDB(db))
	f.Advisories = nil
	res, err := f.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != ModeLegacy {
		t.Fatalf("mode = %q, want legacy", res.Mode)
	}
	// backend.css matched (v1..v3); only-new.js 404 excludes v3 → {12.4.1,12.4.2}.
	got := strings.Join(res.Candidates, ",")
	if got != "12.4.1,12.4.2" {
		t.Errorf("candidates = %q, want 12.4.1,12.4.2 (absence should drop 12.4.3)", got)
	}
}
