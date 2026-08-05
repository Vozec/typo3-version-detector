package t3finger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLegacyMarkerFallback verifies the enumerator does not hinge on
// ext_emconf.php: when a host blocks it (403) but serves ext_localconf.php, the
// marker auto-selection falls back and the extension is still detected.
func TestLegacyMarkerFallback(t *testing.T) {
	present := map[string]bool{
		"/typo3conf/ext/coolext/ext_localconf.php": true,
		"/typo3conf/ext/coolext/ext_tables.php":    true,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		// Host blocks metadata files uniformly (present AND absent → 403).
		if strings.HasSuffix(p, "ext_emconf.php") || strings.HasSuffix(p, "composer.json") {
			w.WriteHeader(403)
			w.Write([]byte("forbidden"))
			return
		}
		if present[p] {
			w.Write([]byte("<?php // config"))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte("not found page padding padding"))
	}))
	defer srv.Close()

	f, _ := New()
	f.Advisories = nil
	res, err := f.EnumerateExtensionsLegacy(context.Background(), srv.URL,
		[]string{"coolext", "nope_ext"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, e := range res.Extensions {
		if e.Confirmed {
			found = append(found, e.Package)
		}
	}
	if len(found) != 1 || found[0] != "coolext" {
		t.Fatalf("found = %v, want [coolext] (via ext_localconf.php fallback)", found)
	}
}

// TestLegacyEmconfPrimary verifies ext_emconf.php is chosen when available, and
// the version is read from it.
func TestLegacyEmconfPrimary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/typo3conf/ext/news/ext_emconf.php":
			w.Write([]byte("<?php $EM_CONF[$_EXTKEY]=['version'=>'11.3.2'];"))
		default:
			w.WriteHeader(404)
			w.Write([]byte("nf"))
		}
	}))
	defer srv.Close()

	f, _ := New()
	f.Advisories = nil
	res, err := f.EnumerateExtensionsLegacy(context.Background(), srv.URL, []string{"news", "absent"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var news *Extension
	for i := range res.Extensions {
		if res.Extensions[i].Package == "news" {
			news = &res.Extensions[i]
		}
	}
	if news == nil || !news.Confirmed {
		t.Fatal("news not detected")
	}
	if news.Version != "11.3.2" {
		t.Errorf("version = %q, want 11.3.2", news.Version)
	}
}
