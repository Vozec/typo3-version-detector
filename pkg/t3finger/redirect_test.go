package t3finger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestProbeIgnoresRedirects verifies that a host which 302-redirects asset
// paths to an HTML page does not produce fabricated "served" file probes — the
// exact bug where 63 junk assets appeared. Real static assets are direct 200s
// with a non-HTML content-type; everything else must be ignored.
func TestProbeIgnoresRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Write([]byte(`<html><body>powered by TYPO3 <a href="/_assets/abc/x.css">x</a></body></html>`))
		case r.URL.Path == "/_assets/abc/x.css":
			// a real asset
			w.Header().Set("Content-Type", "text/css")
			w.Write([]byte("body{}"))
		default:
			// EVERY other path (incl. typo3/sysext/**/*.css probes) 302s to an
			// HTML page — the trap that used to be followed and hashed.
			http.Redirect(w, r, "/", http.StatusFound)
		}
	}))
	defer srv.Close()

	f, _ := New()
	f.Advisories = nil
	res, err := f.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// No probed file may be a redirect target (an HTML page). Only the real
	// /_assets css (200, text/css) is allowed in the report.
	for _, fp := range res.Files {
		if fp.Status == 200 && fp.Path != "/_assets/abc/x.css" {
			t.Errorf("fabricated asset from a redirect/HTML page: %s (status %d)", fp.Path, fp.Status)
		}
	}
}
