// Package t3finger fingerprints a TYPO3 CMS website without authentication:
// it enumerates the installed extensions ("plugins") by abusing the
// deterministic Composer-mode asset path, and detects the core version by
// hashing the static assets TYPO3 ships and matching them against a database
// built from official releases.
//
// Everything here is reachable pre-auth over plain HTTP and is intended for
// authorized security testing and asset inventory only.
package t3finger

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Fingerprinter is the shared client for both extension enumeration and
// version detection against a TYPO3 target.
type Fingerprinter struct {
	HTTP       *http.Client
	DB         *DB
	Advisories *AdvisoryDB
	ExtProbes  *ExtProbeDB
	UserAgent  string
	// Insecure skips TLS certificate verification when true.
	Insecure bool
	// Proxy, when set, routes all HTTP(S) through this proxy URL. Supports
	// http://, https:// and socks5:// schemes (e.g. Burp on
	// http://127.0.0.1:8080, or socks5://127.0.0.1:9050 for Tor).
	Proxy string
	// ProbeConcurrency bounds concurrent HTTP requests (default 16).
	ProbeConcurrency int
	// Rate caps requests per second across all workers (0 = unlimited).
	Rate float64

	// probeHTTP is like HTTP but does not follow redirects (for asset probes).
	probeHTTP *http.Client

	dbBase   map[string]bool   // cached DB path basenames
	subIndex map[string]string // cached Resources/Public sub-path -> sysext prefix
	limiter  *rateLimiter
	limOnce  sync.Once
}

// Option configures a Fingerprinter.
type Option func(*Fingerprinter)

// WithDB sets a custom version database (defaults to the embedded one).
func WithDB(db *DB) Option { return func(f *Fingerprinter) { f.DB = db } }

// WithInsecure disables TLS certificate verification.
func WithInsecure(b bool) Option { return func(f *Fingerprinter) { f.Insecure = b } }

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) Option { return func(f *Fingerprinter) { f.HTTP = c } }

// WithRate caps requests per second (0 = unlimited).
func WithRate(r float64) Option { return func(f *Fingerprinter) { f.Rate = r } }

// WithProxy routes traffic through an http://, https:// or socks5:// proxy.
func WithProxy(p string) Option { return func(f *Fingerprinter) { f.Proxy = p } }

// WithConcurrency sets the maximum number of concurrent requests.
func WithConcurrency(n int) Option { return func(f *Fingerprinter) { f.ProbeConcurrency = n } }

// New builds a Fingerprinter. By default it loads the embedded version DB; a
// missing/empty DB is tolerated (extension enumeration needs no DB).
func New(opts ...Option) (*Fingerprinter, error) {
	f := &Fingerprinter{
		UserAgent:        "t3scan/1.0 (+typo3-version-detector; authorized security testing)",
		ProbeConcurrency: 16,
	}
	if db, err := LoadEmbedded(); err == nil {
		f.DB = db
	} else {
		f.DB = emptyDB()
	}
	f.Advisories = LoadAdvisories()
	f.ExtProbes = LoadExtProbeDB()
	for _, o := range opts {
		o(f)
	}
	if f.HTTP == nil {
		tr := &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: f.Insecure},
			MaxIdleConnsPerHost: 32,
		}
		if f.Proxy != "" {
			pu, err := url.Parse(f.Proxy)
			if err != nil {
				return nil, fmt.Errorf("invalid proxy %q: %w", f.Proxy, err)
			}
			tr.Proxy = http.ProxyURL(pu)
		}
		// The main client follows redirects (identify pages may 302 to a locale
		// or http→https). Asset probes use probeHTTP, which does NOT follow: a
		// static asset that 302s is NOT the asset (a redirect to an HTML page),
		// so following it and hashing the result would fabricate junk matches.
		f.HTTP = &http.Client{Timeout: 20 * time.Second, Transport: tr}
		f.probeHTTP = &http.Client{
			Timeout:       20 * time.Second,
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if f.probeHTTP == nil {
		f.probeHTTP = f.HTTP // custom client supplied via WithHTTPClient
	}
	if f.ProbeConcurrency <= 0 {
		f.ProbeConcurrency = 16
	}
	return f, nil
}

// conc returns the effective concurrency.
func (f *Fingerprinter) conc() int {
	if f.ProbeConcurrency <= 0 {
		return 16
	}
	return f.ProbeConcurrency
}

// rl returns the lazily-built rate limiter.
func (f *Fingerprinter) rl() *rateLimiter {
	f.limOnce.Do(func() { f.limiter = newRateLimiter(f.Rate) })
	return f.limiter
}

// maxBodyBytes bounds a probe's body read. It MUST match the builder's hash
// limit (builder.go) so a live asset in the 8–16 MB range hashes to the same
// md5 on both sides (else it could never match the DB).
const maxBodyBytes = 16 << 20

// httpResult is the minimal outcome of a probe: status + body (may be nil for
// HEAD-like semantics; here we always GET but limit the body).
type httpResult struct {
	Status int
	Body   []byte
	URL    *url.URL
	Header http.Header
}

// get performs a rate-limited GET (following redirects), retrying transient
// network errors. A real HTTP response (any status) is returned as-is.
func (f *Fingerprinter) get(ctx context.Context, rawURL string) (*httpResult, error) {
	return f.doGet(ctx, rawURL, f.HTTP)
}

// getProbe is like get but does NOT follow redirects — for asset probes, where
// a 3xx means "not the asset". The returned Status is the real 200/302/404.
func (f *Fingerprinter) getProbe(ctx context.Context, rawURL string) (*httpResult, error) {
	return f.doGet(ctx, rawURL, f.probeHTTP)
}

func (f *Fingerprinter) doGet(ctx context.Context, rawURL string, client *http.Client) (*httpResult, error) {
	for attempt := 0; ; attempt++ {
		f.rl().wait(ctx)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", f.UserAgent)
		req.Header.Set("Accept", "*/*")
		resp, err := client.Do(req)
		if err != nil {
			if attempt < 3 && ctx.Err() == nil && isTransient(err) {
				time.Sleep(time.Duration(attempt+1) * 300 * time.Millisecond)
				continue
			}
			return nil, err
		}
		body, e := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close()
		if e != nil {
			if attempt < 3 && ctx.Err() == nil {
				continue
			}
			return &httpResult{Status: resp.StatusCode, URL: resp.Request.URL, Header: resp.Header}, nil
		}
		return &httpResult{Status: resp.StatusCode, Body: body, URL: resp.Request.URL, Header: resp.Header}, nil
	}
}

// getHost issues a non-redirect GET with a spoofed Host header — used to probe
// TYPO3's trusted-host check, which throws (500 + "trustedHostsPattern") on a
// mismatch even in Production, confirming TYPO3 and disclosing the config var.
func (f *Fingerprinter) getHost(ctx context.Context, rawURL, host string) *httpResult {
	f.rl().wait(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", f.UserAgent)
	req.Host = host
	resp, err := f.probeHTTP.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return &httpResult{Status: resp.StatusCode, Body: body, URL: resp.Request.URL, Header: resp.Header}
}

// isAsset reports whether the response body is plausibly the static asset at
// path (not an HTML error/redirect page). A real .css/.js/.svg/… is never
// served as text/html, so an HTML content-type means "not the asset".
func (r *httpResult) isAsset() bool {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	return !strings.Contains(ct, "text/html")
}

// head issues a GET but the caller only cares about status/size — used for the
// asset-existence probes where the body length matters for the control compare.
func (f *Fingerprinter) head(ctx context.Context, rawURL string) (status, size int, ok bool) {
	r, err := f.get(ctx, rawURL)
	if err != nil {
		return 0, 0, false
	}
	return r.Status, len(r.Body), true
}

func isTransient(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, n := range []string{"timeout", "temporary", "reset", "eof", "broken pipe", "connection refused", "no route", "unreachable"} {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// normalizeBase turns a user-supplied target into a clean scheme://host[/path]
// base with no trailing slash. Defaults to https when no scheme is given.
func normalizeBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid url %q: missing host", raw)
	}
	u.Fragment = ""
	u.RawQuery = ""
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

// rateLimiter caps the total request rate across all worker goroutines.
type rateLimiter struct {
	interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

func newRateLimiter(rate float64) *rateLimiter {
	if rate <= 0 {
		return &rateLimiter{}
	}
	return &rateLimiter{interval: time.Duration(float64(time.Second) / rate)}
}

func (l *rateLimiter) wait(ctx context.Context) {
	if l == nil || l.interval == 0 {
		return
	}
	l.mu.Lock()
	now := time.Now()
	slot := now
	if l.next.After(now) {
		slot = l.next
	}
	l.next = slot.Add(l.interval)
	l.mu.Unlock()
	delay := time.Until(slot)
	if delay <= 0 {
		return
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
