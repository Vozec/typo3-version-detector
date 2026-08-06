package t3finger

import (
	"context"
	"strings"
)

// Reachability is the outcome of a lightweight "are we actually allowed to talk
// to this host?" check — used to tell a real "not TYPO3 / no plugins" result
// apart from an IP ban / WAF block, where every path answers a blanket 4xx/5xx
// and any scan result would be meaningless.
type Reachability struct {
	Status    int    `json:"status"`           // HTTP status at the root
	Reachable bool   `json:"reachable"`        // got any HTTP response at all
	Blocked   bool   `json:"blocked"`          // root looks banned / WAF-blocked
	Reason    string `json:"reason,omitempty"` // human explanation
	WAF       string `json:"waf,omitempty"`    // detected WAF vendor, if any
}

// Reachability probes the target root and classifies whether we are being
// blocked. A network error is NOT a block (host down / DNS) — only a live HTTP
// response that denies us counts.
func (f *Fingerprinter) Reachability(ctx context.Context, target string) *Reachability {
	base, err := normalizeBase(target)
	if err != nil {
		return &Reachability{Reason: err.Error()}
	}
	r, err := f.get(ctx, base+"/") // follows redirects — a homepage normally 200s
	if err != nil || r == nil {
		msg := "no HTTP response from the root"
		if err != nil {
			msg = "no HTTP response from the root: " + err.Error()
		}
		return &Reachability{Reason: msg}
	}
	rc := &Reachability{Status: r.Status, Reachable: true, WAF: detectWAF(r.Header, r.Body)}
	switch {
	case r.Status == 429:
		rc.Blocked = true
		rc.Reason = "root returned HTTP 429 — rate-limited (lower -rate/-t, or you are temporarily banned)"
	case r.Status == 503:
		rc.Blocked = true
		rc.Reason = "root returned HTTP 503 — WAF challenge or blocked"
	case r.Status == 403:
		rc.Blocked = true
		rc.Reason = "root returned HTTP 403 — IP ban or WAF block likely"
	case r.Status == 401:
		rc.Blocked = true
		rc.Reason = "root returned HTTP 401 — authentication required at the edge"
	case rc.WAF != "" && bodyLooksLikeChallenge(r.Body):
		rc.Blocked = true
		rc.Reason = "root served a WAF challenge/deny page"
	}
	if rc.Blocked && rc.WAF != "" {
		rc.Reason += " (" + rc.WAF + ")"
	}
	return rc
}

// detectWAF names the edge/WAF from response headers and body signatures.
func detectWAF(header map[string][]string, body []byte) string {
	h := func(k string) string {
		if header == nil {
			return ""
		}
		if v, ok := header[k]; ok && len(v) > 0 {
			return strings.ToLower(v[0])
		}
		return ""
	}
	has := func(k string) bool { return header != nil && len(header[k]) > 0 }
	server := h("Server")
	switch {
	case strings.Contains(server, "cloudflare") || has("Cf-Ray"):
		return "Cloudflare"
	case has("X-Iinfo") || strings.Contains(h("X-Cdn"), "incapsula"):
		return "Imperva/Incapsula"
	case has("X-Sucuri-Id") || has("X-Sucuri-Cache"):
		return "Sucuri"
	case strings.Contains(server, "akamai") || has("X-Akamai-Transformed"):
		return "Akamai"
	case strings.Contains(server, "bigip") || strings.Contains(server, "big-ip") || has("X-Wa-Info"):
		return "F5 BIG-IP"
	case has("X-Amz-Cf-Id") && bodyLooksLikeChallenge(body):
		return "AWS WAF/CloudFront"
	}
	// Body signatures (case-insensitive).
	b := strings.ToLower(string(body))
	switch {
	case strings.Contains(b, "attention required") && strings.Contains(b, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(b, "incapsula incident"):
		return "Imperva/Incapsula"
	case strings.Contains(b, "sucuri website firewall"):
		return "Sucuri"
	case strings.Contains(b, "the requested url was rejected"):
		return "F5 BIG-IP"
	case strings.Contains(b, "akamaighost"):
		return "Akamai"
	}
	return ""
}

// bodyLooksLikeChallenge reports whether the body reads like a block/deny/CAPTCHA
// page rather than real site content.
func bodyLooksLikeChallenge(body []byte) bool {
	b := strings.ToLower(string(body))
	for _, s := range []string{
		"access denied", "attention required", "you have been blocked",
		"request unsuccessful", "the requested url was rejected",
		"incapsula incident", "cf-error", "captcha", "are you a human",
		"ray id", "blocked by", "security service",
	} {
		if strings.Contains(b, s) {
			return true
		}
	}
	return false
}
