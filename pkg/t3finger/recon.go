package t3finger

import (
	"bytes"
	"context"
	"regexp"
)

// Finding is a security-relevant pre-auth observation.
type Finding struct {
	Kind     string `json:"kind"`     // install-tool | debug-mode | sitemap | host-header | error-page
	Severity string `json:"severity"` // info | low | medium | high
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	URL      string `json:"url,omitempty"`
}

var (
	// DebugExceptionHandler output (Development context / displayErrors) — leaks
	// absolute paths, class names, source and stack frames.
	reDebugExc = regexp.MustCompile(`(?i)Uncaught TYPO3 Exception|exception-summary|trace-file-path|trace-class|<title>\s*TYPO3 Exception`)
	// Production error page (confirms TYPO3, no leak).
	reProdError     = regexp.MustCompile(`(?i)typo3-error-page-requestid|Oops, an error occurred`)
	reInstallLocked = regexp.MustCompile(`(?i)Install Tool is locked`)
	reInstallPwd    = regexp.MustCompile(`(?i)install tool password|Enter the install tool|installToolPassword`)
	reInstaller     = regexp.MustCompile(`(?i)Installing TYPO3|Welcome to the TYPO3 Installer|FIRST_INSTALL`)
	reSitemapXML    = regexp.MustCompile(`(?i)<(?:urlset|sitemapindex)\b`)
)

func (f *Fingerprinter) addFinding(res *VersionResult, fnd Finding) {
	res.Findings = append(res.Findings, fnd)
	res.IsTypo3 = true
}

// probeRecon runs a handful of cheap pre-auth requests that surface
// security-relevant exposure and double as robust TYPO3 confirmation.
func (f *Fingerprinter) probeRecon(ctx context.Context, base string, res *VersionResult) {
	// 1. Install Tool state.
	if r, err := f.getProbe(ctx, base+"/typo3/install.php"); err == nil && r != nil && r.Status == 200 {
		switch {
		case reInstaller.Match(r.Body):
			f.addFinding(res, Finding{"install-tool", "high", "TYPO3 Installer reachable (FIRST_INSTALL)", "unauthenticated install wizard — full takeover", base + "/typo3/install.php"})
		case reInstallPwd.Match(r.Body):
			f.addFinding(res, Finding{"install-tool", "medium", "Install Tool login exposed", "password prompt reachable pre-auth (brute-force target)", base + "/typo3/install.php"})
		case reInstallLocked.Match(r.Body):
			f.addFinding(res, Finding{"install-tool", "info", "Install Tool present (locked)", "", base + "/typo3/install.php"})
		}
	}

	// 2. Debug / exception exposure — a crafted page type triggers rendering.
	if r, err := f.get(ctx, base+"/?type=98765432"); err == nil && r != nil {
		switch {
		case reDebugExc.Match(r.Body):
			f.addFinding(res, Finding{"debug-mode", "high", "Debug exception page exposed", "Development context / displayErrors leaks absolute paths, classes and stack traces", base + "/?type=98765432"})
		case reProdError.Match(r.Body):
			res.IsTypo3 = true
			res.Markers = appendUniq(res.Markers, "TYPO3 error page (requestId)")
		}
	}

	// 3. Trusted-host check — a spoofed Host throws (500 + config-var name).
	if r := f.getHost(ctx, base+"/", "zzz-not-a-real-host.invalid"); r != nil {
		if r.Status >= 500 && bytes.Contains(r.Body, []byte("trustedHostsPattern")) {
			res.IsTypo3 = true
			res.Markers = appendUniq(res.Markers, "trusted-host check (SYS/trustedHostsPattern)")
		}
	}

	// 4. XML sitemap (EXT:seo) — full page-tree enumeration incl. unlinked pages.
	if r, err := f.get(ctx, base+"/?type=1533906435"); err == nil && r != nil && r.Status == 200 && reSitemapXML.Match(r.Body) {
		f.addFinding(res, Finding{"sitemap", "low", "XML sitemap exposed", "enumerates the page tree (EXT:seo)", base + "/?type=1533906435"})
	}
}
