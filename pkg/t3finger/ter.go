package t3finger

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"time"
)

// terExtensionsURL is the TER (TYPO3 Extension Repository) catalogue: a gzipped
// XML listing every published extension by its extension KEY (the sysext /
// typo3conf/ext folder name), which is what legacy installs expose on disk.
const terExtensionsURL = "https://typo3.org/fileadmin/ter/extensions.xml.gz"

var reExtensionKey = regexp.MustCompile(`<extension extensionkey="([^"]+)"`)

// FetchExtensionKeys downloads the TER catalogue and returns every unique
// extension key. Used by `t3scan buildwordlist -keys` and for legacy-mode
// enumeration, where extensions live at /typo3conf/ext/<key>/ rather than the
// Composer-mode /_assets/<md5>/ path.
func FetchExtensionKeys(ctx context.Context) ([]string, error) {
	c := &http.Client{Timeout: 120 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, terExtensionsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "t3scan/1.0 (+typo3-scanner)")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("TER: HTTP %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	body, err := io.ReadAll(io.LimitReader(gz, 256<<20))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var keys []string
	for _, m := range reExtensionKey.FindAllSubmatch(body, -1) {
		k := string(m[1])
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}
