package t3finger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

// packagistListURL returns every package of a given Composer type.
const packagistListURL = "https://packagist.org/packages/list.json?type=typo3-cms-extension"

// FetchExtensionList downloads the complete, current list of TYPO3 extension
// package names from Packagist. Used by `t3scan buildwordlist` to refresh the
// bundled default.
func FetchExtensionList(ctx context.Context) ([]string, error) {
	c := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, packagistListURL, nil)
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
		return nil, fmt.Errorf("packagist: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var out struct {
		PackageNames []string `json:"packageNames"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("packagist: parse: %w", err)
	}
	seen := map[string]bool{}
	names := out.PackageNames[:0]
	for _, n := range out.PackageNames {
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}
