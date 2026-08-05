package t3finger

import (
	"bufio"
	_ "embed"
	"os"
	"strings"
)

//go:embed data/extensions.txt
var embeddedExtensions string

//go:embed data/extension-keys.txt
var embeddedExtensionKeys string

//go:embed data/extension-seed.txt
var embeddedExtensionSeed string

// SeedExtensionKeys returns the curated seed list of common extension keys used
// by `t3scan buildextdb` to build the default extension-probe DB.
func SeedExtensionKeys() []string { return splitLines(embeddedExtensionSeed) }

// DefaultExtensionList returns the bundled Packagist TYPO3-extension names
// (vendor/package), used for Composer-mode /_assets/ enumeration.
// Refresh it with `t3scan buildwordlist`.
func DefaultExtensionList() []string {
	return splitLines(embeddedExtensions)
}

// DefaultExtensionKeys returns the bundled TER extension keys (folder names),
// used for legacy-mode /typo3conf/ext/<key>/ enumeration.
// Refresh it with `t3scan buildwordlist -keys`.
func DefaultExtensionKeys() []string {
	return splitLines(embeddedExtensionKeys)
}

// LoadExtensionKeys reads extension keys from a file, or returns the embedded
// default when path is empty.
func LoadExtensionKeys(path string) ([]string, error) {
	if path == "" {
		return DefaultExtensionKeys(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return splitLines(string(b)), nil
}

// LoadExtensionList reads candidate packages from a file (one per line, '#'
// comments allowed). If path is empty, the embedded default list is returned.
func LoadExtensionList(path string) ([]string, error) {
	if path == "" {
		return DefaultExtensionList(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return splitLines(string(b)), nil
}

func splitLines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
