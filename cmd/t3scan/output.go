package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// stdout is where human/JSON output is written. It defaults to the real stdout
// but is swapped to a buffer when capturing a target's output for a file.
var stdout io.Writer = os.Stdout

// normalizeHost turns a target URL into a filesystem-safe file stem from its
// host AND path, e.g. "https://Example.COM/de/foo" ->
// "example.com_de_foo". The dotted host is kept so the name ends in
// ".<tld>" (then the path, then the extension).
func normalizeHost(target string) string {
	t := strings.TrimSpace(target)
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	name := t
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		name = u.Host + u.Path
		if u.Port() != "" {
			name = u.Hostname() + "_" + u.Port() + u.Path
		}
	}
	name = strings.ToLower(name)
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '_'
		}
	}, name)
	// collapse runs of underscores and trim separators
	for strings.Contains(name, "__") {
		name = strings.ReplaceAll(name, "__", "_")
	}
	name = strings.Trim(name, "._-")
	if name == "" {
		name = "target"
	}
	return name
}

// outputSink resolves where each target's result is written.
//
//   - single target + -o: -o is a FILE path (used verbatim).
//   - multiple targets + -o: -o is a DIRECTORY (created); one file per host,
//     named "<normalized-host><ext>".
//
// On a name collision (file already on disk, or already produced this run) a
// "-<n>" suffix is inserted before the extension.
type outputSink struct {
	dest string
	dir  bool
	ext  string // ".json" for JSON output, else ".txt"
	used map[string]bool
}

func newSink(dest string, multi, jsonMode bool) (*outputSink, error) {
	if dest == "" {
		return nil, nil
	}
	ext := ".txt"
	if jsonMode {
		ext = ".json"
	}
	s := &outputSink{dest: dest, dir: multi, ext: ext, used: map[string]bool{}}
	if multi {
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return nil, err
		}
	} else if d := filepath.Dir(dest); d != "" && d != "." {
		_ = os.MkdirAll(d, 0o755)
	}
	return s, nil
}

// path returns a non-colliding output path for target and marks it used.
func (s *outputSink) path(target string) string {
	base := s.dest
	if s.dir {
		base = filepath.Join(s.dest, normalizeHost(target)+s.ext)
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	p := base
	for n := 1; s.used[p] || fileExists(p); n++ {
		p = fmt.Sprintf("%s-%d%s", stem, n, ext)
	}
	s.used[p] = true
	return p
}

// write renders content to the resolved path and returns it.
func (s *outputSink) write(target string, content []byte) (string, error) {
	p := s.path(target)
	return p, os.WriteFile(p, content, 0o644)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
