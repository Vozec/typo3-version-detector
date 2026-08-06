package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Vozec/typo3-version-detector/pkg/t3finger"
)

// hostRecord is one host's scan result, normalized from any of the JSON shapes
// t3scan emits (scan report, extension result, or version result).
type hostRecord struct {
	Host       string
	Typo3      string
	Confidence string
	Mode       string
	Blocked    bool
	Exts       []t3finger.Extension
}

// runPrint renders saved scan JSON as tables: by host (default) or by plugin.
func runPrint(args []string) {
	fs := flag.NewFlagSet("print", flag.ExitOnError)
	byPlugin := fs.Bool("by-plugin", false, "group by plugin (which host runs each plugin) instead of by host")
	asJSON := fs.Bool("json", false, "re-emit the merged records as JSON")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	onlyVuln := fs.Bool("cve", false, "show only plugins that have known CVEs")
	all := fs.Bool("all", false, "include unconfirmed / ambiguous plugins too")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Render saved scan JSON as tables.\n\nUsage:\n  t3scan print [flags] <file.json | dir> [...]\n  t3scan scan -json -o out/ ...   &&   t3scan print out/\n\nFlags:\n")
		fs.PrintDefaults()
	}
	positionals := parseFlags(fs, args)
	if *noColor || *asJSON {
		useColor = false
	}
	if len(positionals) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	files := collectJSONFiles(positionals)
	if len(files) == 0 {
		fatal(fmt.Errorf("no .json files found in %s", strings.Join(positionals, ", ")))
	}
	var records []hostRecord
	for _, fp := range files {
		b, err := os.ReadFile(fp)
		if err != nil {
			fmt.Fprintln(os.Stderr, cYellow("skip "+fp+": "+err.Error()))
			continue
		}
		recs := recordsFromJSON(b)
		if len(recs) == 0 {
			fmt.Fprintln(os.Stderr, cDim("no recognizable scan data in "+fp))
		}
		records = append(records, recs...)
	}
	records = mergeByHost(records)
	if len(records) == 0 {
		fatal(fmt.Errorf("nothing to print"))
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(records)
		return
	}
	if *byPlugin {
		printByPlugin(records, *onlyVuln)
	} else {
		printByHost(records, *onlyVuln, *all)
	}
}

// collectJSONFiles expands positionals (files or directories) into a sorted list
// of .json files.
func collectJSONFiles(paths []string) []string {
	var out []string
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, cYellow("skip "+p+": "+err.Error()))
			continue
		}
		if fi.IsDir() {
			filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() && strings.HasSuffix(strings.ToLower(path), ".json") {
					out = append(out, path)
				}
				return nil
			})
		} else {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// recordsFromJSON parses one JSON document (a scan report, extension result,
// version result, or an array of any of these) into host records.
func recordsFromJSON(raw []byte) []hostRecord {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	if raw[0] == '[' { // array — recurse each element
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil {
			return nil
		}
		var out []hostRecord
		for _, e := range arr {
			out = append(out, recordsFromJSON(e)...)
		}
		return out
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil {
		return nil
	}
	trim := func(k string) []byte { return bytes.TrimSpace(keys[k]) }

	// scan report: "version" is a nested object.
	if v := trim("version"); len(v) > 0 && v[0] == '{' {
		var sr scanReport
		if json.Unmarshal(raw, &sr) == nil {
			return []hostRecord{recordFromScan(sr.Target, sr.Version, sr.Extensions)}
		}
	}
	// extension result: "extensions" is an array.
	if e := trim("extensions"); len(e) > 0 && e[0] == '[' {
		var er t3finger.ExtResult
		if json.Unmarshal(raw, &er) == nil {
			return []hostRecord{recordFromExt(&er)}
		}
	}
	// version result: has isTypo3.
	if _, ok := keys["isTypo3"]; ok {
		var vr t3finger.VersionResult
		if json.Unmarshal(raw, &vr) == nil {
			return []hostRecord{recordFromScan(vr.Target, &vr, nil)}
		}
	}
	return nil
}

func recordFromScan(target string, vr *t3finger.VersionResult, er *t3finger.ExtResult) hostRecord {
	rec := hostRecord{Host: hostLabel(target)}
	if vr != nil {
		if rec.Host == "" {
			rec.Host = hostLabel(vr.Target)
		}
		rec.Typo3, rec.Confidence, rec.Mode = vr.Range, vr.Confidence, string(vr.Mode)
		rec.Blocked = vr.Blocked
	}
	if er != nil {
		if rec.Host == "" {
			rec.Host = hostLabel(er.Target)
		}
		rec.Blocked = rec.Blocked || er.Blocked
		rec.Exts = er.Extensions
	}
	return rec
}

func recordFromExt(er *t3finger.ExtResult) hostRecord {
	return hostRecord{Host: hostLabel(er.Target), Blocked: er.Blocked, Exts: er.Extensions}
}

// hostLabel strips the scheme (and trailing slash) from a target for display.
func hostLabel(target string) string {
	s := strings.TrimSpace(target)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	return strings.TrimRight(s, "/")
}

// mergeByHost combines records sharing a host (e.g. a version file + an ext file
// for the same target), preferring non-empty version info and unioning plugins.
func mergeByHost(records []hostRecord) []hostRecord {
	idx := map[string]int{}
	var out []hostRecord
	for _, r := range records {
		if r.Host == "" {
			r.Host = "(unknown)"
		}
		if i, ok := idx[r.Host]; ok {
			m := &out[i]
			if m.Typo3 == "" {
				m.Typo3, m.Confidence, m.Mode = r.Typo3, r.Confidence, r.Mode
			}
			m.Blocked = m.Blocked || r.Blocked
			m.Exts = append(m.Exts, r.Exts...)
		} else {
			idx[r.Host] = len(out)
			out = append(out, r)
		}
	}
	for i := range out {
		out[i].Exts = dedupExts(out[i].Exts)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func dedupExts(exts []t3finger.Extension) []t3finger.Extension {
	seen := map[string]bool{}
	var out []t3finger.Extension
	for _, e := range exts {
		k := e.Package + "|" + e.Key + "|" + e.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}

// keep reports whether a plugin should be shown given the -all / -cve filters.
func keep(e t3finger.Extension, onlyVuln, all bool) bool {
	if onlyVuln && len(e.Vulns) == 0 && len(e.VulnsPossible) == 0 {
		return false
	}
	if !all && !e.Confirmed {
		return false
	}
	return true
}

func latestCell(e t3finger.Extension) (string, func(string) string) {
	if e.Latest == "" {
		return "-", cDim
	}
	if e.Outdated {
		return "⇡ " + e.Latest, cYellow
	}
	return e.Latest, cGreen
}

func cveCell(e t3finger.Extension) (string, func(string) string) {
	switch {
	case len(e.Vulns) > 0:
		return fmt.Sprintf("%d!", len(e.Vulns)), cRed
	case len(e.VulnsPossible) > 0:
		return fmt.Sprintf("~%d", len(e.VulnsPossible)), cYellow
	}
	return "-", cDim
}

func pluginLabel(e t3finger.Extension) string {
	p := e.Package
	if e.Ambiguous && e.Key != "" {
		p += " (" + e.Key + ")"
	}
	return p
}

// printByHost renders one section per host with its plugin table.
func printByHost(records []hostRecord, onlyVuln, all bool) {
	shownHosts, totalPlugins := 0, 0
	for _, r := range records {
		var rows []t3finger.Extension
		for _, e := range r.Exts {
			if keep(e, onlyVuln, all) {
				rows = append(rows, e)
			}
		}
		if onlyVuln && len(rows) == 0 {
			continue
		}
		shownHosts++
		totalPlugins += len(rows)

		head := cCyan("▸ ") + cBold(r.Host)
		if r.Blocked {
			head += "   " + cRed("⛔ blocked")
		} else if r.Typo3 != "" {
			head += "   " + cDim("TYPO3 ") + cBold(r.Typo3)
			if r.Confidence != "" {
				head += cDim(" (" + r.Confidence + ")")
			}
		}
		fmt.Fprintf(stdout, "\n%s\n", head)
		if len(rows) == 0 {
			fmt.Fprintf(stdout, "  %s\n", cDim("no extensions recorded"))
			continue
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Package < rows[j].Package })
		printPluginTable(rows)
	}
	fmt.Fprintf(stdout, "\n%s %d host%s, %d plugin%s\n", cDim("›"), shownHosts, plural2(shownHosts), totalPlugins, plural2(totalPlugins))
}

// printPluginTable prints a compact, terminal-fit PLUGIN/VERSION/LATEST/CVE table.
func printPluginTable(rows []t3finger.Extension) {
	type c struct {
		plugin, ver, latest, cve string
		vc, lc, cc               func(string) string
	}
	cells := make([]c, len(rows))
	wP, wV, wL := len("PLUGIN"), len("VERSION"), len("LATEST")
	for i, e := range rows {
		ver, vc := e.Version, cCyan
		if ver == "" {
			ver, vc = "?", cDim
		} else if e.VersionExact && len(e.VersionCandidates) <= 1 {
			vc = cGreen
		}
		lt, lc := latestCell(e)
		cv, cc := cveCell(e)
		cells[i] = c{pluginLabel(e), ver, lt, cv, vc, lc, cc}
		wP = maxi(wP, dispLen(cells[i].plugin))
		wV = maxi(wV, dispLen(ver))
		wL = maxi(wL, dispLen(lt))
	}
	if w := termWidth() - (wV + wL + 6 + 6); wP > w && w > 12 { // keep it on-screen
		wP = w
	}
	fmt.Fprintf(stdout, "  %s  %s  %s  %s\n",
		cBold(pad("PLUGIN", wP)), cBold(pad("VERSION", wV)), cBold(pad("LATEST", wL)), cBold("CVE"))
	for _, x := range cells {
		fmt.Fprintf(stdout, "  %s  %s  %s  %s\n",
			pad(ellipsizeMiddle(x.plugin, wP), wP), x.vc(pad(x.ver, wV)), x.lc(pad(x.latest, wL)), x.cc(x.cve))
	}
}

// printByPlugin inverts the view: one section per plugin listing the hosts.
func printByPlugin(records []hostRecord, onlyVuln bool) {
	type hostVer struct {
		host string
		e    t3finger.Extension
	}
	groups := map[string][]hostVer{}
	var order []string
	for _, r := range records {
		for _, e := range r.Exts {
			if !e.Confirmed || (onlyVuln && len(e.Vulns) == 0 && len(e.VulnsPossible) == 0) {
				continue
			}
			key := e.Package
			if _, ok := groups[key]; !ok {
				order = append(order, key)
			}
			groups[key] = append(groups[key], hostVer{r.Host, e})
		}
	}
	if len(order) == 0 {
		fmt.Fprintf(stdout, "%s\n", cDim("no plugins found in the input"))
		return
	}
	// Most-widespread plugins first.
	sort.Slice(order, func(i, j int) bool {
		if len(groups[order[i]]) != len(groups[order[j]]) {
			return len(groups[order[i]]) > len(groups[order[j]])
		}
		return order[i] < order[j]
	})

	for _, key := range order {
		g := groups[key]
		sort.Slice(g, func(i, j int) bool { return g[i].host < g[j].host })
		head := cBold(key) + cDim(fmt.Sprintf("  (%d host%s)", len(g), plural2(len(g))))
		if latest := g[0].e.Latest; latest != "" {
			head += cDim("  · latest ") + cGreen(latest)
		}
		if a := g[0].e.Author; a != "" {
			head += cDim("  · " + a)
		}
		fmt.Fprintf(stdout, "\n%s\n", head)

		wH, wV := len("HOST"), len("VERSION")
		for _, hv := range g {
			wH = maxi(wH, dispLen(hv.host))
			v := hv.e.Version
			if v == "" {
				v = "?"
			}
			wV = maxi(wV, dispLen(v))
		}
		if w := termWidth() - (wV + 12); wH > w && w > 12 {
			wH = w
		}
		fmt.Fprintf(stdout, "  %s  %s  %s\n", cBold(pad("HOST", wH)), cBold(pad("VERSION", wV)), cBold("LATEST"))
		for _, hv := range g {
			v := hv.e.Version
			if v == "" {
				v = "?"
			}
			lt, lc := latestCell(hv.e)
			fmt.Fprintf(stdout, "  %s  %s  %s\n", pad(ellipsizeMiddle(hv.host, wH), wH), cCyan(pad(v, wV)), lc(lt))
		}
	}
	fmt.Fprintf(stdout, "\n%s %d distinct plugin%s across %d host%s\n", cDim("›"), len(order), plural2(len(order)), len(records), plural2(len(records)))
}
