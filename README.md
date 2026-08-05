# 🔎 typo3-version-detector

**Fast TYPO3 fingerprinter - core version, extensions, versions, dependencies & CVEs in seconds.**

Pinpoints the exact TYPO3 version, enumerates installed extensions (plugins **and**
themes) with their **exact versions and dependencies**, and maps everything to published
CVEs - all driven by fingerprint databases built from the **official releases (majors
8 → 14, 290 versions)** and the **entire TER catalogue (9,289 extensions)**.

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![TYPO3](https://img.shields.io/badge/TYPO3-8->14-ff8700)](https://typo3.org)

---

```text
  t3scan -> https://example.com

  typo3         CONFIRMED  (powered-by-typo3 + <meta generator> + /_assets/)
  version       12.4.8  (EXACT - static-file hash)
     |- backend.css     md5:03406783 -> 12.4.8
     |- icons.json      md5:c1bba560 -> 12.4.0 - 12.4.19
     |- install mode    legacy
  cve           28 known  (7 high, 18 medium, 3 low)
     ! CVE-2024-22188 [high]  Install Tool vulnerable to Code Execution
     ! CVE-2024-25121 [high]  Improper Access Control persisting files
  extensions    3 found  (full TER catalogue - 9,289 keys)
     - news       v11.3.0 - 11.3.2   [georgringer/news]           (static-file hash)
        |- deps  typo3/cms-core ^11.5 - typo3/cms-extbase ^11.5
        ! CVE-2026-8726 [high]  SQL Injection in extension "News system"
     - solr       v11.5.4            [apache-solr-for-typo3/solr]
     - powermail  v10.9.0            [in2code/powermail]
```

## ✨ Features

- **Exact version fingerprinting** - `md5` of theme-independent core assets
  (`typo3/sysext/**/Resources/Public/**`) **intersected** against a database built across
  every official release. `backend.css` alone pins a patch; a served `composer.lock` or
  `ext_emconf.php` gives the exact version outright.
- **Complete extension database** - every TER plugin & theme (**9,289**), with per-version
  static-file hashes and declared dependencies, so the **installed version of any extension**
  is pinned by hashing what the target serves - even when metadata files are blocked.
- **Composer + legacy enumeration** - Composer mode (TYPO3 ≥ 11.4) via the deterministic
  `/_assets/<md5>/` path; legacy via `/typo3conf/ext/`, with **auto-selected marker files**
  (`ext_emconf.php` → `ext_localconf.php` → `ext_tables.php` → `composer.json`) so a host
  blocking one type is enumerated through another.
- **Behavioural + recon signals** - eID handlers (`dumpFile`/`tx_cms_showpic`) confirm TYPO3
  and bracket the major even on hardened/stripped sites; the backend importmap tightens the
  composer-mode band; and it flags exposed **Install Tool**, **debug/exception** pages, an
  **XML sitemap** (page-tree enumeration) and trusted-host disclosure.
- **CVE mapping** - core and extension versions matched against the official TYPO3 security
  advisory feed; certain hits on a pinned version, "possible" hits on a range.
- **Robust & honest** - a soft-404 / catch-all guard means a 200-everything host never
  false-matches; a file add/remove-boundary fallback still bands the version when content
  hashes miss (a patch newer than the DB, or a hardened site).
- **Built for pipelines** - concurrency, rate-limiting, `http`/`socks5` proxy (Burp, Tor),
  JSON output, and a `--fail-on-vuln` exit code.
- **Library + CLI + Nuclei** - embeddable Go SDK (`t3finger`), a colorized CLI, and a
  standalone Nuclei detection template.

## 📦 Install

```bash
go install github.com/Vozec/typo3-version-detector/cmd/t3scan@latest
```

Or build from source (all databases are embedded - the binary is self-contained):

```bash
git clone https://github.com/Vozec/typo3-version-detector
cd typo3-version-detector
make build      # -> ./t3scan
```

## 🚀 Usage

```bash
t3scan https://example.com                       # detect + core version + CVEs
t3scan scan -ext https://example.com             # full scan: version + extensions + CVEs
t3scan extensions -mode legacy -cve https://...  # extensions with exact versions + deps + CVEs
t3scan -json https://example.com                 # machine-readable
t3scan urls.txt -o out/                          # a file of targets -> one report per host in out/
cat urls.txt | t3scan -json -o out/              # or stream targets on stdin
t3scan -l scope.txt --fail-on-vuln               # scan a list, exit 2 if any CVE hits
t3scan -f https://example.com                    # force: report even if markers don't confirm TYPO3
t3scan -k -proxy socks5://127.0.0.1:9050 https://...   # skip TLS, route through Tor
```

**Targets** can be given as URLs, as a **file** of URLs (`t3scan urls.txt`), or on
**stdin** (`cat urls.txt | t3scan`) — flags may come before or after them.

**Output** (`-o`): for a single target it's a file; for a list it's a directory
(created if missing) with one normalized `<host><path>.txt` (or `.json`) per
host. Existing files are never overwritten — a `-<n>` suffix is added.

| Flag | Description |
|------|-------------|
| `-ext` | (on `scan`) also enumerate installed extensions |
| `-mode auto\|composer\|legacy` | extension enumeration mode (default `auto`) |
| `-cve` | look up known CVEs for the target / found extensions |
| `-t <n>` | max concurrent requests / threads |
| `-rate <n>` | cap requests per second (`0` = unlimited) |
| `-proxy <url>` | route through `http://`, `https://` or `socks5://` |
| `-l <file>` | read targets from a file (`-` for stdin) |
| `-o <path>` | output file (single target) or directory (list); `-<n>` suffix on collision |
| `-f`, `--force` | report/enumerate even when classic markers don't confirm TYPO3 |
| `-json` | machine-readable output |
| `-v` | verbose (every probed asset, full evidence) |
| `-k` | skip TLS certificate verification |
| `--fail-on-vuln` | exit code `2` if a confirmed CVE is found (CI-friendly) |

## 🧠 How it works

**Version = intersection of static-asset hashes.** `t3scan builddb` streams every official
release tarball and hashes the `Resources/Public` tree, emitting `path -> md5 -> [versions]`.
At scan time the tool fetches the most-discriminating files and **intersects** the candidate
sets - each hash narrows the band. Patch releases that touch no static asset are irreducible
passively, which the tool reports honestly as a tight range.

| Signal | Precision | Notes |
|--------|-----------|-------|
| `composer.lock` / `ext_emconf.php` | **exact** | when web-readable |
| static-asset content hash | exact patch → minor | the workhorse |
| file presence (add/remove boundary) | major/minor band | fallback for newer/hardened hosts |
| markers (`powered by TYPO3`, generator, `fe_typo_user`) | is-TYPO3 + install mode | one GET |

**Composer mode** publishes assets at `/_assets/<md5("/vendor/<vendor>/<package>/")>/` -
`403` = installed, `404` = not - so enumeration is one offline md5 plus one request per
candidate. **Legacy mode** probes a known file per extension: `ext_emconf.php` is mandatory
for every TER extension and carries the version, and the tool auto-falls-back to
`ext_localconf.php` / `ext_tables.php` / `composer.json` or the extension's public assets when
a host blocks one type.

**Extension versions** use the same hash-intersection technique per extension: the DB records
the content of each extension's public files across all its versions, so the installed version
is pinned from the bytes the target serves, independent of any metadata file.

## 📚 SDK

```go
import "github.com/Vozec/typo3-version-detector/pkg/t3finger"

f, _ := t3finger.New()

// core version + CVEs
res, _ := f.Detect(context.Background(), "https://example.com")
fmt.Println(res.Range, res.Confidence)          // "12.4.8" "high"
for _, v := range res.Vulnerabilities {
    fmt.Println(v.CVE, v.Title)
}

// legacy extensions - exact version (static-file hashes) + dependencies
keys := t3finger.DefaultExtensionKeys()
leg, _ := f.EnumerateExtensionsLegacy(context.Background(), "https://example.com", keys, nil)
for _, e := range leg.Extensions {
    if e.Confirmed {
        fmt.Printf("%s %s %v\n", e.Package, e.Version, e.Requires)
    }
}
```

Granular calls are exported too: `Detect`, `DetectMode`, `EnumerateExtensions`,
`EnumerateExtensionsLegacy`, `AnnotateExtensionCVEs`.

## 🗂️ Project layout

```
.
├── cmd/t3scan/            # CLI
├── pkg/t3finger/          # SDK package
│   ├── finger.go          # core version detection (static-hash intersection)
│   ├── enum.go            # composer-mode /_assets/ enumeration
│   ├── enum_legacy.go     # legacy enumeration + exact versions + deps
│   ├── db.go / builder.go        # core version DB + builder
│   ├── extprobes.go / extbuilder.go   # extension DB + builder
│   ├── advisories.go      # CVE advisory mapping
│   ├── probes.go          # markers, probe definitions, regexes
│   └── data/              # embedded databases (go:embed)
├── nuclei/                # companion detection template
└── Makefile               # build + database-rebuild targets
```

### Regenerating the databases

Everything embedded is regenerable from upstream; rebuild the binary afterwards to re-embed:

```bash
make db            # core version DB (get.typo3.org releases)
make extdb-full    # complete extension DB (every plugin+theme, all versions, hashes+deps)
make advisories    # CVE advisory set
make data          # all of the above, then rebuild the binary
```

Under the hood: `t3scan builddb`, `t3scan buildextdb -all` (resumable with `-merge`,
lighter with `-maxversions N`), `t3scan buildadvisories`. Nothing is written to disk during
a build - archives are streamed and hashed in memory; ELTS releases are gated and skipped.

## 🛡️ Nuclei template

A companion detection template ships in `nuclei/`:

- `nuclei/typo3-detect.yaml` - pre-auth, multi-signal (favicon mmh3, `powered by TYPO3`,
  generator meta, `fe_typo_user` cookie, Composer/legacy asset paths)

```bash
nuclei -t nuclei/typo3-detect.yaml -l scope.txt -silent
```

## ⚖️ Legal

For **authorized security testing only** - bug-bounty programs, pentest engagements, your own
infrastructure. You are responsible for having permission to scan the hosts you point this at.
WAF/rate-limited hosts may throttle; lower `-rate`/`-t` and run from authorized infra.

## License

MIT © [Vozec](https://github.com/Vozec)
