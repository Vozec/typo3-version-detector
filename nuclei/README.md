# Nuclei template — TYPO3 detection

`typo3-detect.yaml` — a clean, pre-auth [Nuclei](https://github.com/projectdiscovery/nuclei)
template that fingerprints the **TYPO3 CMS** from the outside, using several
independent signals (any one is enough):

| # | Signal | Where |
|---|---|---|
| 1 | `This website is powered by TYPO3` / `powered by TYPO3` | body |
| 2 | `<meta name="generator" content="TYPO3 CMS">` | body |
| 3 | `TYPO3 CMS` (default error page) | body |
| 4 | `fe_typo_user` / `be_typo_user` / `Typo3InstallTool` cookie | headers |
| 5 | `/_assets/<md5>/` (Composer mode) · `typo3conf/` · `typo3temp/` · `typo3/sysext/` | body |
| 6 | **Default favicon MurmurHash3** `-1655488378` | `/favicon.ico` |

It probes only pre-auth paths: `/`, `/typo3/` (backend login), `/favicon.ico`,
`/typo3/install.php`. It also extracts a version when core metadata is exposed.

## The favicon hash

`-1655488378` is the Shodan/FOFA-style mmh3 of the stock TYPO3 favicon
(`typo3/sysext/{backend,install}/Resources/Public/Icons/favicon.ico`), which is
byte-identical across TYPO3 8.x–14.x. Computed as
`mmh3(base64_py(favicon_bytes))` — the same expression Nuclei evaluates. Pivot
queries:

```
Shodan:  http.favicon.hash:-1655488378
FOFA:    icon_hash="-1655488378"
```

> Note: the hash matches when the site serves TYPO3's **default** favicon (very
> common for the backend and un-themed sites). Frontends that ship a custom
> favicon still trip signals #1–#5.

## Usage

```bash
nuclei -t nuclei/typo3-detect.yaml -u https://example.com
nuclei -t nuclei/typo3-detect.yaml -l targets.txt
nuclei -validate -t nuclei/typo3-detect.yaml
```

For deeper work — exact version, extension enumeration, per-version CVE mapping —
use the `t3scan` tool in this repo (the template is the quick "is it TYPO3?"
pass; `t3scan` is the full fingerprint).
