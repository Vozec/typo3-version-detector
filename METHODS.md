# Pre-auth TYPO3 detection — method catalogue

Every vector below is reachable **without authentication**. Ranked roughly by
precision × robustness. Legend: ✅ implemented · 🟡 partial · ⬜ possible/planned.

---

## A. Is it TYPO3? (identification)  ✅

Fetched pages: `/`, `/typo3/`, `/typo3/index.php`, plus one random path.

- **`powered by TYPO3`** — the rendered frontend header comment
  (`Typo3Information::getInlineHeaderComment`). Strong, present unless disabled.
- **`<meta name="generator" content="TYPO3 CMS">`** — PageRenderer generator tag.
- **TYPO3 CMS 404 page** — the default error page contains `TYPO3 CMS`.
- **Backend endpoint** — `/typo3/` / `/typo3/index.php` returning a Login title
  or 401/403 ("Backend access denied").
- **Asset-path leakage** — `href`/`src` pointing at `typo3conf/ext`,
  `typo3/sysext`, `typo3temp`, `fileadmin` (legacy) or `/_assets/<md5>/`
  (composer). Also yields the **install mode** and any **base sub-path**.

## B. Install mode: composer vs legacy  ✅

- `/_assets/<32-hex>/` URLs in the HTML ⇒ **composer** mode (TYPO3 ≥ 11).
- `typo3conf/ext/…` / direct `typo3/sysext/…` URLs ⇒ **legacy** mode.

Mode decides the version strategy: legacy exposes the whole `typo3/sysext/**`
tree for direct path-based hashing; composer hides core under `vendor/` and only
publishes assets under opaque `/_assets/<md5>/` paths (content-only matching).

---

## Tier 1 — exact version

### 1. Exposed `composer.lock`  ✅
`/composer.lock` at the docroot, if web-readable, pins `typo3/cms-core` to an
**exact** version. Best possible signal. (Often blocked, but worth one request.)

### 2. `ext_emconf.php` / sysext `composer.json` content  ✅ / 🟡
`typo3/sysext/core/ext_emconf.php` carries `'version' => 'x.y.z'` in legacy
installs — an exact read. (Core `composer.json` has its `version` field stripped
at packaging, so it is hash-only; extension `composer.json`/`ext_emconf.php` do
carry versions and are used for extension-version detection.)

---

## Tier 2 — static-asset content hashing (the workhorse)  ✅

TYPO3's served static files are **byte-identical within a release** and change
between releases — frequently **per patch**. Hash what the target serves, look
each digest up in a per-version database, and intersect the candidate sets.

- **Legacy:** probe curated paths (and any extra discriminating path the DB
  knows) directly under the web root — `typo3/sysext/**/Resources/Public/**`.
- **Composer:** the `/_assets/<md5>/…` path can't be mapped to a source path, so
  harvested asset URLs are matched by **content only** (md5 → versions across all
  paths).

**Highest-signal file:** `typo3/sysext/backend/Resources/Public/Css/backend.css`
— present 8.x → 13.x and unique per patch. The CKEditor 5 bundle, top-level
backend JS (`modal.js`, `date-time-picker.js`, …) and `icons.json` corroborate.

The database is built by the tool itself (`t3scan builddb`) from the official
release feed `get.typo3.org/api/v1/release/` and the CDN tarballs
`cdn.typo3.com/typo3/<v>/typo3_src-<v>.tar.gz`, hashing the depth-1
`Resources/Public` files of every non-ELTS release. Paths whose content never
varies are pruned; what remains is exactly the signal-bearing set.

**Precision:** patch-level where the DB covers the version and a discriminating
file is served; otherwise a tight minor-level range (e.g. `12.4.x (12.4.8 –
12.4.11)`). Composer-mode installs that expose no hashable core assets fall back
to minor/marker level.

### Presence-based narrowing (add/remove boundaries)  ✅
Beyond content, the mere **presence** of a core file bounds the version. When the
host cleanly 404s a bogus asset (so 200s are trustworthy), a served core file
that could *not* be content-matched — a patch newer than the DB, or a
themed/hardened target — still narrows: candidate ⊆ the versions that ship that
path. Naming boundaries do the work (kebab-case `modal.js` ⇒ ≥12, CamelCase
`Modal.js` ⇒ ≤11; files added/removed across redesigns). This yields a
major/minor band (method `file presence (add/remove boundaries)`) where content
hashing alone would return nothing. In composer/unknown mode only **positive**
presence is used (a 404 there just means `vendor/` is hidden). In **legacy** mode
— where the whole `typo3/sysext/**` tree is genuinely web-served — a 404 for a
DB-known path is real absence, so candidate ⊆ the versions that *don't* ship it
(absence narrowing). That legacy 404-exclusion is additionally gated on a stock
file already having content-matched, so a custom theme dropping a file can't
cause a false exclusion.

### Soft-404 / catch-all guard  ✅
Before trusting any 200, a bogus asset path is calibrated. Hosts that answer
every path with a 200 landing page (SPA catch-all / soft-404) would otherwise
turn every probe into a "served" file; any probe whose body equals the
calibration body is discarded, so a catch-all can never produce a false match.

---

## Tier 3 — extensions  ✅

### Enumeration (composer mode) — deterministic asset path  ✅
`/_assets/<md5("/vendor/<vendor>/<package>/")>/` → 403 installed / 404 absent.
Baseline calibrated per target; hits confirmed against known subpaths to reject
dangling symlinks. Candidate list = the full Packagist TYPO3-extension catalogue
(bundled, refreshable via `buildwordlist`). See the README for the mechanics.

### Enumeration (legacy mode)  ✅
Classic installs expose `/typo3conf/ext/<key>/` and `/typo3/sysext/<key>/`
directly. `t3scan extensions -mode legacy` calibrates a per-location baseline
with a bogus key, then probes the TER key catalogue (~9 300 keys, bundled) and
confirms each hit against a known subpath. `-mode auto` (default) detects the
install layout first and picks composer vs legacy automatically.

### Extension version  ✅ (legacy)
Because the legacy extension root is reachable, each found extension's version is
read from its own metadata, most-reliable first: `ext_emconf.php`
(`'version' => 'x.y.z'`), `composer.json` (`"version": "x.y.z"`),
`Documentation/Settings.{cfg,yml,yaml}` (`release =`), then `ChangeLog`. A body
matching the soft-404 baseline is ignored. (Composer mode exposes only
`Resources/Public` under `/_assets/`, so per-extension versions aren't readable
there.)

---

## Tier 4 — known-CVE mapping  ✅

Each detected core version is checked against the official **TYPO3 core security
advisories** (the Packagist `security-advisories` feed for `typo3/cms-core`, 129
advisories embedded, refreshable via `buildadvisories`). Each advisory carries a
Composer version constraint (`>=12.0.0,<12.4.46|…`) evaluated by a small
OR/AND comparator matcher:

- **pinned version** → advisories that match it are *certain* (`⚠ N`).
- **unpinned range** → an advisory affecting *every* candidate is certain; one
  affecting only *some* is reported as *possible* (`~N`) until the version is
  pinned. This avoids both false alarms and silent misses on a range.

The fix-version boundary is respected: e.g. 12.4.46 (the patch) reports 0 where
12.4.45 reports the advisory.

**Extensions too:** with `extensions -mode legacy -cve`, each found extension
that exposes a version *and* a `composer.json` name is looked up against the same
Packagist feed (one batched request for all found packages), so third-party
extension CVEs are flagged alongside the core ones.

---

## Corroborating signals (presence only)  🟡/⬜

- Cookies: `fe_typo_user` (frontend session), `be_typo_user` (backend, post-auth),
  `Typo3InstallTool`. Presence ⇒ TYPO3; no version encoded.
- HTTP headers carry no default version leak.
- Backend login-page markup/asset set differs notably across 9/10/11/12/13 →
  usable as a **major-branch** classifier when patch-level is impossible. ⬜

---

## Strategy summary

```
identify (markers + mode + base path)
  → exact read (composer.lock / ext_emconf.php)         → done, high confidence
  → else: hash assets (legacy paths ∪ harvested URLs)
          ∩ intersect candidate sets  (catch-all-guarded)
          → unique = exact patch · else tight minor range
  → else: markers only (is-TYPO3, low confidence)
  → map version/range → known CVEs (certain vs possible)
```

The embedded version DB covers majors **8 → 14** (290 releases); extend or
refresh it with `t3scan builddb` (incremental via `-i`). Advisories and both
extension wordlists refresh independently (`buildadvisories`, `buildwordlist
[-keys]`).
