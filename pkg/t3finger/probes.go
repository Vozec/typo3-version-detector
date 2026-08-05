package t3finger

import "regexp"

// DefaultProbes is the curated set of publicly-served static core files we hash
// for version detection in LEGACY (non-composer) installs. Paths are relative
// to the TYPO3 web root (i.e. what a browser requests). They were chosen for
// two properties: they exist across many releases, and their content changes
// between releases (often per-patch), so their md5 pins the version tightly.
//
// Location naming changed across majors (CamelCase JS in ≤11, kebab-case ES
// modules in 12+), so both spellings are listed; a 404 on the wrong one is
// harmless. The engine also auto-probes any additional discriminating path the
// embedded DB knows about, so a fuller DB extends coverage without code changes.
var DefaultProbes = []string{
	// backend.css is the single best signal: present 8.x→13.x, changes per patch.
	"typo3/sysext/backend/Resources/Public/Css/backend.css",
	// Icons manifest — changes across minors.
	"typo3/sysext/core/Resources/Public/Icons/T3Icons/icons.json",
	// CKEditor 5 bundle files (12+) change per patch.
	"typo3/sysext/rte_ckeditor/Resources/Public/Contrib/@ckeditor/ckeditor5-core.js",
	"typo3/sysext/rte_ckeditor/Resources/Public/Contrib/ckeditor5-bundle.js",
	// Backend JS — kebab-case (12/13) and CamelCase (9–11) spellings.
	"typo3/sysext/backend/Resources/Public/JavaScript/date-time-picker.js",
	"typo3/sysext/backend/Resources/Public/JavaScript/modal.js",
	"typo3/sysext/backend/Resources/Public/JavaScript/module-menu.js",
	"typo3/sysext/backend/Resources/Public/JavaScript/Modal.js",
	"typo3/sysext/backend/Resources/Public/JavaScript/ModuleMenu.js",
	"typo3/sysext/backend/Resources/Public/JavaScript/FormEngine.js",
	"typo3/sysext/backend/Resources/Public/JavaScript/LoginRefresh.js",
	// ES-module shim (11–12 era).
	"typo3/sysext/core/Resources/Public/JavaScript/Contrib/es-module-shims.js",
	// Older eras (6.x–8.x).
	"typo3/sysext/rtehtmlarea/htmlarea/htmlarea.js",
	"typo3/sysext/install/Resources/Public/JavaScript/Install.js",
	"typo3/sysext/t3skin/stylesheets/visual/element_message.css",
	// Very old legacy CLI stub / core file.
	"typo3/cli_dispatch.phpsh",
}

// FullProbeSet is every public core file path a version could serve. It is not
// hardcoded; the DB builder hashes the entire typo3/sysext/**/Resources/Public
// tree, and the DB's discriminating paths drive extended probing at runtime.

// ---- is-TYPO3 identification pages ----

// identifyPages are fetched (relative to the site base) to confirm TYPO3 and to
// learn the install sub-path and composer-vs-legacy mode from asset URLs.
var identifyPages = []string{"/", "/typo3/", "/typo3/index.php"}

// TYPO3 body/marker regexes (from the rendered FE header comment, the meta
// generator tag, and the default error page).
var (
	rePoweredBy   = regexp.MustCompile(`(?i)powered by TYPO3`)
	reGenerator   = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["'][^"']*TYPO3\s*CMS`)
	reTypo3CMS    = regexp.MustCompile(`(?i)TYPO3\s*CMS`)
	reBackendHint = regexp.MustCompile(`(?i)Backend access denied|typo3/index\.php|TYPO3 Login|<title>[^<]*Login`)

	// Asset-path leakage in href/src attributes → base path + install mode.
	reAssetLegacy   = regexp.MustCompile(`(?:href|src)=["']([^"']*(?:typo3conf/ext|typo3/sysext|typo3temp|fileadmin)/[^"']*)["']`)
	reAssetComposer = regexp.MustCompile(`(?:href|src)=["']([^"']*/_assets/[0-9a-f]{32}/[^"']*)["']`)
	// General asset URL harvest (any of the above), used to hash discovered files.
	reAnyAsset = regexp.MustCompile(`(?:href|src)=["']([^"'?#]+\.(?:js|css|svg|png|gif|ico|json))(?:[?#][^"']*)?["']`)
	// Extension keys referenced in the HTML: typo3conf/ext/<key>/ or EXT:<key>.
	reExtKeyInPath = regexp.MustCompile(`(?:typo3conf/ext/|EXT:)([a-z0-9][a-z0-9_]{1,60})`)
)

// eID behavioral probes. TYPO3 registers eID entrypoints reachable at
// /index.php?eID=<name>; each returns a handler-specific status even without
// valid params, which is a strong pre-auth TYPO3 marker (survives stripped HTML
// and custom themes). Some were removed at a known release, giving a version
// boundary. Verified across 11.5/12.4/13.4 source (ext_localconf eID_include).
var eidAlways = []string{"dumpFile", "tx_cms_showpic"} // present in all supported versions
// eidRemovedIn13 were registered in ≤12 and removed in 13.0 → presence ⇒ ≤12,
// clean 404 (on a confirmed-TYPO3 host) ⇒ ≥13.
var eidRemovedIn13 = []string{"requirejs", "adminPanel_save"}

// ---- content-based version parsing (exact when the file is exposed) ----

var (
	// ext_emconf.php: 'version' => '1.2.3'
	reEmconfVersion = regexp.MustCompile(`'version'\s*=>\s*'([0-9]+\.[0-9]+\.[0-9]+)'`)
	// composer.json: "version": "1.2.3"  (or dev-master alias)
	reComposerVersion = regexp.MustCompile(`(?:"dev-master"|"version")\s*[:=]\s*"?([0-9]+\.[0-9]+\.?[0-9x]?[0-9x]?)`)
	// composer.json: "name": "vendor/package"
	reComposerName = regexp.MustCompile(`"name"\s*:\s*"([a-z0-9]([a-z0-9._-]*)/[a-z0-9]([a-z0-9._-]*))"`)
	// Documentation/Settings.{yml,yaml,cfg}: release = 1.2 / version: 1.2.3
	reSettingsRelease = regexp.MustCompile(`(?i)(?:release|version)\s*[=:]\s*"?([0-9]+\.[0-9]+\.?[0-9]?[0-9]?)`)
	// composer.lock: pins typo3/cms-core to an exact version.
	reLockCmsCore = regexp.MustCompile(`(?s)"name"\s*:\s*"typo3/cms-core".*?"version"\s*:\s*"v?([0-9]+\.[0-9]+\.[0-9]+)"`)
	// Generic fallback version token.
	reGenericVersion = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9x][0-9x]?)`)
)
