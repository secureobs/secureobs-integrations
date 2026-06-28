#!/usr/bin/env bash
# sync-versions.sh — reads VERSION and updates every version constant in the
# codebase so nothing needs to be touched manually after bumping the VERSION file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="$(cat "$SCRIPT_DIR/VERSION" | tr -d '[:space:]')"
IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"

CODE_TEMPLATES="$REPO_ROOT/SecureObs.Dashboard/src/app/core/utils/code-templates.ts"
INTEGRATIONS_CONTROLLER="$REPO_ROOT/SecureObs.API/Controllers/IntegrationsController.cs"

# Portable sed -i (macOS needs a backup extension, Linux doesn't care)
sedi() { sed -i.bak "$@" && rm -f "${@: -1}.bak"; }

echo "  Syncing versions → v${VERSION} (major: v${MAJOR})"

# ── code-templates.ts ────────────────────────────────────────────────────────
if [[ -f "$CODE_TEMPLATES" ]]; then
    sedi "s/^export const SCANNER_IMAGE_TAG  = 'v[0-9]*';$/export const SCANNER_IMAGE_TAG  = 'v${MAJOR}';/" "$CODE_TEMPLATES"
    sedi "s/^export const INTEGRATIONS_TAG   = 'v[^']*';$/export const INTEGRATIONS_TAG   = 'v${MAJOR}';/" "$CODE_TEMPLATES"
    echo "  ✔ code-templates.ts  →  SCANNER_IMAGE_TAG=v${MAJOR}  INTEGRATIONS_TAG=v${MAJOR}"
else
    echo "  ⚠ code-templates.ts not found — skipping"
fi

# ── IntegrationsController.cs ────────────────────────────────────────────────
if [[ -f "$INTEGRATIONS_CONTROLLER" ]]; then
    sedi "s/private const string DefaultLatestVersion = \"v[0-9][^\"]*\";/private const string DefaultLatestVersion = \"v${VERSION}\";/" "$INTEGRATIONS_CONTROLLER"
    echo "  ✔ IntegrationsController.cs  →  DefaultLatestVersion=v${VERSION}"
else
    echo "  ⚠ IntegrationsController.cs not found — skipping"
fi

# self-scan.yml is intentionally excluded: it pins the floating "v1" tag so it
# always dogfoods the latest release without per-build edits. The release CI
# cannot rewrite it anyway — GITHUB_TOKEN cannot push changes to files under
# .github/workflows/.

# features.component.ts is intentionally excluded: its YAML examples are now
# computed at runtime from IntegrationsVersionService.currentTag() so there
# are no hardcoded version strings left to patch.

# ── changelog.data.ts ────────────────────────────────────────────────────────
node "$REPO_ROOT/Scripts/generate-changelog.js"

echo "  Version sync complete."
