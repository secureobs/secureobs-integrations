#!/usr/bin/env bash
set -euo pipefail

# ── Progress helpers ──────────────────────────────────────────────────────────
TOTAL_STEPS=6
CURRENT_STEP=0
START_TIME=$(date +%s)

step() {
    local label="$1"
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local elapsed=$(( $(date +%s) - START_TIME ))
    local bar_filled=$(( CURRENT_STEP * 20 / TOTAL_STEPS ))
    local bar_empty=$(( 20 - bar_filled ))
    local bar="["
    for ((i=0; i<bar_filled; i++)); do bar+="█"; done
    for ((i=0; i<bar_empty; i++)); do bar+="░"; done
    bar+="]"
    printf "\n\033[1;36m%s %d/%d\033[0m  \033[1;33m%s\033[0m  \033[90m+%ds\033[0m\n" \
        "$bar" "$CURRENT_STEP" "$TOTAL_STEPS" "$label" "$elapsed"
    printf "\033[90m────────────────────────────────────────────────────────────\033[0m\n"
}

ok() {
    local label="$1"
    printf "\033[1;32m  ✔ %s\033[0m\n" "$label"
}
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(cat "$SCRIPT_DIR/VERSION" | tr -d '[:space:]')"
IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"
IMAGE="secureobs/scanner"

printf "\n\033[1;35m  SecureObs Scanner — Build & Push\033[0m\n"
printf "\033[90m  Image : %s\033[0m\n" "$IMAGE"
printf "\033[90m  Version: v%s\033[0m\n" "$VERSION"
printf "\033[90m  Platform: linux/amd64\033[0m\n\n"

# ── Step 1: Sync version constants ───────────────────────────────────────────
step "Syncing version constants across the codebase"
bash "$SCRIPT_DIR/sync-versions.sh"
ok "Version constants synced"

# ── Step 2: Docker daemon check ───────────────────────────────────────────────
step "Checking Docker daemon"
docker info > /dev/null 2>&1
ok "Docker daemon is running"

# ── Step 3: Buildx builder setup ─────────────────────────────────────────────
step "Setting up buildx builder"
if ! docker buildx inspect secureobs-builder >/dev/null 2>&1; then
    echo "  Creating new buildx builder 'secureobs-builder'..."
    docker buildx create --name secureobs-builder --use
    docker buildx inspect --bootstrap
    ok "Builder created and bootstrapped"
else
    docker buildx use secureobs-builder
    ok "Using existing builder 'secureobs-builder'"
fi

# ── Step 4: Build ────────────────────────────────────────────────────────────
step "Building image (this may take a few minutes)"
docker buildx build \
    --platform linux/amd64 \
    --tag "$IMAGE:v${MAJOR}.${MINOR}.${PATCH}" \
    --tag "$IMAGE:v${MAJOR}.${MINOR}" \
    --tag "$IMAGE:v${MAJOR}" \
    --tag "$IMAGE:latest" \
    --push \
    "$SCRIPT_DIR"

# ── Step 5: Git tag ──────────────────────────────────────────────────────────
step "Creating and pushing git tag"
GIT_TAG="integrations-v${VERSION}"
if git rev-parse "$GIT_TAG" >/dev/null 2>&1; then
    ok "Tag $GIT_TAG already exists — skipping"
else
    git tag "$GIT_TAG"
    git push origin "$GIT_TAG"
    ok "Tagged and pushed $GIT_TAG"
fi

# ── Step 6: Done ─────────────────────────────────────────────────────────────
step "Publishing complete"
ok "Docker: v${MAJOR}.${MINOR}.${PATCH} / v${MAJOR}.${MINOR} / v${MAJOR} / latest"
ok "Git tag: $GIT_TAG"

ELAPSED=$(( $(date +%s) - START_TIME ))
printf "\n\033[1;32m  Done in %ds. Image live at docker.io/%s\033[0m\n\n" "$ELAPSED" "$IMAGE"
