#!/usr/bin/env bash
set -euo pipefail

# Package source, fetch dependency archives, and run rpmbuild.
# Usage: rpm/build_rpm.sh [SOURCES_DIR]
# - SOURCES_DIR defaults to ~/rpmbuild/SOURCES

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
SPEC_FILE="$ROOT_DIR/rpm/TSB-agent.spec"

if [[ ! -f "$SPEC_FILE" ]]; then
  echo "ERROR: Spec file not found: $SPEC_FILE" >&2
  exit 1
fi

# Extract Name and Version from spec
PKG_NAME=$(awk -F: '/^Name:/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' "$SPEC_FILE")
PKG_VERSION=$(awk -F: '/^Version:/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' "$SPEC_FILE")

if [[ -z "${PKG_NAME:-}" || -z "${PKG_VERSION:-}" ]]; then
  echo "ERROR: Failed to parse Name/Version from $SPEC_FILE" >&2
  exit 1
fi

# Where to put Source0..N
DEST_DIR=${1:-"$HOME/rpmbuild/SOURCES"}
mkdir -p "$DEST_DIR"

SRC_TARBALL="$DEST_DIR/${PKG_NAME}-${PKG_VERSION}.tar.gz"

echo "==> Packaging source into: $SRC_TARBALL"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
STAGE="$TMPDIR/${PKG_NAME}-${PKG_VERSION}"
mkdir -p "$STAGE"
rsync -a \
  --exclude '.git' \
  --exclude '.idea' \
  --exclude 'build' \
  --exclude '*.o' \
  --exclude '*.a' \
  --exclude '*.so' \
  --exclude '*.so.*' \
  --exclude '*.swp' \
  --exclude '*~' \
  "$ROOT_DIR"/ "$STAGE"/
tar -C "$TMPDIR" -czf "$SRC_TARBALL" "${PKG_NAME}-${PKG_VERSION}"
rm -rf "$TMPDIR"
trap - EXIT

# Only googletest is fetched; other deps (openssl/spdlog/libboundscheck/
# rapidjson) come from the system yum packages (see spec BuildRequires).
# gtest is cloned from gitcode (no archive download available), then packed.
GTEST_GIT_URL="https://gitcode.com/GitHub_Trending/go/googletest"
GTEST_TAG="v1.15.2"
GTEST_OUT="$DEST_DIR/googletest-v1.15.2.tar.gz"

if [[ -f "$GTEST_OUT" ]]; then
  echo "[skip] $GTEST_OUT already exists"
else
  echo "==> Cloning googletest from gitcode (tag: $GTEST_TAG)"
  GIT_TMP=$(mktemp -d)
  git clone --depth 1 --branch "$GTEST_TAG" "$GTEST_GIT_URL" "$GIT_TMP/googletest"
  tar -C "$GIT_TMP" --exclude='.git' -czf "$GTEST_OUT" googletest
  rm -rf "$GIT_TMP"
fi

echo "==> Generating checksums"
MANIFEST="$DEST_DIR/${PKG_NAME}-${PKG_VERSION}-sources.SHA256"
{
  sha256sum "$SRC_TARBALL" || true
  sha256sum "$GTEST_OUT" || true
} > "$MANIFEST"

echo "==> Preparing rpmbuild tree"
RPMBUILD_ROOT="$HOME/rpmbuild"
mkdir -p "$RPMBUILD_ROOT"/{SPECS,SRPMS,RPMS,BUILD,BUILDROOT}

cp -f "$SPEC_FILE" "$RPMBUILD_ROOT/SPECS/"

echo "==> Running rpmbuild"
rpmbuild -ba "$SPEC_FILE" \
  --define "_sourcedir $DEST_DIR" \
  --define "_specdir $ROOT_DIR/rpm" \
  --define "_srcrpmdir $RPMBUILD_ROOT/SRPMS" \
  --define "_rpmdir $RPMBUILD_ROOT/RPMS" \
  --define "_builddir $RPMBUILD_ROOT/BUILD" \
  --define "_buildrootdir $RPMBUILD_ROOT/BUILDROOT"

cat <<EOF

All done.
  - Source0: $SRC_TARBALL
  - Extra sources:
      $GTEST_OUT
  - Checksums: $MANIFEST
  - RPMs in:  $RPMBUILD_ROOT/RPMS
  - SRPM in:  $RPMBUILD_ROOT/SRPMS

EOF
