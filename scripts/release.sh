#!/bin/bash
# =============================================================================
# Hybrid CP-ABE Library Release Script
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 3.0.0
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if version is provided
if [ -z "$1" ]; then
    echo -e "${RED}Error: Version argument required${NC}"
    echo "Usage: ./scripts/release.sh <version>"
    echo "Example: ./scripts/release.sh 3.0.0"
    exit 1
fi

VERSION="$1"
TAG="v${VERSION}"

# Normalize version format (remove 'v' prefix if provided)
VERSION="${VERSION#v}"
TAG="v${VERSION}"

echo -e "${BLUE}=== Hybrid CP-ABE Library Release Script ===${NC}"
echo -e "Version: ${GREEN}${VERSION}${NC}"
echo -e "Tag: ${GREEN}${TAG}${NC}"
echo ""

# Confirm with user
read -p "Proceed with release ${TAG}? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Release cancelled${NC}"
    exit 0
fi

# Step 1: Check if tag exists locally
if git tag -l | grep -q "^${TAG}$"; then
    echo -e "${YELLOW}[1/6] Deleting existing local tag ${TAG}...${NC}"
    git tag -d "${TAG}"
else
    echo -e "${GREEN}[1/6] No existing local tag to delete${NC}"
fi

# Step 2: Check if tag exists on remote
if git ls-remote --tags origin | grep -q "refs/tags/${TAG}"; then
    echo -e "${YELLOW}[2/6] Deleting existing remote tag ${TAG}...${NC}"
    git push origin ":refs/tags/${TAG}"
else
    echo -e "${GREEN}[2/6] No existing remote tag to delete${NC}"
fi

# Step 3: Update VERSION file
echo -e "${BLUE}[3/6] Updating VERSION file...${NC}"
echo "${VERSION}" > VERSION

# Step 4: Update README badge (optional - only if badge exists)
if grep -q "version-.*-blue" README.md; then
    echo -e "${BLUE}[4/6] Updating README badge...${NC}"
    # Update version badge: version-X.X.X-blue or version-X.X.X--RC-blue
    sed -i "s/version-[0-9.]*\(-\{0,2\}[A-Za-z0-9]*\)\{0,1\}-blue/version-${VERSION//-/--}-blue/g" README.md
else
    echo -e "${GREEN}[4/6] No README badge to update${NC}"
fi

# Step 5: Commit and push changes
echo -e "${BLUE}[5/6] Committing and pushing changes...${NC}"
git add VERSION README.md 2>/dev/null || true
if git diff --cached --quiet; then
    echo -e "${GREEN}No changes to commit${NC}"
else
    git commit -m "chore: bump version to ${VERSION}"
    git push origin main
fi

# Step 6: Create and push new tag
echo -e "${BLUE}[6/6] Creating and pushing tag ${TAG}...${NC}"
git tag "${TAG}"
git push origin "${TAG}"

echo ""
echo -e "${GREEN}=== Release ${TAG} completed! ===${NC}"
echo -e "GitHub Actions will now:"
echo -e "  - Build library packages for Linux and Windows"
echo -e "  - Create GitHub Release with:"
echo -e "    - libhybrid-cp-abe_linux_x86_64_v${VERSION}.zip"
echo -e "    - libhybrid-cp-abe_win_x86_64_v${VERSION}.zip"
echo ""
echo -e "Check progress at: ${BLUE}https://github.com/WanThinnn/Hybrid-CP-ABE-Library/actions${NC}"
