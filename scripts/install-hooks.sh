#!/usr/bin/env bash
#
# Install Key Silk git hooks into .git/hooks.
# Run once after cloning: ./scripts/install-hooks.sh
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
src="$repo_root/scripts/hooks"
dest="$repo_root/.git/hooks"

mkdir -p "$dest"
for hook in "$src"/*; do
  name=$(basename "$hook")
  cp "$hook" "$dest/$name"
  chmod +x "$dest/$name"
  echo "✓ installed $name hook"
done

echo ""
echo "Done. For full secret scanning, also install gitleaks:"
echo "  brew install gitleaks   # macOS"
echo "  (the hook works without it, using a built-in pattern guard)"
