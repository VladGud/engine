#!/usr/bin/env bash
set -euo pipefail

TARGET_REPO="github.com/gost-engine/engine"
REMOTE_BRANCH="master"
IGNORED_DIR=".github"

die() { echo "ERROR: $*" >&2; exit 1; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "Not inside a git repository."

# Require clean working tree
if ! git diff --quiet || ! git diff --cached --quiet; then
  die "Working tree has uncommitted changes. Commit/stash them first."
fi

# Find remote pointing to target repo
remote_name="$(
  git remote -v |
    awk -v target="$TARGET_REPO" '
      $2 ~ target && $3 == "(fetch)" { print $1 }
    ' |
    head -n1
)"
[[ -n "${remote_name}" ]] || die "No remote fetch URL matched '${TARGET_REPO}'"

echo "Using remote: ${remote_name}"

# Save current HEAD
old_head="$(git rev-parse --verify HEAD)"
echo "Saved current HEAD: ${old_head}"

# Fetch remote master
echo "Fetching ${REMOTE_BRANCH} from ${remote_name}..."
git fetch "${remote_name}" "${REMOTE_BRANCH}"

remote_ref="refs/remotes/${remote_name}/${REMOTE_BRANCH}"
echo "Checking out ${remote_ref} (detached HEAD)..."
git checkout "${remote_ref}"

# Merge saved HEAD
echo "Merging saved HEAD (${old_head})..."
git merge --no-ff "${old_head}"

# ---- IMPORTANT PART ----
# Restore ignored directory from remote master (first parent)
echo "Restoring ${IGNORED_DIR} from pre-merge state (HEAD^1)..."
git restore --source=HEAD^1 --staged --worktree "${IGNORED_DIR}"

# Commit the restoration
git commit --amend
# ------------------------

echo "Done."
echo "You are in detached HEAD at: $(git rev-parse --verify HEAD)"
echo "To keep the result:"
echo "  git switch -c merge-${remote_name}-${REMOTE_BRANCH}-with-$(echo "${old_head}" | cut -c1-7)"

