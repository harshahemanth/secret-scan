# src/secret_scanner/git.py

"""Git integration for diff-mode scanning."""

import subprocess
from pathlib import Path


class GitError(Exception):
    """Raised when a git operation fails."""


def get_repo_root(path: Path) -> Path:
    """Get the root directory of the git repository containing *path*.

    Raises GitError if *path* is not inside a git repo or git is unavailable.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path),
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise GitError("git is not installed or not on PATH")

    if result.returncode != 0:
        raise GitError(
            f"Not a git repository: {path}\n{result.stderr.strip()}"
        )
    return Path(result.stdout.strip())


def get_changed_files(ref: str, repo_root: Path) -> list:
    """Return absolute paths of files changed since *ref*.

    Uses ``git diff --name-only --diff-filter=ACMR`` to list
    added, copied, modified, and renamed files.

    Raises GitError if git is unavailable or the ref is invalid.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", ref],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise GitError("git is not installed or not on PATH")

    if result.returncode != 0:
        raise GitError(
            f"git diff failed for ref '{ref}': {result.stderr.strip()}"
        )

    files = []
    for line in result.stdout.strip().splitlines():
        if line:
            files.append(str((repo_root / line).resolve()))
    return files
