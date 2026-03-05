# tests/test_git.py

import subprocess
import pytest
from pathlib import Path

from secret_scanner.git import get_repo_root, get_changed_files, GitError


# ── Unit tests (monkeypatched) ──────────────────────────────────────


class TestGetRepoRoot:
    def test_returns_path_on_success(self, monkeypatch):
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="/home/user/repo\n", stderr=""
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)
        result = get_repo_root(Path("/home/user/repo/subdir"))
        assert result == Path("/home/user/repo")

    def test_raises_on_not_a_repo(self, monkeypatch):
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=128,
            stdout="", stderr="fatal: not a git repository"
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)
        with pytest.raises(GitError, match="Not a git repository"):
            get_repo_root(Path("/tmp/notarepo"))

    def test_raises_on_git_not_found(self, monkeypatch):
        def raise_fnf(*a, **kw):
            raise FileNotFoundError("git not found")
        monkeypatch.setattr(subprocess, "run", raise_fnf)
        with pytest.raises(GitError, match="not installed"):
            get_repo_root(Path("/tmp"))


class TestGetChangedFiles:
    def test_returns_absolute_paths(self, monkeypatch):
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="file1.py\ndir/file2.py\n", stderr=""
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)
        repo_root = Path("/home/user/repo")
        files = get_changed_files("main", repo_root)
        assert len(files) == 2
        assert all(f.startswith("/") for f in files)

    def test_raises_on_bad_ref(self, monkeypatch):
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=128,
            stdout="", stderr="fatal: bad revision 'nonexistent'"
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)
        with pytest.raises(GitError, match="git diff failed"):
            get_changed_files("nonexistent", Path("/tmp"))

    def test_empty_diff(self, monkeypatch):
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)
        files = get_changed_files("main", Path("/tmp"))
        assert files == []

    def test_raises_on_git_not_found(self, monkeypatch):
        def raise_fnf(*a, **kw):
            raise FileNotFoundError("git not found")
        monkeypatch.setattr(subprocess, "run", raise_fnf)
        with pytest.raises(GitError, match="not installed"):
            get_changed_files("main", Path("/tmp"))


# ── Integration tests (real git repo) ──────────────────────────────


class TestGitIntegration:
    def _init_repo(self, tmp_path):
        """Create a minimal git repo with an initial commit."""
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=str(tmp_path), capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=str(tmp_path), capture_output=True,
        )
        (tmp_path / "initial.txt").write_text("init")
        subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=str(tmp_path), capture_output=True,
        )

    def test_get_repo_root_real(self, tmp_path):
        self._init_repo(tmp_path)
        root = get_repo_root(tmp_path)
        assert root.exists()

    def test_changed_files_real(self, tmp_path):
        self._init_repo(tmp_path)
        # Add a new file after the initial commit
        (tmp_path / "new_secret.py").write_text("password=hunter2")
        subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
        files = get_changed_files("HEAD", tmp_path)
        assert any("new_secret.py" in f for f in files)

    def test_not_a_repo_raises(self, tmp_path):
        with pytest.raises(GitError):
            get_repo_root(tmp_path)
