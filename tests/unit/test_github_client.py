"""Tests for the GitHub client with PyGithub mocked."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from github import GithubException

from purpleforge.clients.github_client import GitHubClient


def _make_repo() -> MagicMock:
    repo = MagicMock()
    repo.default_branch = "develop"
    repo.get_branch.return_value = MagicMock(commit=MagicMock(sha="base-sha"))
    repo.create_file.return_value = {"commit": MagicMock(sha="new-sha")}
    repo.update_file.return_value = {"commit": MagicMock(sha="updated-sha")}
    repo.create_pull.return_value = MagicMock(html_url="https://example/pr/1")
    return repo


def _client(repo: MagicMock) -> tuple[GitHubClient, MagicMock]:
    with patch("purpleforge.clients.github_client.Github") as gh_cls:
        gh_cls.return_value.get_repo.return_value = repo
        client = GitHubClient(token="t", repo="org/repo")
    return client, gh_cls


class TestConstruction:
    def test_base_url_passed_through(self) -> None:
        with patch("purpleforge.clients.github_client.Github") as gh_cls:
            gh_cls.return_value.get_repo.return_value = _make_repo()
            GitHubClient(token="t", repo="org/repo", base_url="https://ghe.example.com/api/v3")
        gh_cls.assert_called_once_with(login_or_token="t", base_url="https://ghe.example.com/api/v3")

    def test_no_base_url_uses_token_only(self) -> None:
        with patch("purpleforge.clients.github_client.Github") as gh_cls:
            gh_cls.return_value.get_repo.return_value = _make_repo()
            GitHubClient(token="t", repo="org/repo")
        gh_cls.assert_called_once_with("t")


class TestCreateBranch:
    def test_defaults_to_repo_default_branch(self) -> None:
        repo = _make_repo()
        client, _ = _client(repo)
        client.create_branch("feature")
        repo.get_branch.assert_called_once_with("develop")

    def test_reuses_existing_branch(self) -> None:
        repo = _make_repo()
        repo.create_git_ref.side_effect = GithubException(422, {"message": "Reference already exists"}, None)
        client, _ = _client(repo)
        assert client.create_branch("feature") == "feature"

    def test_other_errors_propagate(self) -> None:
        repo = _make_repo()
        repo.create_git_ref.side_effect = GithubException(500, {"message": "server error"}, None)
        client, _ = _client(repo)
        with pytest.raises(GithubException):
            client.create_branch("feature")


class TestCommitFile:
    def test_creates_when_missing(self) -> None:
        repo = _make_repo()
        repo.get_contents.side_effect = GithubException(404, {"message": "Not Found"}, None)
        client, _ = _client(repo)
        sha = client.commit_file("feature", "sigma/x.yaml", "body", "msg")
        assert sha == "new-sha"
        repo.create_file.assert_called_once()
        repo.update_file.assert_not_called()

    def test_updates_when_present(self) -> None:
        repo = _make_repo()
        repo.get_contents.return_value = MagicMock(sha="old-file-sha")
        client, _ = _client(repo)
        sha = client.commit_file("feature", "sigma/x.yaml", "body", "msg")
        assert sha == "updated-sha"
        repo.update_file.assert_called_once()
        assert repo.update_file.call_args.kwargs["sha"] == "old-file-sha"


class TestCreatePullRequest:
    def test_defaults_to_repo_default_branch(self) -> None:
        repo = _make_repo()
        client, _ = _client(repo)
        url = client.create_pull_request("feature", "title", "body")
        assert url == "https://example/pr/1"
        assert repo.create_pull.call_args.kwargs["base"] == "develop"

    def test_explicit_base(self) -> None:
        repo = _make_repo()
        client, _ = _client(repo)
        client.create_pull_request("feature", "title", "body", base="main")
        assert repo.create_pull.call_args.kwargs["base"] == "main"
