"""GitHub API client for deploying advisory detection rule drafts."""

from __future__ import annotations

import logging

from github import Github

logger = logging.getLogger(__name__)


class GitHubClient:
    """Create branches, commit files, and open PRs for detection rule drafts."""

    def __init__(self, token: str, repo: str) -> None:
        self._gh = Github(token)
        self._repo = self._gh.get_repo(repo)

    def create_branch(self, branch_name: str, base: str = "main") -> str:
        """Create a branch from base. Returns branch name."""
        base_ref = self._repo.get_branch(base)
        self._repo.create_git_ref(
            ref=f"refs/heads/{branch_name}",
            sha=base_ref.commit.sha,
        )
        return branch_name

    def commit_file(self, branch: str, path: str, content: str, message: str) -> str:
        """Commit a single file to the branch. Returns commit SHA."""
        result = self._repo.create_file(
            path=path,
            message=message,
            content=content,
            branch=branch,
        )
        return result["commit"].sha

    def create_pull_request(self, branch: str, title: str, body: str) -> str:
        """Create PR from branch to main. Returns PR URL."""
        pr = self._repo.create_pull(
            title=title,
            body=body,
            head=branch,
            base="main",
        )
        return pr.html_url
