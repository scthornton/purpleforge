"""GitHub API client for deploying advisory detection rule drafts."""

from __future__ import annotations

import logging

from github import Github, GithubException

logger = logging.getLogger(__name__)


class GitHubClient:
    """Create branches, commit files, and open PRs for detection rule drafts.

    Works against github.com and GitHub Enterprise Server (pass base_url). Branch
    and file operations are safe to re-run: an existing branch is reused and an
    existing file is updated rather than raising.
    """

    def __init__(self, token: str, repo: str, base_url: str | None = None) -> None:
        self._gh = Github(login_or_token=token, base_url=base_url) if base_url else Github(token)
        self._repo = self._gh.get_repo(repo)

    @property
    def default_branch(self) -> str:
        """The repository's default branch."""
        return str(self._repo.default_branch)

    def create_branch(self, branch_name: str, base: str | None = None) -> str:
        """Create a branch from base, reusing it if it already exists.

        base defaults to the repository's default branch. Returns the branch name.
        """
        base = base or self.default_branch
        base_ref = self._repo.get_branch(base)
        try:
            self._repo.create_git_ref(
                ref=f"refs/heads/{branch_name}",
                sha=base_ref.commit.sha,
            )
        except GithubException as e:
            if self._is_already_exists(e):
                logger.info("Branch %s already exists; reusing it", branch_name)
                return branch_name
            raise
        return branch_name

    def commit_file(self, branch: str, path: str, content: str, message: str) -> str:
        """Commit a file to the branch, updating it when the path already exists.

        Returns the commit SHA.
        """
        try:
            existing = self._repo.get_contents(path, ref=branch)
        except GithubException as e:
            if e.status != 404:
                raise
            existing = None

        if existing is not None:
            # get_contents returns a list for a directory; a file gives one object.
            target = existing[0] if isinstance(existing, list) else existing
            result = self._repo.update_file(
                path=path,
                message=message,
                content=content,
                sha=target.sha,
                branch=branch,
            )
        else:
            result = self._repo.create_file(
                path=path,
                message=message,
                content=content,
                branch=branch,
            )
        return str(result["commit"].sha)

    def create_pull_request(self, branch: str, title: str, body: str, base: str | None = None) -> str:
        """Open a PR from branch into base (default: the repository default branch).

        Returns the PR URL.
        """
        base = base or self.default_branch
        pr = self._repo.create_pull(
            title=title,
            body=body,
            head=branch,
            base=base,
        )
        return str(pr.html_url)

    @staticmethod
    def _is_already_exists(error: GithubException) -> bool:
        """True when a GithubException reports that a reference already exists."""
        if error.status == 422:
            return True
        message = ""
        if isinstance(error.data, dict):
            message = str(error.data.get("message", ""))
        return "already exists" in message.lower()
