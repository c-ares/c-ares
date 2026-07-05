Backporting fixes to release branches
=====================================

Fixes are developed against `main` and then cherry-picked ("backported") onto
the relevant release branches (e.g. `v1.34`, `v1.33`). This is automated by the
`Backport` GitHub Actions workflow (`.github/workflows/backport.yml`).

Release branches are protected and cannot be pushed to directly, so the
workflow always proposes changes as a **pull request** against the release
branch rather than pushing to it.

Usage
-----

Comment on a **merged** pull request:

```
/backport <branch> [<branch> ...] [--no-automerge]
```

Examples:

```
/backport v1.34
/backport v1.34 v1.33
/backport v1.34 --no-automerge
```

- One backport pull request is opened per target branch.
- Only users with the `maintain` or `admin` repository role may run the
  command; anyone else gets a polite refusal.
- The command only operates on pull requests that have already been merged.
- Target branches are recognized by the `vMAJOR.MINOR` naming pattern; any other
  tokens in the comment (aside from `--no-automerge`) are ignored.

What happens on a clean cherry-pick
-----------------------------------

The backport pull request is opened and **auto-merge is enabled by default**.
GitHub will merge it automatically once **all required status checks on the
target branch pass** (this is why the CI checks must be marked as *required* in
the branch protection rules — see setup below). Add `--no-automerge` to open the
pull request without enabling auto-merge.

What happens on a conflict
--------------------------

If the cherry-pick hits a merge conflict, the workflow still opens a pull
request, but:

- the conflict markers are committed, and
- the pull request is opened as a **draft**.

Draft pull requests are never auto-merged, so a maintainer must resolve the
conflict, push the resolution, and mark the pull request ready for review.

One-time repository setup
-------------------------

The workflow requires the following to be configured by a repository
administrator:

1. **GitHub App** (recommended over a personal access token so that backport
   pull requests are attributed to a bot and so that CI runs on them). Create or
   reuse a GitHub App with these repository permissions:
   - Contents: Read and write
   - Pull requests: Read and write

   Install the App on this repository, then add two repository secrets:
   - `BACKPORT_APP_ID` — the App's ID
   - `BACKPORT_APP_PRIVATE_KEY` — a generated private key for the App

2. **Allow auto-merge** must be enabled in the repository settings
   (Settings → General → Pull Requests → Allow auto-merge).

3. **Branch protection on the release branches** (e.g. a rule matching `v*`):
   - Require a pull request before merging (blocks direct pushes).
   - Require status checks to pass before merging, and mark the CI checks as
     *required*. Without required checks, auto-merge merges immediately rather
     than waiting for CI.
   - If pull request approvals are also required, auto-merge will wait for an
     approval before merging; grant the backport App an exception or adjust the
     required-approval count as appropriate for your workflow.

Notes
-----

- The list of authorized roles (`maintain`, `admin`) is enforced in the
  workflow's "Authorize" step. Adjust it there if your maintainers use a
  different repository role.
