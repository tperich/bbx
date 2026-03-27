# Branch Protection Recommendations

Use these settings on your default branch (typically `main`) to keep quality high and accidental breakage low.

## Recommended rules

1. **Require a pull request before merging**
   - Require approvals: **1** (or more)
   - Dismiss stale approvals when new commits are pushed

2. **Require status checks to pass before merging**
   - Required checks:
     - `test (3.10)`
     - `test (3.11)`
     - `test (3.12)`

3. **Require branches to be up to date before merging**
   - Prevents merging stale branches that bypass latest CI results

4. **Require conversation resolution before merging**

5. **Restrict force pushes and deletion**
   - Disable force pushes on protected branches
   - Disable branch deletion

6. **(Optional) Require signed commits**

## Why this matters

- CI failures can’t be merged accidentally.
- PR review is always part of the flow.
- Release tags are cut from tested code.

## Setup path

GitHub → Repository → **Settings** → **Branches** → **Add branch protection rule**
