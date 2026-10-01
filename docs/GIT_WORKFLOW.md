# Git Workflow

## Branches

- `main` — protected stable branch.
- `develop` — integration branch for Week 1 development.
- `feature/<name>-<task>` — personal feature branches.

## Development Workflow

1. Start from the latest `develop`.
2. Create a feature branch.
3. Make and test your changes.
4. Commit your changes.
5. Push your feature branch to GitHub.
6. Open a Pull Request into `develop`.
7. Wait for review and approval.
8. Merge only after approval.

## Branch Naming

Use:

```text
feature/<name>-<task>
```

Example:

```text
feature/tsegazeab-repo-skeleton
```

## Pull Request Naming

Week 1 PRs should use:

```text
[W1 <Day>] P<n>: <summary>
```

Example:

```text
[W1 Mon] P1: Add repo skeleton, workflow docs and branch protection
```

## Important Rules

- Do not push directly to `main`.
- Do not push directly to `develop`.
- Do not force-push shared branches.
- Keep commits focused on your assigned task.
- PRs must be reviewed before merging.
