# Agents

## Git

- Always stage and commit in a single command: `git add file1 file2 && git commit -m "message"`
- Run git commands from the working directory directly — no `cd` or `-C` flags

## Testing

- Run tests with: `uv run pytest tests/ -v`
- Lint + format: `uv run --all-extras ruff check restricted_exec/ tests/` and `ruff format --check restricted_exec/ tests/`

## Opening PRs & versioning

`main` is protected: PRs only, and checks (`lint`, `test`) must pass to merge.
The version is a static string in `pyproject.toml` + `uv.lock` and is **not**
bumped automatically on merge — it must be bumped deliberately, or no release is
cut. Publishing to PyPI is automatic once a `develop` → `main` PR merges.

**Follow the `create-merge-pr` skill** (`.agents/skills/create-merge-pr/`) for the
full PR workflow, including when and how to bump the version.
