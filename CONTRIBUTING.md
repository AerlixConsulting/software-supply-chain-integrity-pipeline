# Contributing to the Software Supply Chain Integrity Pipeline

Thank you for your interest in contributing! This project welcomes bug reports, feature proposals, documentation improvements, and pull requests from the community.

By participating in this project you agree to abide by the code of conduct in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## Getting Started

### Prerequisites

- Python 3.10 or later
- `git`
- `pip`

### Local Setup

```bash
git clone https://github.com/AerlixConsulting/software-supply-chain-integrity-pipeline.git
cd software-supply-chain-integrity-pipeline
python3 -m venv .venv
source .venv/bin/activate
pip install ruff pytest cryptography
```

### Run Tests

```bash
pytest -v
```

### Run Linter

```bash
ruff check src/ tests/
```

---

## Branching Model

| Branch Pattern | Purpose |
|---|---|
| `main` | Stable, release-ready code |
| `feature/<name>` | New features or capabilities |
| `fix/<name>` | Bug fixes |
| `docs/<name>` | Documentation-only changes |
| `chore/<name>` | Refactoring, dependency updates, CI changes |

All changes must be submitted as pull requests against `main`. Direct pushes to `main` are not permitted.

---

## Commit Standards

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

**Types**: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `ci`

**Examples**:
```
feat(sbom): add SPDX 2.3 JSON output option
fix(audit): correct version comparison for >= operator
docs(controls): add FedRAMP High control mappings
test(verifier): add SHA-512 round-trip test
```

---

## Pull Request Requirements

Before submitting a PR, ensure:

- [ ] All tests pass (`pytest -v`)
- [ ] No ruff linting errors (`ruff check src/ tests/`)
- [ ] New functionality includes corresponding tests
- [ ] Docstrings follow the existing style (Google/numpy style with Args/Returns)
- [ ] Documentation is updated where relevant (README, docs/, architecture/)
- [ ] If adding a new CLI command, the help text is clear and examples are provided
- [ ] License headers are present on all new Python files

---

## Code Style

- **Line length**: 110 characters maximum
- **Quotes**: Double quotes for strings
- **Type hints**: Required on all public function signatures
- **Docstrings**: Required on all public functions and classes
- **Imports**: `from __future__ import annotations` at the top of all modules

Ruff enforces code style automatically. Run `ruff check --fix src/ tests/` to auto-fix most issues.

---

## Adding a Vulnerability to the Feed

The vulnerability feed in `src/dependency_audit.py` uses real CVE identifiers. When adding entries:

1. Use the canonical CVE ID from [NVD](https://nvd.nist.gov) or [OSV](https://osv.dev).
2. Include accurate `severity`, `cvss`, `affected_versions`, and `remediation` fields.
3. Add a corresponding test in `tests/test_dependency_audit.py`.

---

## Documentation Expectations

- Architecture changes should be reflected in the relevant `architecture/*.md` diagram.
- New capabilities should be mapped to NIST 800-53 controls in `controls/control-mapping.md`.
- Significant design choices should be recorded as a new `DD-xx` entry in `docs/design-decisions.md`.
- User-facing use cases should be documented in `docs/use-cases.md`.

---

## Reporting Vulnerabilities

Please **do not** open public GitHub issues for security vulnerabilities. Instead, follow the process described in [SECURITY.md](SECURITY.md).

---

## License

By contributing to this project, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
