# PatchProof

**Evidence-based validation of security patches and regression testing for C/C++ in CI/CD.**

PatchProof answers two questions by **running the program**, not by reading it:

1. Does the vulnerability reproduced on the base version still occur on the patched version, within the declared test scope?
2. Did the patch preserve the expected behaviour on valid inputs?

It builds both git versions, runs the declared valid/boundary/invalid test suite, captures crashes and sanitizer evidence, correlates findings with the patch, minimises crashing inputs, and returns the project-mandated CI exit code plus a machine-readable JSON report.

> Course project for **Data & Network Security**, Sharif University of Technology.
> Project 1: *Automatic validation of security patches and regression testing in CI/CD*.

## Repository status

| Part | Owner | Scope | Status |
|---|---|---|---|
| **1. Platform & CI/CD** | Member 1 | Config, git versions, builds, sandboxed runner, JSON, exit codes, CI entrypoint | **Complete** (this repo) |
| **2. Dynamic analysis** | Member 2 | ASan/UBSan parsing, crash taxonomy, detection mechanism, boundary/invalid corpus | **Complete** |
| **3. Patch correlation** | Member 3 | Diff hunks, stack symbolisation, Fixed/Incomplete/New/Regression/Inconclusive | **Complete** |
| **4. Reproducibility & hardening** | Member 4 | Reproducer bundles, input minimisation, regression-test generation, ELF hardening | Planned |

The full split, interfaces and deadlines are in [`docs/team-plan.md`](docs/team-plan.md).

## Quick start

Requires Python 3.11+, git, and a C/C++ toolchain.

```bash
python3 -m unittest discover -s tests -v   # 53 tests, no third-party packages

# Correct patch: expected exit 0
bash examples/demo/run.sh --correct

# Regression patch: expected exit 20
bash examples/demo/run.sh
```

Validate a target configuration without running it:

```bash
python3 -m patchproof validate -c path/to/patchproof.toml
```

Run the pipeline:

```bash
python3 -m patchproof run -c path/to/patchproof.toml
echo $?   # 0 | 10 | 20 | 30 | 40
```

## Exit codes

| Code | Status | Meaning |
|---:|---|---|
| **0** | `PASS` | Bug reproduced on base, absent on patched within scope; all mandatory checks complete |
| **10** | `VULN_REMAINS` / `NEW_ISSUE` | Confirmed remaining/new security issue |
| **20** | `FUNC_REGRESSION` | A valid test passed on base and fails on patched |
| **30** | `BUILD_OR_CONFIG_ERROR` | Target/build/config/tool/environment error |
| **40** | `INCONCLUSIVE` | Mandatory analysis incomplete or evidence insufficient |

Priority when several apply: **40 → 20 → 10 → 30 → 0**.

## Documentation

- [Team plan and four-way split](docs/team-plan.md)
- [Architecture and extension points](docs/architecture.md)
- [Configuration reference](docs/configuration.md)
- [JSON report schema](docs/report-schema.md)
- [CI/CD integration](docs/ci-integration.md)
- [Contributing](CONTRIBUTING.md)

## Layout

```
patchproof/          tool package (stdlib only)
  config.py          TOML target/test configuration
  repo.py            git refs, diff, disposable worktrees
  build.py           release + sanitized builds
  proc.py            timeout, rlimits, process-group kill, artifacts
  testing.py         test matrix and reference expectations
  verdict.py         mandated exit-code priority
  pipeline.py        end-to-end orchestration
  analysis.py        Analyzer protocol for Parts 2/3
  report.py          JSON + developer summary
  cli.py             patchproof run|validate|version
tests/               53 stdlib unittest tests
docs/                design, config, schema, team plan
examples/demo/       runnable correct/regression demo
ci/pipeline.sh       CI entrypoint (tests + both demo modes)
ci/github-actions.yml  GitHub Actions template (copy to .github/workflows/)
```

## Design rules

- **Dynamic execution is mandatory.** A crash never confirms a vulnerability by itself; an analyzer must link it to a finding, otherwise the result is `INCONCLUSIVE`.
- **Generic by configuration.** No target names, function names or paths are hard-coded.
- **Release and sanitized builds are separate.** Results are never mixed.
- **Everything is reproducible.** Commit hashes, binary hashes, commands, exit codes, signals and full logs are persisted.
- **The reference expectation is explicit.** The patched binary's output is not the oracle.
