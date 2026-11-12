# Contributing

## Setup

No third-party runtime dependencies. Python 3.11+ is required for `tomllib`.

```bash
git clone https://github.com/ahanjance/patchproof.git
cd patchproof
python3 -m unittest discover -s tests -v
bash examples/demo/run.sh --correct
bash examples/demo/run.sh
```

Optional editable install for the `patchproof` command:

```bash
python3 -m pip install -e .
patchproof version
```

## Before you commit

- Run the full test suite. It must stay green.
- Add a test for every non-trivial branch, parser change or analyzer signature.
- Keep the tool target-agnostic: new programs enter through TOML, never through
  `if target == "..."`.
- Do not commit `patchproof-out/`, worktrees, build outputs or generated reports.
- Update `docs/configuration.md` or `docs/report-schema.md` when a field changes.
- Keep the report schema backward-compatible: add fields, do not rename or
  remove existing ones without an announcement.

## Commit style

One logical change per commit, imperative subject:

```
feat(crash): classify ASan heap-buffer-overflow findings
fix(verdict): keep unclassified timeouts inconclusive
test(correlation): cover a caller-side length-check change
docs(config): document argv placeholders
```

Do not mix formatting, refactoring and behaviour in one commit. The history is
part of the participation evidence.

## Adding an analyzer (Parts 2 and 3)

1. Create a class with a `name` and
   `analyze(context: AnalysisContext) -> list[Finding]`.
2. Return findings whose `evidence["observations"]` reference the exact
   `(test_id, version, variant)` observations used as evidence.
3. If the evidence is insufficient, return `FindingStatus.INCONCLUSIVE` or do not
   emit a finding. Never guess.
4. Add the analyzer to the integration list in `pipeline.py`.
5. Add tests with synthetic observations and with one real crash.

The contract is documented in `patchproof/analysis.py` and
`docs/architecture.md`.

## Adding a target

1. Prepare the git repo with approved base and patched refs.
2. Add `targets/<name>/patchproof.toml` and its input files.
3. Verify `patchproof validate`, then run all four patch versions.
4. Add the target matrix to the delivery pipeline.
5. Never hard-code its name, functions or paths in the tool.

## Ownership

See `docs/team-plan.md` for the four-way split and the file ownership map. Ask
the owner before editing shared modules (`model.py`, `config.py`, `pipeline.py`,
`report.py`).

## Licensing

By contributing you agree that your changes are released under the MIT license
in `LICENSE`.
