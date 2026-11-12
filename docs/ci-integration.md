# CI/CD integration

PatchProof is a normal command-line process: the pipeline decides from the exit
code and stores the JSON report as an artifact.

## GitHub Actions

```yaml
name: security-patch-validation
on: [pull_request]

jobs:
  patchproof:
    runs-on: ubuntu-latest
    container:
      image: ubuntu:24.04
      options: --cpus 2 --memory 2g --network none
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # required: base and patched refs must exist

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install the tool (no runtime dependencies)
        run: pip install -e .

      - name: Validate the patch
        id: patchproof
        run: |
          set +e
          patchproof run -c targets/my-parser/patchproof.toml -o patchproof-out
          code=$?
          echo "exit_code=$code" >> "$GITHUB_OUTPUT"
          set -e
          exit "$code"

      - name: Upload evidence (always)
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: patchproof-report
          path: patchproof-out/
          if-no-files-found: warn
```

The validation step fails on 10, 20, 30 and 40, so branch protection blocks the
merge. The report is still uploaded because the upload step uses `if: always()`.

If the target lives in another repository, check it out into a sibling path and
point `[target].repo` at it. The refs must be fetched (`fetch-depth: 0` for the
same repo, `ref`/token for a private one).

## GitLab CI

```yaml
patchproof:
  image: ubuntu:24.04
  variables:
    GIT_DEPTH: "0"
  script:
    - apt-get update && apt-get install -y python3 gcc make git
    - python3 -m patchproof run -c targets/my-parser/patchproof.toml -o patchproof-out
  artifacts:
    when: always
    paths:
      - patchproof-out/
    expire_in: 30 days
```

## Exit-code policy

| Code | Pipeline reaction |
|---:|---|
| 0 | Pass the gate |
| 10 | Fail and request a security review |
| 20 | Fail and request a functional fix |
| 30 | Fail as a configuration/infrastructure problem, **not** as a security result |
| 40 | Fail as "evidence insufficient"; do not treat as pass |

Do not set `allow_failure` for 30 or 40. A broken or inconclusive run must not
look green.

## Artifacts to keep

- `report.json` — machine-readable verdict and evidence.
- `summary.txt` — quick developer view.
- `patch.diff` — exact change that was judged.
- `builds/*/build.log` — build failures and flags.
- `artifacts/**/stdout.txt` and `stderr.txt` — full target output; the JSON keeps
  only a preview.
- Part 4 reproducer bundles and generated regression tests.

## Resource isolation

Run target code in a disposable container:

- no secrets in the environment,
- no network if the target does not need it,
- CPU/memory limits at the container level (cgroups), not only `RLIMIT_AS`
  (ASan needs a large virtual address space),
- a read-only or disposable checkout,
- a hard wall-clock timeout at the job level.

PatchProof applies per-process limits and kills the whole process group, but
containment remains the CI runner's responsibility.

## Before enabling the gate

1. Prepare the four versions and reference tests; get instructor approval.
2. Run the pipeline locally for each version and confirm `0 / 10 / 20`.
3. Pin `base_ref` and `patched_ref` to tags or commit hashes, not moving branches.
4. Add the JSON report and reproducers to the delivery bundle.
5. Rehearse the unseen-patch scenario: apply a patch you have not seen, change
   only its ref in the config, and check that the decision still comes from
   execution evidence.
