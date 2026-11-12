# Team plan — four-way split

Course: Data & Network Security · Project 1 · groups of four · 2.5 / 20
Release: 28 Mehr 1405 · Delivery: 18 Aban 1405

This document is the working contract between the four members. Every part has
an owner, concrete deliverables, files it may change freely, and acceptance
criteria that can be demonstrated in the defense.

## Ground rules

1. **Part 1 is frozen as the integration contract.** Changes to `model.py`,
   `config.py`, `pipeline.py` or `report.py` are announced in the group chat and
   committed separately. Other parts plug in through `analysis.Analyzer`.
2. **One owner per file.** Do not edit another member's analyzer without asking.
   Shared files are changed in small commits with a clear message.
3. **Every capability needs evidence.** A feature that cannot be reproduced by
   a test or a report entry does not earn points.
4. **No target-specific code.** New programs are added only through
   `patchproof.toml`. Unseen patches are applied to the same interface at defense.
5. **Commit early, commit often.** One logical change per commit. The history is
   part of the participation evidence.

## Target ownership

Two independent C/C++ programs are required; at least one must be a real,
non-toy project or library.

| Target | Description | Lead | Support |
|---|---|---|---|
| **A** | Real project/library with a known public CVE + public patch; source of both versions available | Member 2 | Member 4 |
| **B** | Second independent C/C++ program (different input shape: argv or file, not stdin) | Member 3 | Member 1 |

Each target needs four versions in the repo: **vulnerable base**, **correct
patch**, **incomplete patch**, **regression patch**, plus the reference test
suite. Target choice, patches, reference tests and expected outputs are
approved by the instructor at the design stage. Split the four versions between
the two target leads, then cross-review.

---

## Member 1 — Platform, CI/CD and integration (10 points + foundation)

**Owns:** CLI, configuration, git versions, build orchestration, sandboxed
runner, test matrix, verdict aggregation, JSON report, summary, CI pipeline.

**Deliverables (already implemented in this repository):**

- `patchproof run|validate|version` with config-only target onboarding.
- Two git refs → two disposable worktrees; diff and changed-file extraction.
- Release and sanitized builds, kept strictly separate.
- Per-execution timeout, CPU/address-space/file-size limits, process-group kill,
  stdout/stderr artifacts, signal and exit-code capture.
- Test matrix over `{base, patched} × {release, sanitized} × tests`.
- Exit-code aggregation with the mandated priority `40 > 20 > 10 > 30 > 0`.
- Structured JSON report and developer summary; error reports also exit 30.
- 53 stdlib tests, runnable demo, GitHub Actions workflow.
- ASan memory note: virtual address space is not limited because ASan reserves
  terabytes; release builds are limited.

**Handoff boundary — nothing outstanding for Member 1:**

Part 1 is closed. The remaining integration work belongs to the authors and the
delivery owner, not to Member 1:

- **Member 2** wires `crash` into `pipeline.execute(analyzers=[...])` and adds
  Target A's config to the delivery pipeline.
- **Member 3** wires `correlation` into the same list and adds Target B's config.
- **Member 4** owns the final delivery pipeline, the four scenarios and the
  unseen-patch rehearsal.
- Member 1 only provides advisory support on the frozen interface if asked.

**Acceptance:** `python -m unittest` green; `examples/demo/run.sh --correct`
exits 0 and `run.sh` exits 20; JSON contains versions, builds, observations,
findings, verdict and evidence; pipeline can be called from a YAML workflow.

---

## Member 2 — Dynamic analysis and crash classification (25 points)

**Owns:** sanitizer/release observation analysis, error taxonomy, detection
mechanism, termination reporting, valid/boundary/invalid test corpus for Target A.

**Deliverables:**

- `patchproof/analyzers/crash.py`: consume `AnalysisContext`, return `Finding`s.
- Parse ASan/UBSan reports and plain signals, classify at least:
  stack buffer overflow, heap buffer overflow, out-of-bounds read/write, UAF,
  double free, null dereference, division by zero, stack smashing.
- Record the **detection mechanism** separately from the error type: OS signal,
  canary / `__stack_chk_fail`, ASan, UBSan, or unclassified crash.
- Record termination: exit code, signal, stdout, stderr, timeout/resource
  exhaustion. Timeouts are reported separately; a hang is not automatically a
  vulnerability.
- Deduplicate repeated crashes by a stable signature (sanitizer type + top
  frames), not by input filename.
- Design and document the valid, boundary and invalid corpus for Target A,
  including the *different* input that defeats the incomplete patch.
- Run every crashing input on **both** versions and **corresponding** builds.
- Wire the analyzer into `pipeline.execute(analyzers=[...])` and add Target A's
  config to the delivery pipeline.

**Evidence contract:** every finding references the observations it classified:

```python
Finding(
    id="SEC-<signature>",
    title="heap-buffer-overflow in parse_header",
    status=FindingStatus.INCOMPLETE,
    evidence={"observations": [
        {"test_id": "hdr-long", "version": "base", "variant": "sanitized"},
        {"test_id": "hdr-long", "version": "patched", "variant": "sanitized"},
    ], "signature": "...", "asan": "..."},
    analyzer="crash",
)
```

**Acceptance:** ASan fixtures for each taxonomy; a crash that no analyzer covers
still forces exit 40; a confirmed remaining bug yields 10; release/sanitized
results are reported separately.

---

## Member 3 — Patch correlation and verdict evidence (25 points)

**Owns:** diff parsing, stack symbolisation, finding-to-change correlation, and
the five statuses on Target B.

**Deliverables:**

- `patchproof/analyzers/correlation.py` (+ helpers):
  - Parse `git diff` hunks: changed files, functions, line ranges.
  - Symbolise stack frames with `addr2line` / `llvm-symbolizer` against the
    corresponding build, then map frames to source files, functions and lines.
  - Correlate a finding with the patch by matching a stack frame / execution
    path to a changed file, function or line; compare base and patched
    executions. **Adjacent source text is not enough.**
  - Emit `Fixed`, `Incomplete`, `New`, `Functional regression` or
    `Inconclusive`. If the evidence is insufficient, say inconclusive — do not
    guess.
  - A newly observed crash does **not** prove the patch caused it.
- Prove that a caller change (e.g. a length check) can explain a crash in a
  callee; include this case in tests.
- Build Target B's four versions and reference tests.
- Wire the analyzer into `pipeline.execute(analyzers=[...])` and add Target B's
  config to the delivery pipeline.
- Never use a patch filename, branch name or known patch ID to decide anything.

**Acceptance:** synthetic diff/stack fixtures plus one real target; each status
is reachable and has an evidence trail in JSON; unseen patch at defense does not
change behaviour of the tool.

---

## Member 4 — Reproducibility, minimisation, hardening and delivery (15 + 5 + 5)

**Owns:** reproducer bundles, delta debugging, regression-test generation,
binary hardening, documentation, final packaging.

**Deliverables:**

- `patchproof/repro.py`: per finding, write a bundle containing the crashing
  input, exact commit hash, binary hash, build settings, relevant environment,
  and full command. Replay at least three times and flag instability.
- `patchproof/minimize.py`: ddmin-style byte/line/argv minimisation that preserves
  the **same error type at a related location**, not merely a non-zero exit
  code. Keep original and minimised inputs.
- `patchproof/regression.py`: add the minimised input to the project regression
  suite automatically; verify it fails on base and passes on patched.
- `patchproof/harden.py`: `readelf` checks for NX, PIE, RELRO (none/partial/full)
  and stack canary in release builds; compare base and patched and warn on an
  unintended protection change. PIE does not prove ASLR; a canary does not prove
  every function is protected.
- `docs/scenarios.md`: how each of the four versions is built, which input
  distinguishes it, and the expected exit code.
- Own the final delivery pipeline: run all four scenarios on both targets and
  the unseen-patch rehearsal.
- Final delivery bundle: code, configs, exact versions, tests, reproducers,
  reports, pipeline file, standalone run guide.

**Acceptance:** three clean replays; minimised input still produces the same
signature; generated regression test is picked up by the next run; hardening
report shows all four properties with raw `readelf` evidence; a deliberate
`-fno-stack-protector` change is detected.

---

## Shared work — four scenarios and unseen patches (15 points)

| Scenario | Expected | Lead | Input that distinguishes it |
|---|---:|---|---|
| Vulnerable base | — | M2 | original crashing input |
| Correct patch | 0 | M3 | original + full suite |
| Incomplete patch | 10 | M2 | a **different** input designed by the team |
| Regression patch | 20 | M4 | a valid input that used to pass |

All four members must be able to run and explain every scenario. Unseen patches
at defense use the same config/input interface and must be judged from execution
evidence.

## Integration milestones

| Milestone | Goal |
|---|---|
| M0 (week 1) | Targets + CVE/patch + reference criteria approved by instructor; Part 1 interface frozen |
| M1 (week 2) | Member 2 crash analyzer works on Target A; Member 3 diff/stack mapping works on fixtures; Member 4 reproducer on one crash |
| M2 (week 3) | Member 2/3 wire their own analyzers; Member 4 owns the delivery pipeline; four scenarios green on both targets; JSON complete |
| M3 (week 4) | Minimisation + regression generation + hardening complete; Member 4 runs the unseen-patch rehearsal; docs and individual defense rehearsal |

## Defense preparation (10 points, individual)

Each member is asked separately and may not use teammates or answer-generating
tools. Everyone must be able to:

1. Explain the overall architecture, their design decisions, and the logic of
   their own code (3 points).
2. Pick a finding or test result and explain how the evidence supports the
   tool's decision (3 points).
3. Make a limited code/config change and verify it by running a test in the
   announced time (4 points).

Minimum 5/10 and at least one point on each axis, otherwise that person's grade
is 0. Rehearse a 10-minute defense and a 10-minute live change. Suggested live
changes: flip a test expectation, disable a binary protection in the build,
change the input delivery mode, add a new target via config only.

## File ownership map

| Path | Owner |
|---|---|
| `patchproof/{config,repo,build,proc,testing,verdict,pipeline,report,cli}.py` | M1 |
| `patchproof/analyzers/crash.py`, `targets/A/`, `tests/test_crash_analyzer.py` | M2 |
| `patchproof/analyzers/correlation.py`, `targets/B/`, `tests/test_correlation.py` | M3 |
| `patchproof/{repro,minimize,regression,harden}.py`, `docs/scenarios.md`, delivery bundle | M4 |
| `README.md`, `docs/team-plan.md`, `docs/architecture.md` | M1 (review by all) |
| `.github/workflows/` | M1 |
