# Architecture

## What the tool must prove

The grader will not accept a static scan or a report aggregator. For a patch,
PatchProof must produce concrete evidence that:

1. the old bug can be reproduced on the base version,
2. the patched version no longer exhibits it **within the declared test scope**,
3. valid behaviour still holds on the patched version,
4. every conclusion is tied to the code changes and can be replayed.

A crash that no analyzer classifies is therefore not a vulnerability finding; it
is `INCONCLUSIVE` (exit 40). Silence in the test suite is not proof of absence.

## Pipeline

```
patchproof.toml
      |
      v
 load + validate config  (config.py)
      |
      v
 resolve base/patched refs, extract `git diff`  (repo.py)
      |
      v
 create disposable worktrees: base, patched  (repo.py)
      |
      v
 build {base,patched} x {release,sanitized}  (build.py)
      |
      v
 run tests x {base,patched} x {release,sanitized}  (testing.py + proc.py)
      |
      +--> observations: exit code, signal, timeout, stdout/stderr, artifacts
      |
      v
 core findings (functional regressions) + analyzers (Parts 2/3)  (pipeline.py)
      |
      v
 verdict: 40 > 20 > 10 > 30 > 0  (verdict.py)
      |
      v
 report.json + summary.txt + patch.diff + artifacts  (report.py)
```

## Modules

| Module | Responsibility | Must not do |
|---|---|---|
| `config.py` | Parse/validate TOML; resolve test inputs and repo path | Run git or target code |
| `repo.py` | Resolve refs, extract diff, add/remove worktrees | Interpret findings |
| `build.py` | Run the declared build commands, resolve and hash binaries | Run tests |
| `proc.py` | Execute one command with timeout/rlimits, capture signal and output | Decide pass/fail |
| `testing.py` | Build argv/stdin per input mode, compare against reference expectation | Classify memory errors |
| `verdict.py` | Turn confirmed findings + observations into one exit code | Invent evidence |
| `pipeline.py` | Orchestrate the run and invoke analyzers | Target-specific logic |
| `analysis.py` | Analyzer protocol, evidence contract | — |
| `report.py` | Serialize report, render summary | Analysis |
| `cli.py` | Argument parsing, error reports, process exit | — |

## Evidence model

Every execution becomes a `TestObservation`:

```json
{
  "test_id": "hdr-long",
  "kind": "security",
  "version": "patched",
  "variant": "sanitized",
  "outcome": "crash",
  "exit_code": null,
  "signal": 6,
  "signal_name": "SIGABRT",
  "timed_out": false,
  "duration_seconds": 0.041,
  "stdout": "...",
  "stderr": "...",
  "stdout_path": ".../stdout.txt",
  "stderr_path": ".../stderr.txt",
  "argv": [".../app-asan"],
  "failure_reasons": ["crashed with SIGABRT"]
}
```

An analyzer returns a `Finding` and **must** reference the observations it
classified:

```python
Finding(
    id="SEC-<stable-signature>",
    title="heap-buffer-overflow in parse_header",
    status=FindingStatus.INCOMPLETE,
    evidence={"observations": [
        {"test_id": "hdr-long", "version": "base", "variant": "sanitized"},
        {"test_id": "hdr-long", "version": "patched", "variant": "sanitized"},
    ], "signature": "...", "frames": [...]},
    analyzer="crash",
)
```

The verdict engine treats an observation as classified only when a finding
references its `(test_id, version, variant)` tuple. Unreferenced crash/timeout
observations force exit 40.

## Analyzer contract

```python
class Analyzer(Protocol):
    name: str

    def analyze(self, context: AnalysisContext) -> list[Finding]: ...
```

`AnalysisContext` provides the config, both worktrees, the diff, all
observations and the run output directory. An analyzer exception is caught,
recorded as an `INCONCLUSIVE` finding, and forces exit 40; it cannot fake a pass.

Part 2 (crash taxonomy) and Part 3 (diff correlation) implement this protocol.
Part 4 adds reproducer/minimisation/hardening modules that consume the same
observations and findings.

## Exit-code decision

`verdict.decide` is intentionally small and deterministic:

1. No builds or failed build → **30**.
2. Target execution error → **30**.
3. Any analyzer incomplete/failed, any unconfirmed/inconclusive finding, a base
   valid-input reference failure, or an unclassified crash/timeout → **40**.
4. Confirmed functional regression → **20**.
5. Confirmed incomplete/new security finding → **10**.
6. Otherwise → **0**.

This is the mandated priority `40 > 20 > 10 > 30 > 0`. Build errors are handled
before the chain because the run produced no trustworthy evidence.

## Sandbox and resource limits

- Each target execution runs in its own process group with `start_new_session`.
- On timeout the whole group receives `SIGKILL`, so children cannot survive.
- `RLIMIT_CORE=0`, `RLIMIT_CPU`, `RLIMIT_FSIZE` are always applied.
- `RLIMIT_AS` is applied to release builds. It is **not** applied to sanitized
  builds: ASan reserves terabytes of virtual address space and would abort at
  startup. Real memory containment for sanitized runs belongs in the container
  (cgroup) layer used for the final evaluation.
- Full stdout/stderr are written to artifacts; the JSON keeps a bounded preview.

## Determinism and scope

- Versions are pinned by commit hash, not by mutable ref names.
- The diff is computed between the resolved commits.
- Binary hashes, build commands, environment, argv, signal and exit code are
  persisted.
- The patched binary's output is never the reference oracle; expectations are
  declared in the config and must be approved before evaluation.
- The test scope is exactly the declared suite. Absence of a crash outside that
  scope is not proof of absence.

## Known limits of Part 1

- No crash classification or diff correlation yet; those are Parts 2 and 3.
- No reproducer bundle, minimiser, generated regression test or hardening report
  yet; those are Part 4.
- Serial execution only. Parallelism can be added later without changing the
  report schema.
- `preexec_fn` is used for rlimits; safe here because the CLI is single-threaded.
