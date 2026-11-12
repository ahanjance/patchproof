# Report schema (version 1.0)

Every run writes:

```
<patchproof-out>/<run-id>/
  report.json          structured result (this schema)
  summary.txt          developer-facing summary
  patch.diff           git diff between the resolved commits
  builds/<version>-<variant>/
    build.log
    stdout.txt
    stderr.txt
  artifacts/<version>/<variant>/<test-id>/
    stdout.txt
    stderr.txt
```

The tool's own exit code is the same value as `verdict.exit_code`. A CI job can
decide from the exit code and attach the directory as an artifact.

## Top level

```json
{
  "schema_version": "1.0",
  "tool": {"name": "patchproof", "version": "0.1.0", "python": "3.12.4", "platform": "Linux-..."},
  "run": {
    "id": "20261112T180000Z-a1b2c3",
    "started_at": "2026-11-12T18:00:00+00:00",
    "finished_at": "2026-11-12T18:00:04+00:00",
    "duration_seconds": 4.21,
    "out_dir": "/abs/patchproof-out/20261112T180000Z-a1b2c3",
    "keep_worktrees": false,
    "worktrees": {}
  },
  "target": {
    "name": "my-parser",
    "repo": "/abs/repo",
    "base_ref": "v1.2.0-vuln",
    "patched_ref": "v1.2.1-fix",
    "base_commit": "<sha>",
    "patched_commit": "<sha>",
    "changed_files": ["src/parser.c"],
    "diff_path": "/abs/.../patch.diff",
    "diff_sha256": "<sha>"
  },
  "config_path": "/abs/patchproof.toml",
  "config_sha256": "<sha>",
  "builds": [],
  "observations": [],
  "findings": [],
  "hardening": null,
  "verdict": {"exit_code": 0, "status": "PASS", "reasons": []},
  "error": null
}
```

`hardening` is reserved for Part 4 and is `null` until integrated.

## `builds[]`

```json
{
  "version": "base",
  "variant": "release",
  "ok": true,
  "command": ["make", "release"],
  "exit_code": 0,
  "signal": null,
  "timed_out": false,
  "duration_seconds": 0.83,
  "log_path": ".../build.log",
  "binary_path": ".../build/parser",
  "binary_sha256": "<sha>",
  "error": ""
}
```

| Field | Meaning |
|---|---|
| `version` | `base` or `patched` |
| `variant` | `release` or `sanitized` |
| `ok` | Binary was produced and is executable |
| `command` | Exact build argv |
| `exit_code` / `signal` / `timed_out` | Build termination |
| `log_path` | Build log with command, output and error |
| `binary_sha256` | Hash of the built executable |

## `observations[]`

One entry per `(test, version, variant)` execution.

```json
{
  "test_id": "cve-original",
  "kind": "security",
  "version": "patched",
  "variant": "sanitized",
  "outcome": "crash",
  "expectation_met": false,
  "exit_code": null,
  "signal": 6,
  "signal_name": "SIGABRT",
  "timed_out": false,
  "duration_seconds": 0.041,
  "stdout": "...",
  "stderr": "...",
  "stdout_path": ".../stdout.txt",
  "stderr_path": ".../stderr.txt",
  "argv": [".../parser-asan", "--parse", ".../crash.bin"],
  "failure_reasons": ["crashed with SIGABRT"]
}
```

| Field | Meaning |
|---|---|
| `outcome` | `pass`, `fail`, `crash`, `timeout` or `error` |
| `expectation_met` | Checked against `expect_exit`, stdout/stderr expectations and no crash/timeout |
| `signal_name` | Symbolic signal when the kernel terminated the process |
| `stdout` / `stderr` | Bounded preview (32 KiB, head+tail); full bytes are in the paths |
| `failure_reasons` | Human-readable unmet expectations |

`outcome="error"` is a tool/config failure (for example, an unreadable input or
an unstartable binary) and forces exit 30.

## `findings[]`

```json
{
  "id": "SEC-1a2b3c",
  "title": "heap-buffer-overflow in parse_header",
  "status": "incomplete",
  "kind": "security",
  "confirmed": true,
  "summary": "ASan reports a write 4 bytes past a 16-byte heap buffer",
  "evidence": {
    "observations": [
      {"test_id": "cve-original", "version": "base", "variant": "sanitized"},
      {"test_id": "cve-original", "version": "patched", "variant": "sanitized"}
    ],
    "signature": "heap-buffer-overflow@parse_header+0x42",
    "frames": ["parse_header src/parser.c:88", "main src/main.c:12"],
    "diff_hunks": [{"file": "src/parser.c", "function": "parse_header", "lines": "80-92"}]
  },
  "analyzer": "crash"
}
```

### Status values

| `status` | Meaning | Effect |
|---|---|---|
| `fixed` | Old bug reproduced on base; not observed on patched in scope | none |
| `incomplete` | Patch is bypassable / old bug still reproduces | exit 10 |
| `new` | A new confirmed security issue appeared | exit 10 |
| `functional_regression` | Valid input that passed on base fails on patched | exit 20 |
| `inconclusive` | Evidence insufficient to decide | exit 40 |

`confirmed=false` also forces exit 40. `kind` is `security` or `functional`.

### Evidence contract

The verdict engine only considers an observation "classified" when a finding
lists its exact tuple in `evidence.observations`:

```json
{"test_id": "...", "version": "base|patched", "variant": "release|sanitized"}
```

An unclassified `crash` or `timeout` observation forces exit 40. This is how the
tool enforces "a crash alone does not confirm a vulnerability".

## `verdict`

```json
{
  "exit_code": 20,
  "status": "FUNC_REGRESSION",
  "reasons": ["REG-valid-zero: functional regression on valid-zero"]
}
```

| Code | Status | Condition |
|---:|---|---|
| 0 | `PASS` | No confirmed issue; all mandatory checks complete |
| 10 | `VULN_REMAINS`, `NEW_ISSUE` or `VULN_REMAINS_OR_NEW_ISSUE` | Confirmed remaining/new security finding |
| 20 | `FUNC_REGRESSION` | Confirmed functional regression |
| 30 | `BUILD_OR_CONFIG_ERROR` | Build, config, tool or execution-setup error |
| 40 | `INCONCLUSIVE` | Missing evidence, failed analyzer, broken base reference, unclassified crash/timeout |

Priority: **40 → 20 → 10 → 30 → 0**.

## Reproducibility fields

For every run the report fixes:

- config path + SHA-256,
- base and patched commit hashes,
- diff SHA-256 and `patch.diff`,
- build commands, environment, exit codes and binary hashes,
- target argv, input test ID and artifact paths,
- tool version, Python version and platform.

Part 4 will add the reproducer bundle (input bytes, exact command, environment
and three replay outcomes) under `findings[].evidence.reproducer`.
