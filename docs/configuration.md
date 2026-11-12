# Configuration reference

A target is added **only** through a `patchproof.toml` file. No target names,
function names or paths are compiled into the tool.

```bash
patchproof validate -c targets/my-project/patchproof.toml
patchproof run      -c targets/my-project/patchproof.toml -o patchproof-out
```

## Complete example

```toml
[target]
name = "my-parser"
repo = "../repo"          # or absolute
base_ref = "v1.2.0-vuln"  # tag, branch or commit
patched_ref = "v1.2.1-fix"

[build]
command = ["make", "release"]
binary = "build/parser"   # relative to the worktree
timeout_seconds = 300
env = { CFLAGS = "-O2 -g" }

[build.sanitized]
command = ["make", "asan"]
binary = "build/parser-asan"
env = { ASAN_OPTIONS = "abort_on_error=1:detect_leaks=0:symbolize=1" }

[run]
timeout_seconds = 10
memory_mb = 512
cpu_seconds = 5
file_size_mb = 32
env = { LANG = "C" }

[[tests]]
id = "valid-small"
kind = "functional"
input_mode = "stdin"
input = "inputs/small.txt"
expect_exit = 0
stdout_contains = "parsed 3 records"

[[tests]]
id = "boundary-empty"
kind = "boundary"
input_mode = "stdin"
input = "inputs/empty.txt"
expect_exit = 0
stdout_contains = "parsed 0 records"

[[tests]]
id = "invalid-header"
kind = "invalid"
input_mode = "stdin"
input = "inputs/truncated.bin"
expect_exit = 1
stderr_contains = "invalid header"

[[tests]]
id = "cve-original"
kind = "security"
input_mode = "file"
input = "inputs/crash-original.bin"
argv = ["--parse", "{input}"]

[[tests]]
id = "cve-bypass"
kind = "security"
input_mode = "argv"
input = "inputs/crash-bypass.bin"
argv = ["--parse", "{input}", "--verbose"]
```

## `[target]`

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Label used in the report |
| `repo` | yes | Path to the target git repository. Relative paths resolve against the config file's directory |
| `base_ref` | yes | Git ref of the vulnerable version; resolved to a commit hash |
| `patched_ref` | yes | Git ref of the patched version; resolved to a commit hash |

Both refs must exist as commits. Uncommitted changes in the target repo are
ignored: the tool checks out the resolved commits into disposable worktrees.

## `[build]`

| Key | Required | Default | Meaning |
|---|---|---|---|
| `command` | yes | — | Non-empty argv array; no shell interpolation |
| `binary` | yes | — | Built executable, relative to the worktree (absolute allowed) |
| `env` | no | `{}` | Extra environment for the build and, by default, for the matching test variant |
| `timeout_seconds` | no | `300` | Build timeout |
| `[build.sanitized]` | no | — | Second build used for Asan/UBSan observations |

`[build.sanitized]` accepts `command`, `binary` and `env`. If it is absent, only
the release variant is run and `variants` is `("release",)`.

Recommended sanitized flags:

```toml
command = ["cc", "-O1", "-g", "-fsanitize=address,undefined",
           "-fno-omit-frame-pointer", "-o", "app-asan", "app.c"]
```

The built binary must exist and be executable, otherwise the run exits 30.

> **ASan and memory limits.** Release runs get `RLIMIT_AS = memory_mb`.
> Sanitized runs do not, because ASan reserves a huge virtual address range and
> dies immediately under a small address-space limit. Enforce real memory with
> the container/cgroup limits used during evaluation.

## `[run]`

| Key | Default | Meaning |
|---|---|---|
| `timeout_seconds` | `10` | Default per-execution timeout; a test may override it |
| `memory_mb` | `512` | Address-space limit for release runs |
| `cpu_seconds` | `5` | `RLIMIT_CPU` for every target run |
| `file_size_mb` | `32` | `RLIMIT_FSIZE` for every target run |
| `env` | `{}` | Extra environment for every target run; overrides build-variant env keys |

`RLIMIT_CORE=0` is always applied. A timeout, CPU limit or file-size limit is
reported as a timeout/resource observation, not blindly as a vulnerability.

## `[[tests]]`

At least one test is required. IDs must be unique.

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Stable identifier used in reports and evidence |
| `kind` | yes | `functional`, `boundary`, `invalid` or `security` |
| `input_mode` | no | `stdin`, `file`, `argv` or `none`; defaults to `stdin` when `input` is present, otherwise `none` |
| `input` | for non-`none` | File containing the test input; relative to the config file |
| `argv` | no | Arguments after the binary; supports placeholders |
| `expect_exit` | functional/boundary: yes; others: no | Expected exit code |
| `stdout_contains` | no | Required substring of stdout |
| `stdout_regex` | no | Required Python regular expression in stdout |
| `stderr_contains` | no | Required substring of stderr |
| `timeout_seconds` | no | Overrides `[run].timeout_seconds` for this test |

### Input delivery

| Mode | Behaviour |
|---|---|
| `stdin` | The file bytes are piped to stdin |
| `file` | The input path is appended to argv unless `argv` already contains `{input}` |
| `argv` | Same as `file`; use when the program takes the input as an argument |
| `none` | No stdin and no appended argument; useful for argument-only tests |

Placeholders available in every `argv` entry:

- `{input}` — absolute path of the test input
- `{repo}` — absolute path of the version's worktree
- `{out}` — artifact directory for this observation

### Test kinds

| Kind | Purpose | Verdict effect |
|---|---|---|
| `functional` | Normal behaviour that must keep working | Base passes and patched fails → **20** |
| `boundary` | Edge of valid behaviour (empty, max, zero) | Same as functional |
| `invalid` | Rejected input; must fail gracefully, not crash | Crash/timeout requires an analyzer or → **40** |
| `security` | The original bug and bypass inputs | Analyzer classifies as fixed / incomplete / new |

`expect_exit` is mandatory for `functional` and `boundary` because the reference
behaviour must be explicit. For `invalid` and `security`, omitting it means the
only requirement is "no crash and no timeout"; any exit code is acceptable.

### Reference truth

The expected values must come from the program documentation or independent
reference tests, not from the patched binary and not from an LLM. A valid test
that fails on the base version makes the run `INCONCLUSIVE` (40), because no
regression can be claimed against a broken reference.

## Adding a new target — checklist

1. Put both versions in a git repo and tag them (`base_ref`, `patched_ref`).
2. Write the release build command and verify the binary path.
3. Add a sanitized build with ASan/UBSan and verify it starts.
4. Add valid, boundary, invalid and security inputs as files.
5. Declare reference exit codes and output checks.
6. Run `patchproof validate`, then `patchproof run`.
7. Confirm the expected exit code for each of the four patch versions.
8. Commit the config and test inputs next to the target.

## Common errors

| Message | Fix |
|---|---|
| `config file not found` | Pass the correct `-c` path |
| `unknown key(s)` | Remove the typo; unknown keys are rejected to catch misspellings |
| `input is not a file` | Paths are relative to the config file, not the repo |
| `expect_exit is required` | Add the reference exit code for a valid/boundary test |
| `unknown git ref` | Fetch tags or use a commit hash |
| `built binary not found` | `binary` is relative to the worktree root |
| `build exited with code …` | Read `builds/<version>-<variant>/build.log` in the run directory |
| Exit 40 with an unclassified crash | Part 2 analyzer has not linked the observation to a finding |
