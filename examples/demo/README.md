# Demo

A throwaway C target that exercises the Part 1 platform end to end:

| Mode | Patched behaviour | Expected exit |
|---|---|---:|
| `--correct` | same valid behaviour | 0 |
| `--regression` (default) | rejects `n == 0`, breaking a boundary test | 20 |

```bash
bash examples/demo/run.sh --correct
bash examples/demo/run.sh
KEEP_DEMO=1 bash examples/demo/run.sh   # keep repo + report
```

Each run creates a temporary git repo with `base` and `patched` tags, builds
release and ASan/UBSan variants, runs the three tests on both versions and both
variants, and prints the JSON report path.

The demo deliberately contains no memory bug: crash classification is Part 2 and
diff correlation is Part 3. Until those analyzers are plugged in, a crashing
input correctly produces exit 40 (evidence insufficient), never a fake pass.
