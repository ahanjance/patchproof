# Patch Correlation and Evidence

This component answers one question: does a confirmed execution problem line up with the code changes introduced by the patch?

## Goal

The tool must compare:

- the base version,
- the patched version,
- the git diff between them,
- the observed crash or timeout evidence.

It then decides whether the evidence indicates:

- the original issue is fixed,
- the issue remains,
- a new issue appeared,
- the patch caused a functional regression,
- or the evidence is insufficient.

## Inputs

The correlation layer consumes:

- the unified git diff,
- normalized stack frames from crash output,
- associated test observations (`test_id`, `version`, `variant`),
- the Part 2 crash classification when available.

## Core workflow

1. Parse the diff into changed files and hunks.
2. Extract user frames and drop runtime/sanitizer internals.
3. Resolve frame locations to file and line when possible.
4. Compare frame location, function name, and call-chain context with changed regions.
5. Record direct and indirect evidence.
6. Assign a status only from evidence-backed conclusions.

## Direct evidence

A direct match exists when the crash location or a nearby user frame resolves to the same file and line range, or to a function touched by the diff.

This is the strongest evidence because it links a real execution failure to a changed code region.

## Indirect evidence

Some bugs are explained by a caller-side guard or validation change that lets invalid input reach a downstream function. In those cases, the tool can correlate a changed caller function with a downstream crash, but only when the causal chain is clear.

If the link is weak or ambiguous, the result must remain inconclusive instead of being guessed.

## Evidence contract

Every finding must keep exact observation references in its evidence:

```json
"evidence": {
  "observations": [
    {"test_id": "cve-1", "version": "base", "variant": "sanitized"},
    {"test_id": "cve-1", "version": "patched", "variant": "sanitized"}
  ]
}
```

This is how the verdict engine knows which observations were used to decide a status.

## Status values

The correlation layer maps evidence to these statuses:

- `fixed`: base reproduces the bug; patched does not.
- `incomplete`: the issue still reproduces after the patch.
- `new`: a different confirmed issue appears on patched.
- `functional_regression`: valid/boundary behavior regressed.
- `inconclusive`: evidence is missing, ambiguous, or not confirmed.

## Scope boundary

This logic stays inside the patch-correlation layer. It does not rebuild binaries, classify crashes by itself, or define CI behavior. Those responsibilities remain with the other project components.

The important rule is simple: a crash alone does not prove a vulnerability. The evidence must support the code-change relationship and the status decision.
