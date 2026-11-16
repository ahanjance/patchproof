# PatchProof - Scenario Documentation

## 1. Purpose

This document describes the four required patch-validation scenarios
used to evaluate PatchProof.

Each scenario compares a vulnerable base version with a patched
version and uses execution evidence to determine whether the patch
is correct, incomplete, or introduces a functional regression.

The scenarios must be reproducible using the same target configuration,
build settings, and test inputs.

## 2. Exit Codes

PatchProof uses the following exit codes:

| Exit Code | Meaning |
|---|---|
| 0 | Patch is correct; no remaining or newly introduced issue was detected. |
| 10 | The original security issue remains or a new security issue was detected. |
| 20 | A functional regression was detected in the patched version. |
| 30 | Build, configuration, or environment error. |
| 40 | Result is inconclusive or required evidence is incomplete. |

Exit-code priority:

40 > 20 > 10 > 30 > 0

An inconclusive result takes precedence over other findings because
the available evidence is insufficient to make a reliable decision.

## 3. Scenario 1: Vulnerable Base

### Objective

Establish that the original target contains a reproducible security
vulnerability before evaluating the patch.

### Setup

1. Check out the vulnerable base commit.
2. Build the target using the configured build command.
3. Execute the security test designed to trigger the vulnerability.
4. Preserve the execution output, crash information, and relevant
   artifacts.

### Input

Use the security input specified in the target configuration.

The input must trigger the original vulnerability in the base version.

### Expected Result

The vulnerability must be reproducible.

A clean execution or an unclassified crash is not sufficient evidence
to confirm the vulnerability.

### Evidence

- Base commit hash.
- Build command and build result.
- Test input.
- Execution command.
- Exit status, signal, or sanitizer report.
- Relevant stack trace and artifacts.

## 4. Scenario 2: Correct Patch

### Objective

Verify that the patch fixes the original vulnerability without
introducing a detectable functional regression.

### Setup

1. Check out the patched commit.
2. Build the patched target using the same build configuration.
3. Execute the original security test.
4. Execute the functional regression tests.
5. Compare the observations with those from the vulnerable base.

### Input

Use the same security input that successfully triggered the
vulnerability in the base version.

Also execute valid functional inputs to verify that normal behavior
is preserved.

### Expected Result

- The original security issue is no longer reproducible.
- Functional tests pass.
- No new security issue is detected.

Expected PatchProof exit code: **0**

### Evidence

- Patched commit hash.
- Build result.
- Security test result.
- Functional test results.
- Comparison with base observations.

## 5. Scenario 3: Incomplete Patch

### Objective

Verify that PatchProof detects a patch that addresses the original
triggering input but fails to eliminate the underlying vulnerability.

### Setup

1. Check out the vulnerable base commit.
2. Check out the incomplete patched commit.
3. Build both versions using identical build settings.
4. Execute the original security input against both versions.
5. Execute an additional input that exercises the remaining
   vulnerable code path.

### Input

Two inputs are required:

- Original input: triggers the vulnerability in the base version
  but is no longer sufficient to trigger it after the incomplete patch.
- Distinguishing input: triggers the same underlying vulnerability
  through a different input or execution path.

### Expected Result

The original input may pass on the patched version, but the
distinguishing input must demonstrate that the vulnerability remains.

Expected PatchProof exit code: **10**

### Evidence

- Base and patched commit hashes.
- Original and distinguishing inputs.
- Base and patched execution observations.
- Crash or sanitizer evidence.
- Finding classification.

## 6. Scenario 4: Functional Regression

### Objective

Verify that PatchProof detects a patch that removes the original
security vulnerability but breaks previously valid functionality.

### Setup

1. Check out the vulnerable base commit.
2. Check out the regression-patched commit.
3. Build both versions using identical build settings.
4. Execute the security test to verify that the original vulnerability
   is fixed.
5. Execute a valid functional input that worked on the base version.
6. Compare the execution results.

### Input

Use a valid input that:

- Executes successfully on the vulnerable base version.
- Represents expected program behavior.
- Fails or produces incorrect behavior on the regression-patched
  version.

The input must not depend on undefined behavior or an invalid
program state.

### Expected Result

- The original security vulnerability is fixed.
- The valid functional input passes on the base version.
- The same input fails or behaves incorrectly on the patched version.
- PatchProof identifies a functional regression.

Expected PatchProof exit code: **20**

### Evidence

- Base and patched commit hashes.
- Valid functional input.
- Base execution output and exit status.
- Patched execution output and exit status.
- Regression finding and classification.

## 7. Reproducibility Requirements

For every confirmed finding:

1. Preserve the exact input that reproduces the finding.
2. Record the relevant commit hash.
3. Record the binary SHA-256 hash.
4. Preserve build settings and relevant environment variables.
5. Record the exact execution command.
6. Replay the reproducer at least three times.
7. Check whether the failure signature remains stable.
8. Preserve both original and minimized inputs when minimization
   is performed.

A finding that cannot be reproduced reliably must not be presented
as a confirmed result.

## 8. Hardening Inspection

For release binaries, inspect the following ELF security properties:

- NX
- PIE
- RELRO
- Stack Canary

Compare the base and patched binaries and report any unintended
reduction in protection.

Raw readelf output must be preserved as evidence.

Note:
- PIE does not prove that ASLR is enabled at runtime.
- Stack Canary symbol presence does not prove that every function
  is protected.

## 9. Final Scenario Matrix

| Scenario | Security Vulnerability | Functional Behavior | Expected Exit |
|---|---|---|---|
| Vulnerable Base | Reproducible | Baseline behavior | Reference |
| Correct Patch | Fixed | Preserved | 0 |
| Incomplete Patch | Still present | Preserved | 10 |
| Functional Regression | Fixed | Broken | 20 |

## 10. Evaluation Across Targets

All four scenarios must be evaluated on both target projects.

For each target:

- Use the corresponding target configuration.
- Preserve the exact base and patched references.
- Use reproducible test inputs.
- Record build and execution evidence.
- Save the final PatchProof report.

The same validation process must be used for both targets.
