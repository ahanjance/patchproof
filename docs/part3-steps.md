# Part 3 implementation plan: patch correlation and status classification

This document is the concrete implementation plan for Part 3 only. It is intentionally scoped to the patch-correlation analyzer and does not modify the platform contract owned by Part 1 or the crash-classification logic owned by Part 2.

## Scope boundary

Part 3 owns the logic that answers: "How does a confirmed execution result relate to the patch changes, and what status should the tool assign?"

This includes:
- parsing and structuring the git diff
- mapping observed crash/timeout stack frames to source files, functions, and lines
- correlating a finding to the changed code regions using execution evidence
- classifying the result as Fixed, Incomplete, New, Functional Regression, or Inconclusive
- emitting findings with evidence references that satisfy the analyzer contract

This does not include:
- building binaries or executing tests (Part 1)
- crash detection or sanitizer taxonomy (Part 2)
- reproducer bundles, minimisation, or hardening inspection (Part 4)

## Step 1 — Define the Part 3 analyzer contract and evidence requirements

### Needed
- Review the analyzer protocol in `patchproof/analysis.py`.
- Review the reporting schema in `docs/report-schema.md`.
- Review the architecture rules in `docs/architecture.md`.
- Confirm that Part 3 will produce `Finding` objects whose `evidence["observations"]` reference the exact `(test_id, version, variant)` tuples used in the reasoning.

### Implementation requirements
- Create a `CorrelationAnalyzer` class with a `name` attribute and `analyze(context)` method.
- Return `Finding` objects only for evidence-backed conclusions.
- Use the project status enum values: `fixed`, `incomplete`, `new`, `functional_regression`, `inconclusive`.
- Do not emit guessed findings when evidence is weak.
- Keep this logic isolated to Part 3 and avoid touching Part 1 or Part 2 files.

### Testing
- Unit tests for the extraction of evidence references from observations.
- Unit test that a finding without a valid observation tuple is rejected or produces an inconclusive result.
- Test that an analyzer exception is treated as inconclusive by the pipeline.

### Dependency on other parts
- Part 1: the `AnalysisContext` and observation model already exist and are implemented.
- Part 2: the crash analyzer already produces crash findings and observations that Part 3 may consume as evidence in the same pipeline run.
- Status: requirements are implemented in the current repo for the protocol, and this step is in scope for Part 3.

---

## Step 2 — Parse the git diff into structured change facts

### Needed
- `context.diff` from `AnalysisContext`.
- A parser for unified diff output.
- A data structure for changed files, hunks, and line ranges.

### Implementation requirements
- Parse the raw git diff into a list of changed files.
- For each file, parse hunks and extract:
  - old start/end lines
  - new start/end lines
  - added and removed code fragments
  - optional function names or nearby context lines
- Represent this in a minimal internal model, for example:
  - `DiffFile`
  - `DiffHunk`
  - `ChangedRegion`
- Do not modify Part 1 git repo logic; this is only a parser for diff evidence.
- Do not hard-code a target name or file path.

### Testing
- Unit tests for a simple one-file diff with a change in a function body.
- Unit tests for a multi-file diff.
- Unit tests for a hunk with additions and removals.
- Unit tests that ensure changed lines are accurately mapped to ranges.

### Dependency on other parts
- Part 1: `repo.py` already produces the diff and changed files in the pipeline. This step consumes those values, but does not modify them.
- Status: not fully implemented yet in the repo; this is one of the key Part 3 tasks.

---

## Step 3 — Extract user frames from crash reports and normalize them

### Needed
- The raw observation stderr files or captured stderr strings.
- The crash/timed-out observation data from Part 1 and Part 2.
- A minimal stack parser that can isolate frames relevant to the target program.

### Implementation requirements
- For each relevant observation, parse stack traces or sanitizer output.
- Extract the user frames and drop runtime/sanitizer frames such as ASan/UBSan/libc internals.
- Normalize each frame into a lightweight structure:
  - function name
  - file
  - line (if available)
  - raw symbol string
- Keep this logic limited to analysis of execution evidence and diff correlation.
- This must not modify the test runner or crash taxonomy logic.

### Testing
- Unit tests with a synthetic ASan stack trace.
- Unit tests with a UBSan stack trace.
- Unit tests with a canary or glibc abort stack.
- Unit tests that ensure runtime frames are excluded and only user frames are kept.

### Dependency on other parts
- Part 2: the crash analyzer already identifies the relevant crash class and uses similar stack parsing; Part 3 can consume the same observation artifacts but must not alter Part 2 behavior.
- Status: not implemented yet as a dedicated Part 3 module; this step is in scope for Part 3.

---

## Step 4 — Symbolize stack frames to source locations

### Needed
- The binary paths produced during build.
- The stack frames extracted in Step 3.
- Access to `addr2line` and/or `llvm-symbolizer` on the build machine.

### Implementation requirements
- For each frame that has an address or symbol, symbolize it against the relevant binary.
- Convert the runtime frame to source-level file, function, and line number when possible.
- If symbolization fails, fall back to the symbol name and mark the location as partial evidence instead of guessing a file or line.
- Keep the symbolizer invocation generic and only operate on the observed binary, not on a target-specific path.
- Maintain a clear separation between Part 3 analysis and the build system.

### Testing
- Unit tests using a simple compiled dummy C test binary with debug symbols.
- Unit tests for a frame that cannot be symbolized.
- Unit tests for a mixed case where some frames resolve and others do not.
- Test that a missing symbolizer is handled gracefully without causing a crash in the pipeline.

### Dependency on other parts
- Part 1: build outputs provide the actual binary paths.
- Status: not implemented yet; this is a required Part 3 step.

---

## Step 5 — Build the direct correlation engine for same-file/same-function matches

### Needed
- Changed-region data from Step 2
- Symbolized frame data from Step 4
- Base and patched observations that correspond to the same test ID

### Implementation requirements
- For each relevant observation pair (base and patched), compare:
  - same test ID
  - same input or same security test
  - same crash signature or same top frame pattern
  - same or related source locations
- Check whether the crash location or stack path intersects a changed region in the diff.
- If the top frame or a nearby frame resolves to a changed file/function/line, record this as a direct match.
- This is the simplest meaningful correlation case and should be implemented first before chasing indirect caller/callee relationships.

### Testing
- Unit tests with:
  - changed function and crash in same function
  - changed file but crash in another function
  - file changed but no direct stack match
- Assertions that a direct match produces a reasoned evidence trail and not just a file proximity guess.

### Dependency on other parts
- Part 2: crash classification gives a stable signature to compare across base and patched versions.
- Status: not implemented yet; this is a core Part 3 capability.

---

## Step 6 — Add indirect correlation for caller/callee effects

### Needed
- The direct correlation result from Step 5
- The call chain from symbolized frames
- The changed regions and function names

### Implementation requirements
- Handle cases where the modified logic is in a caller function, but the actual crash occurs in a callee after a bad value is propagated.
- Check whether a changed validation or length-check in a caller can explain the downstream failing function.
- Attach the evidence chain to the finding in a specific, auditable way.
- If the causal path is not clear, do not claim a strong link; mark as inconclusive instead.
- Keep this logic strictly within Part 3 and avoid affecting crash detection or code builds.

### Testing
- Unit tests built around a synthetic call graph:
  - caller validates length and patch modifies it
  - callee later dereferences a bad pointer or reads out of bounds
- Test that the tool recognizes the chain but only when the evidence is valid.
- Test that an ambiguous chain remains inconclusive.

### Dependency on other parts
- Part 2: crash observations and stack traces are required for the logic.
- Status: not implemented yet; this logic is explicitly required by the project overview and the team plan.

---

## Step 7 — Implement the status classifier: Fixed, Incomplete, New, Functional Regression, Inconclusive

### Needed
- The correlation results from Steps 5 and 6
- The observation records for base and patched executions
- The reference expectations for valid and boundary tests
- The crash classifications from Part 2

### Implementation requirements
- Map the evidence into one of the five statuses:
  - `fixed`: base reproduced, patched did not, and the evidence supports the patch relationship
  - `incomplete`: same issue or equivalent bug reproduced on patched
  - `new`: new confirmed issue appears on patched that was not seen on base
  - `functional_regression`: a valid/boundary test passed on base and failed on patched
  - `inconclusive`: insufficient evidence, ambiguous correlation, or unstable reproduction
- Do not classify based on patch filename, branch name, or known patch IDs.
- This is the central Part 3 decision-making logic.

### Testing
- Unit tests covering all five statuses.
- Realistic end-to-end tests with synthetic observation sets.
- Tests for mixed results: regression plus security issue, inconclusive overshadowing regression, etc.

### Dependency on other parts
- Part 1: valid test comparison model is already present in the pipeline.
- Part 2: crash classification and security findings are required to decide some statuses.
- Status: core logic is not yet implemented; this is the main final Part 3 deliverable.

---

## Step 8 — Serialize findings with diff evidence and observation references

### Needed
- The final status decisions from Step 7
- The full set of observations and changed regions

### Implementation requirements
- Emit `Finding` objects that include:
  - `id`
  - `title`
  - `status`
  - `kind`
  - `confirmed`
  - `summary`
  - `evidence` dictionary containing the exact references to the observations used
  - optional correlation metadata: frames, diff hunks, file/function/line mapping
- Ensure every observation used in the evidence is referenced by exact `(test_id, version, variant)` tuples.
- Keep this serialized output compatible with the result schema and the verdict engine.

### Testing
- Unit test that `finding.evidence["observations"]` matches the actual observation keys used.
- Unit test that a finding with missing observation references is treated as inconclusive by verdict logic.
- Unit test that multiple findings are serialized without loss of correlation metadata.

### Dependency on other parts
- Part 1: verdict engine already expects this output schema.
- Status: not implemented yet as a dedicated Part 3 feature.

---

## Step 9 — Integrate the CorrelationAnalyzer into the execution pipeline

### Needed
- The analyzer class created in Step 1
- All previous step outputs
- The pipeline entrypoints in `patchproof/pipeline.py`

### Implementation requirements
- Add the `CorrelationAnalyzer` to the `analyzers` list in the pipeline or the CLI entry point.
- Ensure the pipeline continues to collect observations, then passes the `AnalysisContext` to the analyzer.
- Ensure any Part 3 exception becomes an inconclusive finding rather than a silent pass.
- Keep the integration limited to the pipeline but do not modify Part 1 core execution semantics.

### Testing
- Unit test that the pipeline accepts the new analyzer and returns findings.
- Unit test that an analyzer failure forces an inconclusive result.
- Integration test that a patch correlation result can coexist with other findings and still produce the right final verdict.

### Dependency on other parts
- Part 1: pipeline and execution flow already exist.
- Status: not implemented yet; this is the final integration point for Part 3.

---

## Step 10 — End-to-end validation with synthetic and real-target fixtures

### Needed
- All prior steps
- One or more synthetic diff-and-stack fixtures
- One real target where a valid bug is fixed and another where a regression occurs

### Implementation requirements
- Run the analyzer against synthetic fixtures that exercise all five statuses.
- Confirm that the evidence links are correct and the final status matches the expected outcome.
- Run at least one real target scenario showing a legitimate bug correlation and a valid functional regression scenario.
- Keep the outputs deterministic and reviewable.

### Testing
- End-to-end test suite in `tests/` using synthetic data.
- Real-target tests with the project’s target config pattern.
- Assertions on final exit-code behavior through the verdict engine.
- Validate that a patch with insufficient evidence remains inconclusive and does not pass.

### Dependency on other parts
- Part 1: full execution pipeline and verdict engine are already present.
- Part 2: crash taxonomy is required for the security test cases used in validation.
- Status: this is the final validation and sign-off step for Part 3.

---

## Notes on scope and conflict avoidance

These steps are intentionally constrained to Part 3 only:
- No modifications to `config.py`, `repo.py`, `build.py`, `proc.py`, `testing.py`, `pipeline.py` beyond analyzer integration.
- No new target-specific logic or hard-coded names.
- No changes to crash taxonomy or sanitizer parsing owned by Part 2.
- No changes to reproducer bundles, delta debugging, or ELF hardening owned by Part 4.

The implementation should therefore be isolated to the analyzer contract and helper logic, leaving the rest of the project stable and reducing the risk of teammate conflicts.
