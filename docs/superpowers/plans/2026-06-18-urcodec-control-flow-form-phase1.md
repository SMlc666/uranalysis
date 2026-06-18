# Urcodec Control-Flow Form Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make forms a real decode path for the highest-value control-flow families and upgrade the corpus gate to enforce unknown-family budgets.

**Architecture:** Extend `InstructionForm` so forms can decode raw bytes, then route `Decoder` through forms before legacy fallback. Migrate AArch64 and x86-64 control-flow families with test-first slices, and add family-budget enforcement plus reporting in `ura-corpus-gate`.

**Tech Stack:** Rust 2021 workspace, `cargo test`, `cargo fmt`, existing `urcodec` roundtrip tests, and existing `ura-corpus-gate` unit tests.

---

## File Structure

- Modify: `crates/urcodec/src/form.rs` for decode-capable form metadata.
- Modify: `crates/urcodec/src/decoder.rs` for form-first decode dispatch.
- Modify: `crates/urcodec/src/arch/aarch64/forms.rs` for AArch64 control-flow form decode/encode/parse.
- Modify: `crates/urcodec/src/arch/x86_64/forms.rs` for x86-64 relative control-flow form decode/encode/parse.
- Modify: `crates/urcodec/tests/seed_forms.rs` to prove the migrated families roundtrip.
- Modify: `crates/ura-corpus-gate/src/main.rs` for per-family budgets and summary output.
- Modify: `tests/corpus/manifest.toml` to add initial optional family budgets.
- Modify: `docs/urcodec/aarch64-coverage.md` and `docs/urcodec/x86_64-coverage.md` to reflect the expanded seed set.

### Task 1: Make Forms Decode-Capable

**Files:**
- Modify: `crates/urcodec/src/form.rs`
- Modify: `crates/urcodec/src/decoder.rs`
- Test: `crates/urcodec/tests/seed_forms.rs`

- [ ] **Step 1: Write failing decode-path tests for representative form-owned instructions**
- [ ] **Step 2: Run the focused tests and verify the new assertions fail**
- [ ] **Step 3: Add form decode callbacks and form-first `Decoder` dispatch**
- [ ] **Step 4: Re-run focused tests and verify they pass**

### Task 2: Migrate AArch64 Control-Flow Families

**Files:**
- Modify: `crates/urcodec/src/arch/aarch64/forms.rs`
- Test: `crates/urcodec/tests/seed_forms.rs`

- [ ] **Step 1: Write failing roundtrip tests for `bl`, `b.cond`, and `cbnz`**
- [ ] **Step 2: Run the focused tests and verify they fail**
- [ ] **Step 3: Implement decode/encode/parse helpers for AArch64 control-flow families**
- [ ] **Step 4: Re-run focused tests and verify they pass**

### Task 3: Migrate x86-64 Relative Control-Flow Families

**Files:**
- Modify: `crates/urcodec/src/arch/x86_64/forms.rs`
- Test: `crates/urcodec/tests/seed_forms.rs`

- [ ] **Step 1: Write failing roundtrip tests for `jmp`, `jne`, and `ret imm16` or keep scope to currently targeted families if `ret imm16` is deferred**
- [ ] **Step 2: Run the focused tests and verify they fail**
- [ ] **Step 3: Implement decode/encode/parse helpers for x86-64 relative control-flow families**
- [ ] **Step 4: Re-run focused tests and verify they pass**

### Task 4: Add Corpus Gate Family Budgets

**Files:**
- Modify: `crates/ura-corpus-gate/src/main.rs`
- Modify: `tests/corpus/manifest.toml`
- Test: `crates/ura-corpus-gate/src/main.rs`

- [ ] **Step 1: Write failing unit tests for family-budget enforcement and summary output**
- [ ] **Step 2: Run the focused tests and verify they fail**
- [ ] **Step 3: Implement manifest parsing, enforcement, and summary rendering**
- [ ] **Step 4: Re-run focused tests and verify they pass**

### Task 5: Update Coverage Docs And Verify Workspace

**Files:**
- Modify: `docs/urcodec/aarch64-coverage.md`
- Modify: `docs/urcodec/x86_64-coverage.md`

- [ ] **Step 1: Update coverage docs to match the migrated seed families**
- [ ] **Step 2: Run `cargo fmt --check`**
- [ ] **Step 3: Run targeted crate tests**
- [ ] **Step 4: Run `cargo test --workspace`**
- [ ] **Step 5: Run `cargo clippy --workspace --all-targets -- -D warnings`**
