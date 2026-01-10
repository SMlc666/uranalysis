# Overview

## Goals
- Build a multi-tier IR binary analysis engine with decompiler-quality pseudocode.
- Start with ARM64 and ELF, while keeping architecture extensions straightforward.
- Deliver a CLI client first; allow future GUI clients via the same engine library.

## Scope
- In: engine core, IR stack, analysis pipeline, ARM64 decode/lift, ELF loading, CLI.
- Out: full GUI parity with commercial tools, broad ISA coverage, plugin ecosystem.

## Deliverables (initial)
- Engine library (.a/.so/.dll) exporting a stable C++ API.
- CLI client that exercises the engine and produces readable outputs.

## Non-goals (initial)
- Network protocol / RPC layer.
- Full binary format coverage (PE/Mach-O).
- Full IDA/Binary Ninja feature parity.
