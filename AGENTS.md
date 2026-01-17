# URANAYZLE KNOWLEDGE BASE

**Generated:** 2026-01-17 | **Commit:** d651ed7 | **Branch:** main

## OVERVIEW

Binary analysis framework: ELF/PE loading → Capstone disassembly → 3-tier IR (LLIR→MLIR→HLIR) → decompilation. C++20, xmake build.

## STRUCTURE

```
uranayzle/
├── src/engine/           # Core library (see src/engine/AGENTS.md)
│   ├── arch/{arm64,x86_64}/  # Architecture lifters
│   ├── ir/{llir,mlil,hlil}/  # IR pipeline (see src/engine/ir/AGENTS.md)
│   ├── decompiler/           # Pseudocode gen (see src/engine/decompiler/AGENTS.md)
│   ├── loader/{elf,pe}/      # Binary format parsers
│   └── include/engine/       # Public headers
├── clients/
│   ├── common/           # Shared client SDK (see clients/common/AGENTS.md)
│   ├── cli/              # REPL client (replxx)
│   └── imgui/            # Windows GUI (see clients/imgui/AGENTS.md)
├── tests/                # Catch2 tests + sample binaries
├── third-party/llvm/     # Embedded LLVM demangler
└── docs/                 # Architecture docs
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add instruction support | `src/engine/arch/{arch}/llil_lifter.cpp` | Switch on Capstone opcode |
| Add IR optimization | `src/engine/ir/{level}/opt.cpp` | LLIR/MLIR/HLIL passes |
| Add decompiler pass | `src/engine/decompiler/passes/` | See pipeline order in AGENTS.md |
| Add binary format | `src/engine/loader/` | Follow ELF/PE pattern |
| Add CLI command | `clients/common/src/commands/` | Register in `commands.h` |
| Add GUI view | `clients/imgui/views/` | Inherit `ViewBase` |
| Add test | `tests/` | Use `test_helpers.h`, Catch2 |

## COMPLEXITY HOTSPOTS

| File | Lines | Why |
|------|-------|-----|
| `arch/arm64/llil_lifter.cpp` | 2022 | 1000+ ARM64 opcodes via switch |
| `decompiler/transforms/expr_transforms.cpp` | 1376 | Recursive pattern matching |
| `xrefs/xrefs.cpp` | 1224 | Symbolic eval + relocations |
| `decompiler/transforms/var_transforms.cpp` | 1222 | SSA manipulation |
| `ehframe/eh_frame.cpp` | 1144 | DWARF CFI state machine |

## CROSS-CUTTING PATTERNS

**Session Model**: `engine::Session` owns all state (image, symbols, xrefs, analysis DB).

**Service Layer**: `clients/common/services/` wraps engine APIs for clients.

**Command Registry**: Shared between CLI REPL and ImGui command palette.

**Logging**: `spdlog` via `engine/log.h`. ImGui adds custom sink for Log View.

**Pass Manager**: LLVM-inspired, shared across all IR tiers (`src/engine/pass/`).

## CONVENTIONS

- **Indent**: 4 spaces, K&R braces
- **Naming**: `CamelCase` classes, `snake_case` functions
- **Headers**: Public in `include/` directories, use `std::` types
- **Logging**: `SPDLOG_DEBUG`, `SPDLOG_INFO`, etc.

## ANTI-PATTERNS

- **Type forcing**: Do NOT force types to register width in decompiler
- **Float Phi**: Do NOT trust float regs defined only by Phi nodes (often garbage)
- **SSA skip**: Do NOT bypass SSA construction for IR passes
- **as any**: Never suppress type errors

## COMMANDS

```bash
# Configure + build (debug)
xmake f && xmake

# Release build
xmake f --mode=release && xmake

# Run CLI
xmake run cli -- <args>

# Run GUI (Windows only)
xmake f --plat=windows --with-imgui_client=y && xmake run imgui_client

# Run tests
xmake run engine_tests
```

## DEPENDENCIES

| Package | Purpose |
|---------|---------|
| capstone | Disassembly |
| catch2 | Testing |
| replxx | CLI readline |
| sqlite3 | Analysis DB |
| raw_pdb | PDB parsing |
| spdlog | Logging |
| imgui | GUI (Windows) |

## KNOWN ISSUES

- `range_analysis.cpp/h` in root should be in `src/engine/decompiler/passes/`
- `nul` file in root is Windows artifact, ignore
- Tests are smoke-level; granular unit tests needed
