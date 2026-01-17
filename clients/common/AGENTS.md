# Client Common Knowledge Base

## Overview

Shared library for CLI and ImGui clients: services, formatters, commands.

## Structure

```
common/
├── include/client/
│   ├── session.h          # Typedef to engine::Session
│   ├── output.h           # Output handling (stdout, file, string)
│   ├── command.h          # Command registry framework
│   ├── services/          # Engine API wrappers
│   │   ├── analysis_service.h
│   │   ├── ir_service.h
│   │   └── disasm_service.h
│   ├── formatters/        # String formatting utilities
│   │   ├── ir.h
│   │   ├── xrefs.h
│   │   ├── symbols.h
│   │   └── address.h
│   └── commands/          # Command definitions
│       └── commands.h
└── src/
    ├── services/          # Service implementations
    ├── formatters/        # Formatter implementations
    │   └── ir.cpp         # IR formatting (651 lines)
    └── commands/          # Command implementations
```

## Where to Look

| Task | Location |
|------|----------|
| Add CLI command | `src/commands/` + register in `commands.h` |
| Add service | `include/client/services/` + `src/services/` |
| Add formatter | `include/client/formatters/` + `src/formatters/` |
| Change output handling | `output.h` / `output.cpp` |

## Services

| Service | Purpose |
|---------|---------|
| `AnalysisService` | Function discovery, xref analysis |
| `IRService` | IR building, lifting, pseudocode generation |
| `DisasmService` | Disassembly operations |

## Command Pattern

```cpp
// Adding a command
class MyCommand : public Command {
    std::string name() const override { return "mycmd"; }
    std::string help() const override { return "Does something"; }
    void execute(const Args& args, Output& out) override {
        // Implementation
    }
};
// Register in CommandRegistry
```

## Notes

- Services wrap engine APIs for easier client use
- Formatters convert engine types to display strings
- Both CLI and ImGui clients link this library
