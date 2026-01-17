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
│   │   ├── ir.h, xrefs.h, symbols.h, address.h
│   └── commands/
│       └── commands.h     # Command declarations
├── src/
│   ├── command.cpp        # Registry implementation
│   ├── tokenizer.cpp      # Command line tokenization
│   ├── args/              # Argument parsing
│   ├── services/          # Service implementations
│   ├── formatters/        # Formatter implementations (ir.cpp: 651 lines)
│   ├── commands/          # Command implementations
│   └── util/              # Address resolver, etc.
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
| `IRService` | IR building, lifting, pseudocode |
| `DisasmService` | Disassembly operations |

## Command Pattern

```cpp
class MyCommand : public Command {
    std::string name() const override { return "mycmd"; }
    std::string help() const override { return "Does something"; }
    void execute(const Args& args, Output& out) override {
        // Implementation
    }
};
// Register in default_commands.cpp
```

## Argument Parsing

```cpp
// In command execute():
ArgSpec spec;
spec.add_positional("address", ArgType::Address);
spec.add_flag("verbose", 'v');
auto matches = spec.parse(args);
uint64_t addr = matches.get_address("address");
```

## Notes

- Services wrap engine APIs for easier client use
- Formatters convert engine types to display strings
- Both CLI and ImGui link this library
- Command registry shared with ImGui command palette
