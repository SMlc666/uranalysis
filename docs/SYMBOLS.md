# Symbol Infrastructure

To support richer analysis without touching LLIR/MLIR details, the engine now exposes a dedicated symbol & metadata layer:

## Loader-side support
- `ElfSymbol` records the essential fields parsed from `.symtab` / `.dynsym`.
- `load_elf_image_with_symbols()` pulls symbols alongside sections/segments and hands them to the session (ELF readers still expose the legacy `load_elf_image()` for backward compatibility).

## Engine data structures
- `symbols::SymbolTable` keeps the parsed symbol list plus fast lookups by name/address.
- `rtti::RttiCatalog` scans the full data segment space and applies ABI-specific heuristics: Itanium vtables follow `[offset][type_info][functions…]` while MSVC vtables begin with an `RTTICompleteObjectLocator`. Every candidate’s functions are validated against executable segments and the corresponding `type_info` or `TypeDescriptor` is parsed, so even tables whose virtuals are pure-call stubs survive discovery. Each `TypeInfo` also records which ABI it came from so downstream logic can differentiate handles/decls.
- `dwarf::DwarfCatalog` mirrors `.debug_*` sections so higher layers can access raw DWARF bytes without re-parsing ELF repeatedly.

## Session API
- Sessions now retain the raw `std::vector<ElfSymbol>` from the loader plus prebuilt `SymbolTable`, `RttiCatalog`, and `DwarfCatalog`.
- Callers can access them through `Session::symbols()`, `Session::symbol_table()`, `Session::rtti_catalog()`, and `Session::dwarf_catalog()`.
- The discovery pipeline injects these symbols when `FunctionDiscoveryOptions::include_symbol_entries` is enabled, making symbol-based entry collection the default.

## Analysis hooks
- `analysis::discover_functions_arm64()` now accepts symbol-based options (symbol tables, tail jumps, manual entries).
- Internal helpers in `analysis/detail/` keep the discovery extension points separate from LLIR so they can be shared with future MLIR/HLIR passes.

Use this foundation to build RTTI-aware type recovery, DWARF-driven stack analysis, or symbol-aware decompilation without modifying LLIR itself.
