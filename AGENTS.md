# Repository Guidelines

## Project Structure & Module Organization
- `src/engine/` holds the core analyzer code (disassembly, ELF loading, IR). Headers live under `src/engine/include`.
- `clients/` contains two apps: `cli/` for the REPL launcher and `imgui/` for the Windows GUI + DX11/DX12 backends. Reusable helpers live in `clients/common/{include,src}`.
- `docs/` documents architecture, roadmap, and technology decisions; keep supporting material there. `tests/` is reserved for future unit/integration suites.
- `build/` accumulates artifacts from local builds (xmake default); treat it as scratch and avoid committing its contents.

## Build, Test, and Development Commands
- Configure and build via `xmake`: run `xmake f` to configure the default debug workspace (`cxx20`, static engine) and `xmake` to compile every target (`engine`, `cli`, `client_common`).
- For release builds override the mode: `xmake f --mode=release && xmake`.
- Run the console client with `xmake run cli -- <command args>`. On Windows, enable the GUI client before building: `xmake f --plat=windows --with-imgui_client=y && xmake run imgui_client`.
- Tests are currently placeholder; once suites exist use `xmake test` (after `xmake f`) so the same configuration drives compilation and execution.

## Coding Style & Naming Conventions
- Stick to four-space indentation and K&R braces as seen in `clients/common/src/*.cpp` and `clients/imgui/*.cpp`.
- Prefer `CamelCase` for structs/classes (`CommandRegistry`, `UiState`) and `snake_case` or lowercase verbs for functions (`run_imgui_dx11`, `parse_u64`).
- Keep public headers in `include/` directories and rely on `std::` types for strings/streams. Mirrors for helper files (e.g., `client/common`) should stay self-contained.

## Testing Guidelines
- Drop new tests under `tests/` with descriptive filenames like `elf_loader_test.cpp`; keep tests close to the component they validate.
- Use the same `xmake` configuration for tests (`xmake f`), then `xmake test` once harnesses exist. Write tests the way the engine code is authored to keep the same style and includes.
- Aim for readable error messages and add data-driven cases when verifying disassembly paths or ELF parsing.

## Commit & Pull Request Guidelines
- Use short imperative commit messages (e.g., `Add seek command to client`) even though history is minimal. Group related changes into one commit when possible; avoid mixing formatting fixes with feature work.
- Each PR should summarize what changed, why, and link any supporting issue or doc page. Mention if manual steps (e.g., `xmake f --with-imgui_client=y`) are required for reviewers.
- Attach screenshots only for GUI work, and call out platform-specific dependencies when they affect testing or review (DX11/DX12 choices on Windows).
