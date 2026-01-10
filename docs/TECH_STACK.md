# Tech Stack

## Language and build
- C++20
- xmake

## Dependencies (initial)
- capstone: ARM64 decode
- lief (or LLVM Object): ELF loading
- spdlog: logging
- CLI11: CLI parsing
- sqlite3: analysis database storage
- Catch2: testing

## Notes
- Capstone can be replaced by a custom decoder later without changing engine interfaces.
- ELF is the only supported binary format in the initial phase.
