mod fixtures;

use ura_core::{elf_loader::LoadedElf, model::LoadProfile, Result};

#[test]
fn loads_minimal_aarch64_executable() -> Result<()> {
    let bytes = fixtures::minimal_elf64_aarch64_executable();
    let loaded = LoadedElf::parse(&bytes)?;

    assert_eq!(loaded.entry, 0x400080);
    assert_eq!(loaded.profile, LoadProfile::Executable);
    assert_eq!(loaded.segments.len(), 1);
    assert_eq!(loaded.segments[0].vaddr, 0x400000);
    assert_eq!(loaded.va_to_offset(0x400080), Some(0x80));
    assert_eq!(loaded.executable_ranges(), vec![(0x400000, 0x401000)]);
    Ok(())
}
