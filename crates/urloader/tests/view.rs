mod fixtures;

use urloader::{load, Architecture, ImageClass, ImageFormat};

#[test]
fn analysis_view_exposes_target_and_executable_ranges_for_minimal_elf() {
    let bytes = fixtures::minimal_elf64_aarch64_executable();
    let raw = load(&bytes).expect("raw image should load");
    let view = raw.analysis_view(&bytes).expect("view should build");

    assert_eq!(view.target.format, ImageFormat::Elf);
    assert_eq!(view.target.architecture, Architecture::Aarch64);
    assert_eq!(view.target.class, ImageClass::Bits64);
    assert!(view.capabilities.can_map_executable_bytes);
    assert_eq!(view.entry, Some(0x400080));
    assert_eq!(view.ranges.len(), 1);
    assert_eq!(view.ranges[0].file_offset, 0);
}
