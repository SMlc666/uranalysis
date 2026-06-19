mod fixtures;

use std::{fs, process::Command};

#[test]
fn binary_view_round_trips_into_ura_core_analysis_for_elf_and_pe() {
    for bytes in [
        fixtures::minimal_elf64_aarch64_executable(),
        fixtures::minimal_pe32_plus_x86_64(),
    ] {
        let raw = urloader::load(&bytes).expect("raw image should load");
        let view = raw.analysis_view(&bytes).expect("view should build");
        let state = ura_core::analysis::build_state_from_view_with_instruction_limit(
            &view,
            &ura_core::model::UserFacts::default(),
            Some(32),
        )
        .expect("state should build");
        assert!(!state.instructions.is_empty());
    }
}

#[test]
fn debug_view_extracts_lines_and_function_ranges_from_dwarf_elf() {
    let dir = tempfile::tempdir().expect("tempdir should exist");
    let source = dir.path().join("sample.c");
    let output = dir.path().join("sample");
    fs::write(
        &source,
        "static int sample_debug_function(int x) { return x + 1; }\nint main(void) { return sample_debug_function(1); }\n",
    )
    .expect("source should be written");

    let status = Command::new("cc")
        .arg("-gdwarf-4")
        .arg("-O0")
        .arg("-o")
        .arg(&output)
        .arg(&source)
        .status()
        .expect("cc should launch");
    assert!(status.success(), "cc failed with status {status}");

    let bytes = fs::read(&output).expect("binary should be readable");
    let raw = urloader::load(&bytes).expect("raw image should load");
    let view = raw.analysis_view(&bytes).expect("view should build");
    let debug = view.debug.as_ref().expect("debug view should exist");

    assert!(view.capabilities.has_debug_lines);
    assert!(view.capabilities.has_debug_function_ranges);
    assert!(!debug.line_entries.is_empty());
    assert!(debug
        .function_ranges
        .iter()
        .any(|range| range.name.as_deref() == Some("sample_debug_function")));
}
