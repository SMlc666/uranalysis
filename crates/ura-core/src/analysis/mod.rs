pub mod diagnostics;
pub mod disasm;
pub mod functions;
pub mod strings;
pub mod xrefs;

use crate::{
    elf_loader::LoadedElf,
    model::{Diagnostic, Function, Instruction, StringRef, Xref},
    Result,
};

pub struct AnalysisOutput {
    pub instructions: Vec<Instruction>,
    pub strings: Vec<StringRef>,
    pub functions: Vec<Function>,
    pub xrefs: Vec<Xref>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn run_initial_analysis(
    loaded: &LoadedElf,
    user_functions: &[Function],
) -> Result<AnalysisOutput> {
    let instructions = disasm::linear_disassemble(loaded)?;
    let strings = strings::extract_strings(loaded);
    let functions = functions::discover_functions(loaded.entry, &instructions, user_functions);
    let xrefs = xrefs::build_xrefs(&instructions, &strings);
    let diagnostics = diagnostics::collect_diagnostics(&instructions);
    Ok(AnalysisOutput {
        instructions,
        strings,
        functions,
        xrefs,
        diagnostics,
    })
}
