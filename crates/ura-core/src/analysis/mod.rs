pub mod cfg;
pub mod diagnostics;
pub mod disasm;
pub mod functions;
pub mod refresh;
pub mod strings;
pub mod target;
pub mod xrefs;

use crate::{
    model::{BasicBlock, CfgEdge, Diagnostic, Function, Instruction, Segment, StringRef, Xref},
    Result,
};

pub struct AnalysisImage<'a> {
    pub target: target::AnalysisTarget,
    pub entry: u64,
    pub bytes: &'a [u8],
    pub segments: &'a [Segment],
}

impl AnalysisImage<'_> {
    pub fn va_to_offset(&self, addr: u64) -> Option<u64> {
        self.segments.iter().find_map(|seg| {
            let end = seg.vaddr.checked_add(seg.file_size)?;
            if addr >= seg.vaddr && addr < end {
                Some(seg.file_offset + (addr - seg.vaddr))
            } else {
                None
            }
        })
    }

    pub fn executable_ranges(&self) -> Vec<(u64, u64)> {
        self.segments
            .iter()
            .filter(|seg| seg.permissions.contains('x'))
            .map(|seg| (seg.vaddr, seg.vaddr + seg.mem_size))
            .collect()
    }

    pub fn bytes_at(&self, addr: u64, size: usize) -> Option<&[u8]> {
        let offset = self.va_to_offset(addr)? as usize;
        self.bytes.get(offset..offset.checked_add(size)?)
    }
}

pub struct AnalysisOutput {
    pub instructions: Vec<Instruction>,
    pub basic_blocks: Vec<BasicBlock>,
    pub cfg_edges: Vec<CfgEdge>,
    pub strings: Vec<StringRef>,
    pub functions: Vec<Function>,
    pub xrefs: Vec<Xref>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn run_initial_analysis(
    image: &AnalysisImage<'_>,
    user_functions: &[Function],
) -> Result<AnalysisOutput> {
    run_initial_analysis_with_instruction_limit(image, user_functions, None)
}

pub fn run_initial_analysis_with_instruction_limit(
    image: &AnalysisImage<'_>,
    user_functions: &[Function],
    max_instructions: Option<usize>,
) -> Result<AnalysisOutput> {
    let instructions = disasm::linear_disassemble_with_limit(image, max_instructions)?;
    let strings = strings::extract_strings(image);
    let window = refresh::AnalysisWindow {
        start: image.entry,
        end: image.entry.saturating_add(4),
        reason: refresh::RefreshReason::SourceBytesChanged,
    };
    let mut diagnostics = diagnostics::collect_diagnostics(&instructions);
    let cfg = match cfg::build_cfg(&instructions, &[image.entry], window) {
        Ok(cfg) => cfg,
        Err(err) if max_instructions.is_some() => {
            diagnostics.push(Diagnostic {
                addr: Some(image.entry),
                severity: "error".to_string(),
                message: err.to_string(),
            });
            cfg::CfgOutput {
                basic_blocks: Vec::new(),
                cfg_edges: Vec::new(),
            }
        }
        Err(err) => return Err(err),
    };
    let functions = functions::discover_functions(
        image.entry,
        &instructions,
        &cfg.basic_blocks,
        &cfg.cfg_edges,
        user_functions,
    );
    let xrefs = xrefs::build_xrefs(&instructions, &strings, &cfg.cfg_edges);
    diagnostics.extend(diagnostics::collect_graph_diagnostics(&cfg.cfg_edges));
    diagnostics.extend(diagnostics::collect_user_function_diagnostics(
        &functions,
        &instructions,
    ));
    Ok(AnalysisOutput {
        instructions,
        basic_blocks: cfg.basic_blocks,
        cfg_edges: cfg.cfg_edges,
        strings,
        functions,
        xrefs,
        diagnostics,
    })
}
