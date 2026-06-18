pub mod cfg;
pub mod diagnostics;
pub mod disasm;
pub mod functions;
pub mod invalidation;
pub mod pass;
pub mod refresh;
pub mod scheduler;
pub mod session;
pub mod strings;
pub mod target;
pub mod xrefs;

use crate::{
    model::{
        AnalysisState, BasicBlock, CfgEdge, Diagnostic, Function, Instruction, Segment, StringRef,
        UserFacts, Xref,
    },
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

fn segments_from_loaded(segments: &[urloader::Segment]) -> Vec<Segment> {
    segments
        .iter()
        .map(|segment| Segment {
            id: segment.id,
            name: segment.name.clone(),
            vaddr: segment.vaddr,
            file_offset: segment.file_offset,
            file_size: segment.file_size,
            mem_size: segment.mem_size,
            permissions: segment.permissions.clone(),
        })
        .collect()
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

pub fn build_state_from_loaded(
    loaded: &urloader::LoadedImage,
    user_facts: &UserFacts,
) -> Result<AnalysisState> {
    let segments = segments_from_loaded(&loaded.segments);
    let target = target::AnalysisTarget::from_loaded(loaded)?;
    let image = AnalysisImage {
        target,
        entry: loaded.entry,
        bytes: &loaded.bytes,
        segments: &segments,
    };
    let user_functions = functions::manual_functions_from_facts(user_facts);
    let output = run_initial_analysis(&image, &user_functions)?;

    Ok(AnalysisState {
        instructions: output.instructions,
        strings: output.strings,
        basic_blocks: output.basic_blocks,
        cfg_edges: output.cfg_edges,
        functions: output.functions,
        xrefs: output.xrefs,
        diagnostics: output.diagnostics,
    })
}
