use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

const MAX_CORPUS_INSTRUCTIONS_PER_SAMPLE: usize = 20_000;
const X86_64_UNKNOWN_CONTEXT_BYTES: usize = 8;

#[derive(Debug, Deserialize)]
struct Manifest {
    sample: Vec<Sample>,
}

#[derive(Debug, Deserialize)]
struct Sample {
    id: String,
    kind: String,
    output: PathBuf,
    format: String,
    arch: String,
    class: String,
    min_instructions: usize,
    max_unknown_rate: f64,
    required_strings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    ok: bool,
    samples: Vec<SampleReport>,
    unknown_clusters: Vec<UnknownClusterReport>,
}

#[derive(Debug, Serialize)]
struct SampleReport {
    id: String,
    kind: String,
    ok: bool,
    detected_format: Option<String>,
    detected_architecture: Option<String>,
    detected_class: Option<String>,
    decoded_instruction_count: usize,
    basic_block_count: usize,
    cfg_edge_count: usize,
    unknown_instruction_count: usize,
    unknown_rate: f64,
    string_count: usize,
    function_count: usize,
    xref_count: usize,
    diagnostic_count: usize,
    cfg_failure_count: usize,
    unknown_clusters: Vec<UnknownClusterReport>,
    failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct UnknownClusterReport {
    architecture: String,
    bytes: String,
    context_bytes: String,
    decoder: String,
    count: usize,
    samples: Vec<String>,
    first_address: u64,
    candidate_family: String,
}

fn main() -> Result<()> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        bail!("real-sample corpus gate is GitHub Actions only");
    }

    let args = Args::parse()?;
    let manifest_bytes = fs::read(&args.manifest)
        .with_context(|| format!("read manifest {}", args.manifest.display()))?;
    let manifest_text = std::str::from_utf8(&manifest_bytes)?;
    let manifest: Manifest = toml::from_str(manifest_text)?;

    let mut reports = Vec::new();
    for sample in &manifest.sample {
        reports.push(run_sample(&args.root, sample));
    }

    let ok = reports.iter().all(|report| report.ok);
    let unknown_clusters = aggregate_unknown_clusters(&reports);
    let report = Report {
        ok,
        samples: reports,
        unknown_clusters,
    };
    write_file(&args.report, &serde_json::to_string_pretty(&report)?)?;
    write_file(&args.summary, &render_summary(&report))?;

    if !report.ok {
        bail!("corpus gate failed");
    }
    Ok(())
}

struct Args {
    manifest: PathBuf,
    root: PathBuf,
    report: PathBuf,
    summary: PathBuf,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut manifest = None;
        let mut root = None;
        let mut report = None;
        let mut summary = None;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| anyhow!("missing value for {arg}"))?;
            match arg.as_str() {
                "--manifest" => manifest = Some(PathBuf::from(value)),
                "--root" => root = Some(PathBuf::from(value)),
                "--report" => report = Some(PathBuf::from(value)),
                "--summary" => summary = Some(PathBuf::from(value)),
                other => bail!("unknown argument {other}"),
            }
        }
        Ok(Self {
            manifest: manifest.ok_or_else(|| anyhow!("missing --manifest"))?,
            root: root.ok_or_else(|| anyhow!("missing --root"))?,
            report: report.ok_or_else(|| anyhow!("missing --report"))?,
            summary: summary.ok_or_else(|| anyhow!("missing --summary"))?,
        })
    }
}

fn run_sample(root: &Path, sample: &Sample) -> SampleReport {
    match analyze_sample(root, sample) {
        Ok(report) => report,
        Err(err) => SampleReport {
            id: sample.id.clone(),
            kind: sample.kind.clone(),
            ok: false,
            detected_format: None,
            detected_architecture: None,
            detected_class: None,
            decoded_instruction_count: 0,
            basic_block_count: 0,
            cfg_edge_count: 0,
            unknown_instruction_count: 0,
            unknown_rate: 1.0,
            string_count: 0,
            function_count: 0,
            xref_count: 0,
            diagnostic_count: 0,
            cfg_failure_count: 1,
            unknown_clusters: Vec::new(),
            failure_reason: Some(err.to_string()),
        },
    }
}

fn analyze_sample(root: &Path, sample: &Sample) -> Result<SampleReport> {
    let input = root.join("tests/corpus").join(&sample.output);
    if !input.exists() {
        bail!("sample output missing: {}", input.display());
    }
    let bytes = fs::read(&input)?;
    let loaded = urloader::load(&bytes)?;
    let state = ura_core::analysis::build_state_from_loaded_with_instruction_limit(
        &loaded,
        &ura_core::model::UserFacts::default(),
        Some(MAX_CORPUS_INSTRUCTIONS_PER_SAMPLE),
    )?;
    let instructions = &state.instructions;
    let basic_blocks = &state.basic_blocks;
    let cfg_edges = &state.cfg_edges;
    let strings = &state.strings;
    let functions = &state.functions;
    let xrefs = &state.xrefs;
    let diagnostics = &state.diagnostics;
    let cfg_failure_count = diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic.severity == "error" && diagnostic.message.contains("CFG decode gap")
        })
        .count();

    let detected_format = format!("{:?}", loaded.format).to_ascii_lowercase();
    let detected_architecture = format!("{:?}", loaded.architecture).to_ascii_lowercase();
    let detected_class = format!("{:?}", loaded.class).to_ascii_lowercase();
    let unknown = instructions
        .iter()
        .filter(|insn| insn.decode_status == ura_core::model::DecodeStatus::Unknown)
        .count();
    let unknown_rate = if instructions.is_empty() {
        1.0
    } else {
        unknown as f64 / instructions.len() as f64
    };
    let unknown_clusters =
        collect_unknown_clusters(&sample.id, &detected_architecture, instructions);

    let mut failures = Vec::new();
    if detected_format != sample.format {
        failures.push(format!(
            "format expected {} got {}",
            sample.format, detected_format
        ));
    }
    if detected_architecture != sample.arch {
        failures.push(format!(
            "architecture expected {} got {}",
            sample.arch, detected_architecture
        ));
    }
    if detected_class != sample.class {
        failures.push(format!(
            "class expected {} got {}",
            sample.class, detected_class
        ));
    }
    if instructions.len() < sample.min_instructions {
        failures.push(format!(
            "instruction count expected at least {} got {}",
            sample.min_instructions,
            instructions.len()
        ));
    }
    if unknown_rate > sample.max_unknown_rate {
        failures.push(format!(
            "unknown rate expected at most {:.4} got {:.4}",
            sample.max_unknown_rate, unknown_rate
        ));
    }
    for required in &sample.required_strings {
        if !strings.iter().any(|s| s.value.contains(required)) {
            failures.push(format!("required string not found: {required}"));
        }
    }

    let ok = failures.is_empty();
    Ok(SampleReport {
        id: sample.id.clone(),
        kind: sample.kind.clone(),
        ok,
        detected_format: Some(detected_format),
        detected_architecture: Some(detected_architecture),
        detected_class: Some(detected_class),
        decoded_instruction_count: instructions.len(),
        basic_block_count: basic_blocks.len(),
        cfg_edge_count: cfg_edges.len(),
        unknown_instruction_count: unknown,
        unknown_rate,
        string_count: strings.len(),
        function_count: functions.len(),
        xref_count: xrefs.len(),
        diagnostic_count: diagnostics.len(),
        cfg_failure_count,
        unknown_clusters,
        failure_reason: if ok { None } else { Some(failures.join("; ")) },
    })
}

fn collect_unknown_clusters(
    sample_id: &str,
    architecture: &str,
    instructions: &[ura_core::model::Instruction],
) -> Vec<UnknownClusterReport> {
    let mut clusters =
        BTreeMap::<(String, String, String, String, String), UnknownClusterAccumulator>::new();
    for (index, instruction) in instructions.iter().enumerate() {
        if instruction.decode_status != ura_core::model::DecodeStatus::Unknown {
            continue;
        }
        let bytes = format_bytes(&instruction.bytes);
        let context_bytes = format_bytes(&unknown_context_bytes(architecture, instructions, index));
        let candidate_family = candidate_family(architecture, &instruction.bytes);
        let key = (
            architecture.to_string(),
            bytes.clone(),
            context_bytes.clone(),
            instruction.decoder.clone(),
            candidate_family.clone(),
        );
        let entry = clusters
            .entry(key)
            .or_insert_with(|| UnknownClusterAccumulator {
                architecture: architecture.to_string(),
                bytes,
                context_bytes,
                decoder: instruction.decoder.clone(),
                count: 0,
                samples: BTreeSet::new(),
                first_address: instruction.addr,
                candidate_family,
            });
        entry.count += 1;
        entry.samples.insert(sample_id.to_string());
        entry.first_address = entry.first_address.min(instruction.addr);
    }
    sorted_unknown_clusters(
        clusters
            .into_values()
            .map(UnknownClusterAccumulator::finish),
    )
}

fn aggregate_unknown_clusters(reports: &[SampleReport]) -> Vec<UnknownClusterReport> {
    let mut clusters =
        BTreeMap::<(String, String, String, String, String), UnknownClusterAccumulator>::new();
    for report in reports {
        for cluster in &report.unknown_clusters {
            let key = (
                cluster.architecture.clone(),
                cluster.bytes.clone(),
                cluster.context_bytes.clone(),
                cluster.decoder.clone(),
                cluster.candidate_family.clone(),
            );
            let entry = clusters
                .entry(key)
                .or_insert_with(|| UnknownClusterAccumulator {
                    architecture: cluster.architecture.clone(),
                    bytes: cluster.bytes.clone(),
                    context_bytes: cluster.context_bytes.clone(),
                    decoder: cluster.decoder.clone(),
                    count: 0,
                    samples: BTreeSet::new(),
                    first_address: cluster.first_address,
                    candidate_family: cluster.candidate_family.clone(),
                });
            entry.count += cluster.count;
            entry.samples.extend(cluster.samples.iter().cloned());
            entry.first_address = entry.first_address.min(cluster.first_address);
        }
    }
    sorted_unknown_clusters(
        clusters
            .into_values()
            .map(UnknownClusterAccumulator::finish),
    )
}

#[derive(Debug)]
struct UnknownClusterAccumulator {
    architecture: String,
    bytes: String,
    context_bytes: String,
    decoder: String,
    count: usize,
    samples: BTreeSet<String>,
    first_address: u64,
    candidate_family: String,
}

impl UnknownClusterAccumulator {
    fn finish(self) -> UnknownClusterReport {
        UnknownClusterReport {
            architecture: self.architecture,
            bytes: self.bytes,
            context_bytes: self.context_bytes,
            decoder: self.decoder,
            count: self.count,
            samples: self.samples.into_iter().collect(),
            first_address: self.first_address,
            candidate_family: self.candidate_family,
        }
    }
}

fn sorted_unknown_clusters(
    clusters: impl IntoIterator<Item = UnknownClusterReport>,
) -> Vec<UnknownClusterReport> {
    let mut clusters = clusters.into_iter().collect::<Vec<_>>();
    clusters.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.architecture.cmp(&right.architecture))
            .then_with(|| left.bytes.cmp(&right.bytes))
            .then_with(|| left.context_bytes.cmp(&right.context_bytes))
            .then_with(|| left.decoder.cmp(&right.decoder))
    });
    clusters
}

fn unknown_context_bytes(
    architecture: &str,
    instructions: &[ura_core::model::Instruction],
    index: usize,
) -> Vec<u8> {
    let instruction = &instructions[index];
    if architecture != "x86_64" {
        return instruction.bytes.clone();
    }

    let mut context = Vec::new();
    let mut expected_addr = instruction.addr;
    for next in &instructions[index..] {
        if next.addr != expected_addr {
            break;
        }
        for byte in &next.bytes {
            if context.len() == X86_64_UNKNOWN_CONTEXT_BYTES {
                return context;
            }
            context.push(*byte);
        }
        expected_addr = expected_addr.wrapping_add(next.bytes.len() as u64);
    }
    context
}

fn format_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(empty)".to_string();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn candidate_family(architecture: &str, bytes: &[u8]) -> String {
    match architecture {
        "aarch64" => candidate_aarch64_family(bytes),
        "x86_64" => candidate_x86_64_family(bytes),
        other => format!("{other}_unknown_encoding"),
    }
}

fn candidate_aarch64_family(bytes: &[u8]) -> String {
    let Ok(word_bytes) = <[u8; 4]>::try_from(bytes) else {
        return "aarch64_malformed_fixed_width".to_string();
    };
    let word = u32::from_le_bytes(word_bytes);
    format!("aarch64_encoding_group_0x{:02x}", (word >> 25) & 0x7f)
}

fn candidate_x86_64_family(bytes: &[u8]) -> String {
    match bytes.first().copied() {
        Some(0x0f) => "x86_64_two_byte_opcode".to_string(),
        Some(0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf2 | 0xf3 | 0x40..=0x4f) => {
            "x86_64_prefix_or_prefixed_opcode".to_string()
        }
        Some(_) => "x86_64_unknown_opcode_or_prefix".to_string(),
        None => "x86_64_empty_decode".to_string(),
    }
}

fn render_summary(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("# Corpus Gate\n\n");
    out.push_str(
        "| Sample | OK | Instructions | Blocks | Edges | CFG Failures | Unknown Rate | Failure |\n",
    );
    out.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |\n");
    for sample in &report.samples {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {:.4} | {} |\n",
            sample.id,
            sample.ok,
            sample.decoded_instruction_count,
            sample.basic_block_count,
            sample.cfg_edge_count,
            sample.cfg_failure_count,
            sample.unknown_rate,
            sample.failure_reason.clone().unwrap_or_default()
        ));
    }
    out.push_str("\n## Unknown Instruction Clusters\n\n");
    out.push_str(
        "| Architecture | Bytes | Context Bytes | Decoder | Count | Samples | First Address | Candidate Family |\n",
    );
    out.push_str("| --- | --- | --- | --- | ---: | --- | --- | --- |\n");
    for cluster in &report.unknown_clusters {
        out.push_str(&format!(
            "| {} | `{}` | `{}` | {} | {} | {} | 0x{:x} | {} |\n",
            cluster.architecture,
            cluster.bytes,
            cluster.context_bytes,
            cluster.decoder,
            cluster.count,
            cluster.samples.join(","),
            cluster.first_address,
            cluster.candidate_family
        ));
    }
    out
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_includes_cfg_metrics() {
        let report = Report {
            ok: true,
            unknown_clusters: Vec::new(),
            samples: vec![SampleReport {
                id: "sample".to_string(),
                kind: "source".to_string(),
                ok: true,
                detected_format: Some("elf".to_string()),
                detected_architecture: Some("aarch64".to_string()),
                detected_class: Some("bits64".to_string()),
                decoded_instruction_count: 4,
                basic_block_count: 2,
                cfg_edge_count: 1,
                unknown_instruction_count: 0,
                unknown_rate: 0.0,
                string_count: 1,
                function_count: 1,
                xref_count: 1,
                diagnostic_count: 0,
                cfg_failure_count: 0,
                unknown_clusters: Vec::new(),
                failure_reason: None,
            }],
        };

        let summary = render_summary(&report);

        assert!(summary
            .contains("| Sample | OK | Instructions | Blocks | Edges | CFG Failures | Unknown Rate | Failure |"));
        assert!(summary.contains("| sample | true | 4 | 2 | 1 | 0 | 0.0000 |  |"));
    }

    #[test]
    fn summary_includes_unknown_cluster_section() {
        let report = Report {
            ok: true,
            samples: Vec::new(),
            unknown_clusters: Vec::new(),
        };

        let summary = render_summary(&report);

        assert!(summary.contains("## Unknown Instruction Clusters"));
        assert!(summary.contains(
            "| Architecture | Bytes | Context Bytes | Decoder | Count | Samples | First Address | Candidate Family |"
        ));
    }

    #[test]
    fn unknown_clusters_group_by_architecture_decoder_and_bytes() {
        let instructions = vec![
            instruction(0x1000, &[0xff], ura_core::model::DecodeStatus::Unknown),
            instruction(0x2000, &[0xff], ura_core::model::DecodeStatus::Unknown),
            instruction(0x1002, &[0xc3], ura_core::model::DecodeStatus::Complete),
        ];

        let clusters = collect_unknown_clusters("sample", "x86_64", &instructions);

        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].architecture, "x86_64");
        assert_eq!(clusters[0].bytes, "ff");
        assert_eq!(clusters[0].context_bytes, "ff");
        assert_eq!(clusters[0].decoder, "urcodec/x86_64");
        assert_eq!(clusters[0].count, 2);
        assert_eq!(clusters[0].samples, vec!["sample".to_string()]);
        assert_eq!(clusters[0].first_address, 0x1000);
        assert_eq!(
            clusters[0].candidate_family,
            "x86_64_unknown_opcode_or_prefix"
        );
    }

    #[test]
    fn x86_unknown_clusters_include_contiguous_context_bytes() {
        let instructions = vec![
            instruction(0x1000, &[0x0f], ura_core::model::DecodeStatus::Unknown),
            instruction(0x1001, &[0x84], ura_core::model::DecodeStatus::Unknown),
            instruction(0x1002, &[0x11], ura_core::model::DecodeStatus::Unknown),
            instruction(0x1003, &[0x22], ura_core::model::DecodeStatus::Unknown),
            instruction(0x1004, &[0x33], ura_core::model::DecodeStatus::Unknown),
            instruction(0x1005, &[0x44], ura_core::model::DecodeStatus::Unknown),
            instruction(0x2000, &[0x0f], ura_core::model::DecodeStatus::Unknown),
            instruction(0x2001, &[0x85], ura_core::model::DecodeStatus::Unknown),
        ];

        let clusters = collect_unknown_clusters("sample", "x86_64", &instructions);

        let two_byte_clusters = clusters
            .iter()
            .filter(|cluster| cluster.bytes == "0f")
            .collect::<Vec<_>>();
        assert_eq!(two_byte_clusters.len(), 2);
        assert!(two_byte_clusters
            .iter()
            .any(|cluster| cluster.context_bytes == "0f 84 11 22 33 44"));
        assert!(two_byte_clusters
            .iter()
            .any(|cluster| cluster.context_bytes == "0f 85"));
    }

    fn instruction(
        addr: u64,
        bytes: &[u8],
        decode_status: ura_core::model::DecodeStatus,
    ) -> ura_core::model::Instruction {
        ura_core::model::Instruction {
            addr,
            size: bytes.len() as u8,
            bytes: bytes.to_vec(),
            mnemonic: if decode_status == ura_core::model::DecodeStatus::Unknown {
                ".byte".to_string()
            } else {
                "ret".to_string()
            },
            operands: String::new(),
            text: String::new(),
            kind: if decode_status == ura_core::model::DecodeStatus::Unknown {
                ura_core::model::InstructionKind::Unknown
            } else {
                ura_core::model::InstructionKind::Return
            },
            flow: ura_core::model::FlowKind::Fallthrough,
            fallthrough: Some(addr + bytes.len() as u64),
            branch_target: None,
            decode_status,
            decoder: "urcodec/x86_64".to_string(),
            decoder_version: "test".to_string(),
            function_addr: None,
        }
    }
}
