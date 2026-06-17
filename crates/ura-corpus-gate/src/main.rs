use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tempfile::tempdir;

const MAX_CORPUS_INSTRUCTIONS_PER_SAMPLE: usize = 20_000;

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
    failure_reason: Option<String>,
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
    let report = Report {
        ok,
        samples: reports,
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
            failure_reason: Some(err.to_string()),
        },
    }
}

fn analyze_sample(root: &Path, sample: &Sample) -> Result<SampleReport> {
    let input = root.join("tests/corpus").join(&sample.output);
    if !input.exists() {
        bail!("sample output missing: {}", input.display());
    }
    let dir = tempdir()?;
    let project = dir.path().join(format!("{}.ura", sample.id));

    ura_core::commands::new_project_with_instruction_limit(
        &input,
        &project,
        MAX_CORPUS_INSTRUCTIONS_PER_SAMPLE,
    )?;
    let info = ura_core::commands::info(&project)?;
    let instructions = ura_core::commands::disasm(&project, 0, usize::MAX)?;
    let basic_blocks = ura_core::commands::basic_blocks(&project)?;
    let cfg_edges = ura_core::commands::cfg_edges(&project)?;
    let strings = ura_core::commands::strings(&project, None)?;
    let functions = ura_core::commands::functions(&project)?;
    let xrefs = ura_core::commands::all_xrefs(&project)?;
    let diagnostics = ura_core::commands::diagnostics(&project)?;

    let detected_format = format!("{:?}", info.format).to_ascii_lowercase();
    let detected_architecture = format!("{:?}", info.architecture).to_ascii_lowercase();
    let detected_class = format!("{:?}", info.class).to_ascii_lowercase();
    let unknown = instructions
        .iter()
        .filter(|insn| insn.decode_status == ura_core::model::DecodeStatus::Unknown)
        .count();
    let unknown_rate = if instructions.is_empty() {
        1.0
    } else {
        unknown as f64 / instructions.len() as f64
    };

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
        cfg_failure_count: 0,
        failure_reason: if ok { None } else { Some(failures.join("; ")) },
    })
}

fn render_summary(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("# Corpus Gate\n\n");
    out.push_str("| Sample | OK | Instructions | Blocks | Edges | Unknown Rate | Failure |\n");
    out.push_str("| --- | --- | ---: | ---: | ---: | ---: | --- |\n");
    for sample in &report.samples {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {:.4} | {} |\n",
            sample.id,
            sample.ok,
            sample.decoded_instruction_count,
            sample.basic_block_count,
            sample.cfg_edge_count,
            sample.unknown_rate,
            sample.failure_reason.clone().unwrap_or_default()
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
                failure_reason: None,
            }],
        };

        let summary = render_summary(&report);

        assert!(summary
            .contains("| Sample | OK | Instructions | Blocks | Edges | Unknown Rate | Failure |"));
        assert!(summary.contains("| sample | true | 4 | 2 | 1 | 0.0000 |  |"));
    }
}
