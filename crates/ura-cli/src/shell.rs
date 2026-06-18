use std::path::PathBuf;

use anyhow::{bail, Result};
use rustyline::DefaultEditor;

use crate::SessionProject;

pub fn run(project: PathBuf) -> Result<()> {
    let mut rl = DefaultEditor::new()?;
    let mut project = SessionProject::load(project)?;
    let mut current_addr = 0u64;
    loop {
        let line = rl.readline("ura> ")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _ = rl.add_history_entry(trimmed);
        let mut parts = trimmed.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        match cmd {
            "quit" | "exit" => break,
            "info" => println!("{:#?}", project.session.state.functions),
            "funcs" => println!("{:#?}", project.session.state.functions),
            "strings" => {
                let filter = parts.next().unwrap_or("");
                let rows = project
                    .session
                    .state
                    .strings
                    .iter()
                    .filter(|s| s.value.contains(filter))
                    .cloned()
                    .collect::<Vec<_>>();
                println!("{rows:#?}");
            }
            "diagnostics" => println!("{:#?}", project.session.state.diagnostics),
            "disasm" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                current_addr = addr;
                let rows = project
                    .session
                    .state
                    .instructions
                    .iter()
                    .filter(|insn| insn.addr >= addr)
                    .take(16)
                    .cloned()
                    .collect::<Vec<_>>();
                println!("{rows:#?}");
            }
            "xrefs" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                current_addr = addr;
                let rows = project
                    .session
                    .state
                    .xrefs
                    .iter()
                    .filter(|xref| xref.to_addr == addr || xref.from_addr == addr)
                    .cloned()
                    .collect::<Vec<_>>();
                println!("{rows:#?}");
            }
            "rename" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let name = parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing name"))?;
                project.session.rename(addr, name)?;
                project.refresh()?;
                project.save()?;
            }
            "comment" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let text = parts.collect::<Vec<_>>().join(" ");
                project.session.comment(addr, &text)?;
                project.refresh()?;
                project.save()?;
            }
            "make-func" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                project.session.update_manual_function_range(addr, addr, addr + 4)?;
                project.refresh()?;
                project.save()?;
            }
            "set-func-range" => {
                let func_addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let start = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let end = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                project
                    .session
                    .update_manual_function_range(func_addr, start, end)?;
                project.refresh()?;
                project.save()?;
            }
            "reanalyze" => {
                project.force_reanalyze()?;
                project.save()?;
            }
            "save" => println!("saved"),
            "revert" => println!("revert skipped: edits are saved transactionally by command"),
            other => bail!("unknown command: {other}"),
        }
    }
    Ok(())
}

fn parse_shell_addr(value: &str, current_addr: u64) -> Result<u64> {
    if let Some(offset) = value.strip_prefix("+0x") {
        return Ok(current_addr + u64::from_str_radix(offset, 16)?);
    }
    if let Some(hex) = value.strip_prefix("0x") {
        return Ok(u64::from_str_radix(hex, 16)?);
    }
    bail!("unsupported address expression: {value}")
}
