use std::path::PathBuf;

use anyhow::{bail, Result};
use rustyline::DefaultEditor;

pub fn run(project: PathBuf) -> Result<()> {
    let mut rl = DefaultEditor::new()?;
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
            "info" => println!("{:#?}", ura_core::commands::info(&project)?),
            "funcs" => println!("{:#?}", ura_core::commands::functions(&project)?),
            "strings" => println!(
                "{:#?}",
                ura_core::commands::strings(&project, parts.next())?
            ),
            "diagnostics" => println!("{:#?}", ura_core::commands::diagnostics(&project)?),
            "disasm" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                current_addr = addr;
                println!("{:#?}", ura_core::commands::disasm(&project, addr, 16)?);
            }
            "xrefs" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                current_addr = addr;
                println!("{:#?}", ura_core::commands::xrefs(&project, addr)?);
            }
            "rename" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let name = parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing name"))?;
                ura_core::commands::rename(&project, addr, name)?;
            }
            "comment" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let text = parts.collect::<Vec<_>>().join(" ");
                ura_core::commands::comment(&project, addr, &text)?;
            }
            "make-func" => {
                let addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                ura_core::commands::make_function(&project, addr)?;
            }
            "set-func-range" => {
                let func_addr = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let start = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                let end = parse_shell_addr(parts.next().unwrap_or(""), current_addr)?;
                ura_core::commands::set_function_range(&project, func_addr, start, end)?;
            }
            "reanalyze" => ura_core::commands::reanalyze(&project)?,
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
