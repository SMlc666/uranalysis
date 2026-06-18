mod output;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use ura_cli::{shell, SessionProject};

#[derive(Parser)]
#[command(name = "ura")]
#[command(about = "Ura binary analysis CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    New {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    Analyze {
        project: PathBuf,
    },
    Info {
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Funcs {
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Disasm {
        project: PathBuf,
        addr: String,
        #[arg(long, default_value_t = 16)]
        count: usize,
        #[arg(long)]
        json: bool,
    },
    Xrefs {
        project: PathBuf,
        addr: String,
        #[arg(long)]
        json: bool,
    },
    Strings {
        project: PathBuf,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Diagnostics {
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Rename {
        project: PathBuf,
        addr: String,
        name: String,
    },
    Comment {
        project: PathBuf,
        addr: String,
        text: String,
    },
    MakeFunc {
        project: PathBuf,
        addr: String,
    },
    SetFuncRange {
        project: PathBuf,
        func_addr: String,
        start: String,
        end: String,
    },
    Shell {
        project: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::New { input, output } => {
            let mut project = SessionProject::create(&input, &output)?;
            project.refresh()?;
            project.save()?;
        }
        Command::Analyze { project } => {
            let mut project = SessionProject::load(&project)?;
            project.force_reanalyze()?;
            project.save()?;
        }
        Command::Info { project, json } => {
            let project = SessionProject::load(&project)?;
            let info = serde_json::json!({
                "format": project.stored.source.format,
                "architecture": project.stored.source.architecture,
                "profile": project.stored.source.profile,
                "entry": project.stored.source.entry,
                "functions": project.session.state.functions.len(),
                "xrefs": project.session.state.xrefs.len(),
                "diagnostics": project.session.state.diagnostics.len(),
            });
            if json {
                output::print_json(&info)?;
            } else {
                println!("{info:#?}");
            }
        }
        Command::Funcs { project, json } => {
            let project = SessionProject::load(&project)?;
            let funcs = project.session.state.functions;
            if json {
                output::print_json(&funcs)?;
            } else {
                println!("{funcs:#?}");
            }
        }
        Command::Disasm {
            project,
            addr,
            count,
            json,
        } => {
            let project = SessionProject::load(&project)?;
            let addr = parse_addr(&addr)?;
            let rows = project
                .session
                .state
                .instructions
                .iter()
                .filter(|insn| insn.addr >= addr)
                .take(count)
                .cloned()
                .collect::<Vec<_>>();
            if json {
                output::print_json(&rows)?;
            } else {
                println!("{rows:#?}");
            }
        }
        Command::Xrefs {
            project,
            addr,
            json,
        } => {
            let addr = parse_addr(&addr)?;
            let project = SessionProject::load(&project)?;
            let rows = project
                .session
                .state
                .xrefs
                .iter()
                .filter(|xref| xref.to_addr == addr || xref.from_addr == addr)
                .cloned()
                .collect::<Vec<_>>();
            if json {
                output::print_json(&rows)?;
            } else {
                println!("{rows:#?}");
            }
        }
        Command::Strings {
            project,
            filter,
            json,
        } => {
            let project = SessionProject::load(&project)?;
            let filter = filter.unwrap_or_default();
            let rows = project
                .session
                .state
                .strings
                .iter()
                .filter(|s| s.value.contains(&filter))
                .cloned()
                .collect::<Vec<_>>();
            if json {
                output::print_json(&rows)?;
            } else {
                println!("{rows:#?}");
            }
        }
        Command::Diagnostics { project, json } => {
            let project = SessionProject::load(&project)?;
            let rows = project.session.state.diagnostics;
            if json {
                output::print_json(&rows)?;
            } else {
                println!("{rows:#?}");
            }
        }
        Command::Rename {
            project,
            addr,
            name,
        } => {
            let mut project = SessionProject::load(&project)?;
            project.session.rename(parse_addr(&addr)?, &name)?;
            project.refresh()?;
            project.save()?;
        }
        Command::Comment {
            project,
            addr,
            text,
        } => {
            let mut project = SessionProject::load(&project)?;
            project.session.comment(parse_addr(&addr)?, &text)?;
            project.refresh()?;
            project.save()?;
        }
        Command::MakeFunc { project, addr } => {
            let mut project = SessionProject::load(&project)?;
            let addr = parse_addr(&addr)?;
            project
                .session
                .update_manual_function_range(addr, addr, addr + 4)?;
            project.refresh()?;
            project.save()?;
        }
        Command::SetFuncRange {
            project,
            func_addr,
            start,
            end,
        } => {
            let mut project = SessionProject::load(&project)?;
            let func_addr = parse_addr(&func_addr)?;
            project.session.update_manual_function_range(
                func_addr,
                parse_addr(&start)?,
                parse_addr(&end)?,
            )?;
            project.refresh()?;
            project.save()?;
        }
        Command::Shell { project } => shell::run(project)?,
    }
    Ok(())
}

fn parse_addr(value: &str) -> Result<u64> {
    Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
}
