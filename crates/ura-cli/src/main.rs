mod output;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use ura_cli::shell;

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
        Command::New { input, output } => ura_core::commands::new_project(input, output)?,
        Command::Analyze { project } => ura_core::commands::reanalyze(project)?,
        Command::Info { project, json } => {
            let info = ura_core::commands::info(project)?;
            if json {
                output::print_json(&info)?;
            } else {
                println!("{info:#?}");
            }
        }
        Command::Funcs { project, json } => {
            let funcs = ura_core::commands::functions(project)?;
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
            let rows = ura_core::commands::disasm(project, parse_addr(&addr)?, count)?;
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
            let rows = ura_core::commands::xrefs(project, parse_addr(&addr)?)?;
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
            let rows = ura_core::commands::strings(project, filter.as_deref())?;
            if json {
                output::print_json(&rows)?;
            } else {
                println!("{rows:#?}");
            }
        }
        Command::Diagnostics { project, json } => {
            let rows = ura_core::commands::diagnostics(project)?;
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
        } => ura_core::commands::rename(project, parse_addr(&addr)?, &name)?,
        Command::Comment {
            project,
            addr,
            text,
        } => ura_core::commands::comment(project, parse_addr(&addr)?, &text)?,
        Command::MakeFunc { project, addr } => {
            ura_core::commands::make_function(project, parse_addr(&addr)?)?
        }
        Command::SetFuncRange {
            project,
            func_addr,
            start,
            end,
        } => {
            ura_core::commands::set_function_range(
                project,
                parse_addr(&func_addr)?,
                parse_addr(&start)?,
                parse_addr(&end)?,
            )?;
        }
        Command::Shell { project } => shell::run(project)?,
    }
    Ok(())
}

fn parse_addr(value: &str) -> Result<u64> {
    Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
}
