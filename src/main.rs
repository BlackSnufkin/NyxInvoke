#![allow(non_snake_case, non_camel_case_types,dead_code,unused_imports)]

mod common;

use clap::Parser;
use common::*;

fn main() {
    let cli = Cli::parse();

    let result = match cli.mode {
        Mode::Clr { args, base, key, iv, assembly } => {
            execute_clr_mode(args, base, key, iv, assembly)
        },
        Mode::Ps { command, script } => {
            execute_ps_mode(command, script)
        },
        Mode::Bof { args, base, key, iv, bof } => {
            execute_bof_mode(args, base, key, iv, bof)
        },
    };

    match result {
        Ok(()) => println!("Operation completed successfully."),
        Err(e) => eprintln!("Error: {}", e),
    }
}