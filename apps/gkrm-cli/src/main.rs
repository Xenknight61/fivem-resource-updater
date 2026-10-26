use clap::Parser;
use gkrm_cli::{run, Cli, EXIT_INVALID};

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if error.kind() == clap::error::ErrorKind::DisplayHelp
                || error.kind() == clap::error::ErrorKind::DisplayVersion
            {
                let _ = error.print();
                std::process::exit(0);
            }
            if is_json_format_requested() {
                println!(
                    "{{\n  \"schema_version\": 1,\n  \"outcome\": \"invalid_usage\",\n  \"error\": \"invalid_usage\",\n  \"code\": \"invalid_usage\",\n  \"message\": \"Invalid command usage.\"\n}}"
                );
            } else {
                let _ = error.print();
            }
            std::process::exit(EXIT_INVALID);
        }
    };

    match run(cli) {
        Ok((output, code)) => {
            print!("{output}");
            if code != 0 {
                std::process::exit(code);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(error.exit_code());
        }
    }
}

fn is_json_format_requested() -> bool {
    let args: Vec<String> = std::env::args().collect();
    for window in args.windows(2) {
        if window[0] == "--format" && window[1] == "json" {
            return true;
        }
    }
    for arg in &args {
        if arg == "--format=json" {
            return true;
        }
    }
    false
}
