use clap::Parser;

mod generate_parameters;

#[derive(Parser)]
pub struct XtaskOptions {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    GeneratePoseidonParameters(generate_parameters::Options),
}

fn main() -> Result<(), anyhow::Error> {
    let opts = XtaskOptions::parse();

    match opts.command {
        Command::GeneratePoseidonParameters(opts) => {
            generate_parameters::generate_parameters(opts)?
        }
    }

    Ok(())
}
