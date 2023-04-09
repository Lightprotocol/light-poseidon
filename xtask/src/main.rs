use clap::Parser;

mod generate_parameters;
mod generate_readme;

#[derive(Parser)]
pub struct XtaskOptions {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    GeneratePoseidonParameters(generate_parameters::Options),
    /// Generate the README.md file.
    GenerateReadme(generate_readme::Options),
}

fn main() -> Result<(), anyhow::Error> {
    let opts = XtaskOptions::parse();

    match opts.command {
        Command::GeneratePoseidonParameters(opts) => {
            generate_parameters::generate_parameters(opts)?
        }
        Command::GenerateReadme(opts) => generate_readme::generate_readme(opts)?,
    }

    Ok(())
}
