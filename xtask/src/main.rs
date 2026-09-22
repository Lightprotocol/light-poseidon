use clap::Parser;

mod generate_parameters;
mod sparse_mds;

#[derive(Parser)]
pub struct XtaskOptions {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    GeneratePoseidonParameters(generate_parameters::Options),
    GenerateSparseMdsParameters(sparse_mds::generate::Options),
}

fn main() -> Result<(), anyhow::Error> {
    let opts = XtaskOptions::parse();

    match opts.command {
        Command::GeneratePoseidonParameters(opts) => {
            generate_parameters::generate_parameters(opts)?
        }
        Command::GenerateSparseMdsParameters(opts) => {
            sparse_mds::generate::generate_sparse_mds_parameters(opts)?
        }
    }

    Ok(())
}
