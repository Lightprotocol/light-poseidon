use std::{
    env,
    fs::File,
    io::{self, prelude::*},
    path::PathBuf,
    process::{Command, Stdio},
    thread::spawn,
};

use ark_ff::{BigInteger, BigInteger256};
use clap::{Parser};

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(long)]
    path: Option<PathBuf>,
}
#[allow(dead_code)]
fn rustfmt(code: String) -> Result<Vec<u8>, anyhow::Error> {
    let mut cmd = match env::var_os("RUSTFMT") {
        Some(r) => Command::new(r),
        None => Command::new("rustfmt"),
    };

    let mut cmd = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdin = cmd.stdin.take().unwrap();
    let mut stdout = cmd.stdout.take().unwrap();

    let stdin_handle = spawn(move || {
        stdin.write_all(code.as_bytes()).unwrap();
    });

    let mut formatted_code = vec![];
    io::copy(&mut stdout, &mut formatted_code)?;

    let _ = cmd.wait();
    stdin_handle.join().unwrap();

    Ok(formatted_code)
}
use std::path::Path;
pub fn generate_parameters(_opts: Options) -> Result<(), anyhow::Error> {
    // git clone hadehash into target
    // run create params script to compute files in target
    // loop over files in dir scripts/params/
    // the line after Round constants for GF(p):
    // remove [ ], split at , parse
    if !Path::new("./target/hadeshash").exists() {
        let _git_result = std::process::Command::new("git")
        .arg("clone")
        .arg("https://extgit.iaik.tugraz.at/krypto/hadeshash.git")
        .arg("./target/hadeshash")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| anyhow::format_err!("git clone failed: {}", e.to_string()))?;
    }
    let partial_rounds = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
    if !Path::new("./target/params").exists() {
        let _mkdir_result = std::process::Command::new("mkdir")
        .arg("./target/params")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| anyhow::format_err!("mkdir failed: {}", e.to_string()))?;
        
    }
    for i in 2..18 {
        let path = format!("./target/params/poseidon_params_bn254_x5_{}", i);

        if !Path::new(&path).exists() {
            println!("Generating Parameters partial rounds {} t = {}", partial_rounds [i-2],i );
            let arg = format!("./target/hadeshash/code/generate_parameters_grain.sage");

            let output = std::process::Command::new("sage")        
            .args([
                arg, String::from("1"), String::from("0"), String::from("254"),  format!("{}",i),  String::from("8"), format!("{}",partial_rounds[i - 2]), String::from("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"),
            ]).output()?;
            let mut file = File::create(&path)?;
            file.write_all(&output.stdout)?;
        }
    }

    let mut code = String::new();
    code += "
    //! Constants and MDS matrix for the BN254 curve with the following properties:
    //!
    //! * x^5 S-boxes
    //! * 3 prime fields (one zero prime field and two inputs from the caller)
    //! * 8 full rounds and 57 partial rounds
    //!
    //! Those parameters are used for our Poseidon hash implementation.
    //!
    //! They were generated using the official script from the Poseidon paper:
    //! [generate_parameters_grain.sage](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage)
    //! with the following parameters:
    //!
    //! ```bash
    //! sage generate_parameters_grain.sage 1 0 254 3 8 57 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    //! ```
    pub const FULL_ROUNDS: usize = 8;
    pub const PARTIAL_ROUNDS: [usize; 16] = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
    pub const WIDTH: usize = 3;
    pub const ALPHA: u64 = 5;

    /// Returns Poseidon parameters for the BN254 curve with the following
    /// properties:
    ///
    /// * x^5 S-boxes
    /// * 3 inputs (one input with zeros and two inputs from the syscall)
    /// * 8 full rounds and 57 partial rounds
    ///
    /// The argument of this macro is a type which implements
    /// [`ark_ff::PrimeField`](ark_ff::PrimeField).
    use ark_bn254::{Fr, FrParameters};
    use ark_ff::Fp256;
    use crate::PoseidonParameters;
    pub fn get_poseidon_parameters(t: u8) -> PoseidonParameters<Fp256<FrParameters>> {
    match t {
        0_u8..=1_u8 | 18_u8..=u8::MAX => {unimplemented!()}\n";
    for t in 2..18 {
        let path = [
            String::from("./target/params/poseidon_params_bn254_x5_"),
            t.to_string()
        ]
        .concat();
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let lines = contents.lines();

        for line in lines {

            if line.starts_with("['") {
                code += &[
                    String::from("\t"),
                    t.to_string(),
                    String::from(
                        " => {{
                        let ark = vec![\n",
                    ),
                ]
                .concat();

                let line_processed = line
                    .strip_prefix("[")
                    .unwrap()
                    .strip_suffix("]")
                    .unwrap()
                    .trim()
                    .split(", ")
                    .collect::<Vec<&str>>();
                let _x: Vec<&str> = line_processed
                    .iter()
                    .map(|elem| {
                        let str = String::from(
                            elem.strip_prefix("'").unwrap().strip_suffix("'").unwrap(),
                        );
                        code += &get_fr_string(&str);
                        return "1";
                    })
                    .collect();
                code += "\t\t\t\t];\n";
            } else if line.starts_with(" [['") {
                code += &String::from("\t\t\t\tlet mds = vec![\n");
                let line_processed = line.split("[").collect::<Vec<&str>>();

                let _x: Vec<&str> = line_processed
                    .iter()
                    .map(|e| {
                        if e.starts_with("'") {
                            code += &String::from("\t\t\t\t\tvec![\n");
                        }

                        for elem in e.split("'") {
                            if elem.starts_with("0x") {
                                code += &get_fr_string(&String::from(elem));
                            }
                        }
                        if e.starts_with("'") {
                            code += &String::from("\t\t\t\t\t],\n");
                        }

                        return "1";
                    })
                    .collect();
                code += &String::from("\t\t];\n");
            }
        }
        code += &[
            String::from(
                "
            crate::PoseidonParameters::new(
            ark,
            mds,
            FULL_ROUNDS,
            PARTIAL_ROUNDS[",
            ),
            (t - 2).to_string(),
            String::from(
                "],
            t.into(),
            ALPHA,
            )\n",
            ),
        ]
        .concat();
        code += "\t}}\n";
    }

    code += "\t}\n}\n";

    let path = "./light-poseidon/src/parameters/bn254_x5.rs";
    let mut file = File::create(&path)?;
    file.write_all(b"// This file is generated by xtask. Do not edit it manually.\n\n")?;
    // write!(file, "{}", code)?;
    file.write_all(&rustfmt(code.to_string())?)?;

    println!("Poseidon Parameters written to {:?}", path);


    Ok(())
}

fn get_fr_string(string: &String) -> String {
    let mut x = BigInteger256::new([0u64, 0u64, 0u64, 0u64]);
    let mut bytes = hex::decode(string.split_at(2).1).unwrap();
    let mut tmp_str = String::from("Fr::from(ark_ff::BigInteger256::new([\n");
    bytes.reverse();

    BigInteger256::read_le(&mut x, &mut bytes.as_slice()).unwrap();

    for i in 0..4 {
        tmp_str += &[
            String::from("\t"),
            u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap()).to_string(),
            String::from(",\n"),
        ]
        .concat();
    }

    tmp_str += "])),\n";
    tmp_str
}
