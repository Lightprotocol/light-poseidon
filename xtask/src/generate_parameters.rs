use std::{
    env,
    fs::File,
    io::{self, prelude::*},
    path::PathBuf,
    process::{Command, Stdio},
    thread::spawn,
};

use clap::Parser;

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

const MAX_SOLANA_LIMIT: usize = 14;
const FIELD: &str = "1";
const SBOX: &str = "0";
const FIELD_ELEMENT_BIT_SIZE: &str = "254";
const FULL_ROUNDS: &str = "8";
const PARTIAL_ROUNDS: [u8; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];
const MODULUS_HEX: &str = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
#[allow(clippy::needless_return)]
pub fn generate_parameters(_opts: Options) -> Result<(), anyhow::Error> {
    // git clone hadehash into target
    // create params to compute files in target
    // loop over files in dir target/params/
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
    if !Path::new("./target/params").exists() {
        let _mkdir_result = std::process::Command::new("mkdir")
            .arg("./target/params")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|e| anyhow::format_err!("mkdir failed: {}", e.to_string()))?;
    }
    for i in 2..17 {
        let path = format!("./target/params/poseidon_params_bn254_x5_{}", i);

        if !Path::new(&path).exists() {
            println!(
                "Generating Parameters partial rounds {} t = {}",
                PARTIAL_ROUNDS[i - 2],
                i
            );
            let arg = "./target/hadeshash/code/generate_parameters_grain.sage".to_string();

            let output = std::process::Command::new("sage")
                .args([
                    arg,
                    FIELD.to_string(),
                    SBOX.to_string(),
                    FIELD_ELEMENT_BIT_SIZE.to_string(),
                    format!("{}", i),
                    FULL_ROUNDS.to_string(),
                    format!("{}", PARTIAL_ROUNDS[i - 2]),
                    MODULUS_HEX.to_string(),
                ])
                .output()?;
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
    pub const PARTIAL_ROUNDS: [usize; 15] = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64];
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
    use ark_ff::PrimeField;
    use crate::{PoseidonParameters, PoseidonError};
    // to avoid warnings when width_limit_13 feature is used
    #[allow(unused_variables)]
    pub fn get_poseidon_parameters<F: PrimeField + std::convert::From<ark_ff::BigInteger256>>(t: u8) -> Result<PoseidonParameters<F>, PoseidonError> {
    if t == 0_u8 {
        #[cfg(not(feature = \"width_limit_13\"))]
        return Err(PoseidonError::InvalidWidthCircom {
            width: t as usize,
            max_limit: 16usize,
        });
        #[cfg(feature = \"width_limit_13\")]
        return Err(PoseidonError::InvalidWidthCircom {
            width: t as usize,
            max_limit: 13usize,
        });\n
    }\n";
    for t in 2..17 {
        let path = format!("./target/params/poseidon_params_bn254_x5_{}", t);
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let lines = contents.lines();

        for line in lines {
            if line.starts_with("['") {
                code += &[
                    String::from("\telse if "),
                    t.to_string(),
                    String::from(
                        " == t {
                        let ark = vec![\n",
                    ),
                ]
                .concat();

                let line_processed = line
                    .strip_prefix('[')
                    .unwrap()
                    .strip_suffix(']')
                    .unwrap()
                    .trim()
                    .split(", ")
                    .collect::<Vec<&str>>();
                let _x: Vec<&str> = line_processed
                    .iter()
                    .map(|elem| {
                        let str = String::from(
                            elem.strip_prefix('\'').unwrap().strip_suffix('\'').unwrap(),
                        );
                        code += &get_fr_string(&str);

                        return "1";
                    })
                    .collect();
                code += "\t\t\t\t];\n";
            } else if line.starts_with(" [['") {
                code += &String::from("\t\t\t\tlet mds = vec![\n");
                let line_processed = line.split('[').collect::<Vec<&str>>();

                let _x: Vec<&str> = line_processed
                    .iter()
                    .map(|e| {
                        if e.starts_with('\'') {
                            code += &String::from("\t\t\t\t\tvec![\n");
                        }

                        for elem in e.split('\'') {
                            if elem.starts_with("0x") {
                                code += &get_fr_string(&String::from(elem));
                            }
                        }
                        if e.starts_with('\'') {
                            code += &String::from("\t\t\t\t\t],\n");
                        }

                        return "1";
                    })
                    .collect();
                code += &String::from("\t\t];\n");
            }
        }
        if t < MAX_SOLANA_LIMIT {
            code += &format!(
                "return Ok(crate::PoseidonParameters::new(
                ark,
                mds,
                FULL_ROUNDS,
                PARTIAL_ROUNDS[{}],
                t.into(),
                ALPHA,
                ));\n",
                t - 2
            );
        } else {
            code += &format!(
                "#[cfg(feature = \"width_limit_13\")]
                return Err(PoseidonError::InvalidWidthCircom {{
                    width: {} as usize,
                    max_limit: 13usize,
                }});\n",
                t
            );

            code += &format!(
                "
                #[cfg(not(feature = \"width_limit_13\"))]
                return Ok(crate::PoseidonParameters::new(
                ark,
                mds,
                FULL_ROUNDS,
                PARTIAL_ROUNDS[{}],
                t.into(),
                ALPHA,
                ));\n",
                t - 2
            );
        }
        code += "\t}\n";
    }
    code += "else {
        #[cfg(not(feature = \"width_limit_13\"))]
        return Err(PoseidonError::InvalidWidthCircom {
            width: t as usize,
            max_limit: 16usize,
        });
        #[cfg(feature = \"width_limit_13\")]
        return Err(PoseidonError::InvalidWidthCircom {
            width: t as usize,
            max_limit: 13usize,
        });\n
    }";
    code += "}\n";

    let path = "./light-poseidon/src/parameters/bn254_x5.rs";
    let mut file = File::create(path)?;
    file.write_all(b"// This file is generated by xtask. Do not edit it manually.\n\n")?;
    // file.write_all(&rustfmt(code.to_string())?)?;
    write!(file, "{}", code)?;
    println!("Poseidon Parameters written to {:?}", path);
    std::process::Command::new("cargo")
        .arg("fmt")
        .output()
        .map_err(|e| anyhow::format_err!("cargo fmt failed: {}", e.to_string()))?;
    Ok(())
}

fn get_fr_string(string: &str) -> String {
    let mut bytes = hex::decode(string.split_at(2).1).unwrap();
    let mut tmp_str = String::from("F::from(ark_ff::BigInteger256::new([\n");
    bytes.reverse();
    for i in 0..4 {
        tmp_str += &format!(
            "\t{},\n",
            u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap())
        );
    }

    tmp_str += "])),\n";
    tmp_str
}
