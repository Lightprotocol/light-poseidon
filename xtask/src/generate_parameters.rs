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

const FIELD: &str = "1";
const SBOX: &str = "0";
const FIELD_ELEMENT_BIT_SIZE: &str = "254";
const FULL_ROUNDS: &str = "8";
const PARTIAL_ROUNDS: [u8; 12] = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65];
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
            .map_err(|e| anyhow::format_err!("git clone failed: {}", e))?;
    }
    if !Path::new("./target/params").exists() {
        let _mkdir_result = std::process::Command::new("mkdir")
            .arg("./target/params")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|e| anyhow::format_err!("mkdir failed: {}", e))?;
    }
    for i in 2..14 {
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
    /// Number of full rounds, identical for every supported width.
    pub const FULL_ROUNDS: usize = 8;
    /// S-box exponent.
    pub const ALPHA: u64 = 5;

    use ark_bn254::Fr;
    use ark_ff::BigInteger256;
    use crate::{PoseidonError, PoseidonParameters};

";
    for t in 2..14 {
        let path = format!("./target/params/poseidon_params_bn254_x5_{}", t);
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Round constants, in round-major order, and the MDS matrix flattened
        // row-major. Both are emitted as `static` arrays so that the Montgomery
        // conversion happens at compile time via the const fn `Fr::new`.
        let mut ark: Vec<String> = Vec::new();
        let mut mds: Vec<String> = Vec::new();

        for line in contents.lines() {
            if line.starts_with("['") {
                let stripped = line
                    .strip_prefix('[')
                    .and_then(|l| l.strip_suffix(']'))
                    .ok_or_else(|| anyhow::format_err!("malformed ark line for t={}", t))?;
                for elem in stripped.trim().split(", ") {
                    let value = elem
                        .strip_prefix('\'')
                        .and_then(|e| e.strip_suffix('\''))
                        .ok_or_else(|| anyhow::format_err!("malformed ark entry for t={}", t))?;
                    ark.push(get_fr_string(value));
                }
            } else if line.starts_with(" [['") {
                for elem in line.split('\'') {
                    if elem.starts_with("0x") {
                        mds.push(get_fr_string(elem));
                    }
                }
            }
        }

        let expected_mds = t * t;
        if mds.len() != expected_mds {
            return Err(anyhow::format_err!(
                "t={}: expected {} MDS entries, parsed {}",
                t,
                expected_mds,
                mds.len()
            ));
        }
        let expected_ark = t * (8 + PARTIAL_ROUNDS[t - 2] as usize);
        if ark.len() != expected_ark {
            return Err(anyhow::format_err!(
                "t={}: expected {} round constants, parsed {}",
                t,
                expected_ark,
                ark.len()
            ));
        }

        code += &format!(
            "/// Round constants for width {}: {} rounds x {} lanes.\n",
            t,
            8 + PARTIAL_ROUNDS[t - 2] as usize,
            t
        );
        code += &format!("pub static ARK_{}: [Fr; {}] = [\n", t, ark.len());
        for entry in &ark {
            code += entry;
        }
        code += "];\n\n";

        code += &format!("/// MDS matrix for width {}, flattened row-major.\n", t);
        code += &format!("pub static MDS_{}: [Fr; {}] = [\n", t, mds.len());
        for entry in &mds {
            code += entry;
        }
        code += "];\n\n";
    }

    code += "/// Returns the Circom-compatible BN254 x^5 parameters for state width `t`.\n";
    code += "///\n";
    code += "/// The returned parameters borrow `'static` data, so this performs no\n";
    code += "/// allocation and no field conversion. Dimensions are fixed when this\n";
    code += "/// file is generated, so they are not re-checked on every call.\n";
    code +=
        "pub fn get_poseidon_parameters(t: u8) -> Result<PoseidonParameters<Fr>, PoseidonError> {\n";
    code += "    match t {\n";
    for t in 2..14 {
        code += &format!(
            "        {} => Ok(PoseidonParameters::new_unchecked(\n            &ARK_{},\n            &MDS_{},\n            FULL_ROUNDS,\n            {},\n            {},\n            ALPHA,\n        )),\n",
            t,
            t,
            t,
            PARTIAL_ROUNDS[t - 2],
            t
        );
    }
    code += "        _ => Err(PoseidonError::InvalidWidthCircom {\n";
    code += "            width: t as usize,\n";
    code += "            max_limit: 13usize,\n";
    code += "        }),\n";
    code += "    }\n";
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
        .map_err(|e| anyhow::format_err!("cargo fmt failed: {}", e))?;
    Ok(())
}

/// Emits one field element as a `const`-evaluable `Fr`.
///
/// `Fp::new` is a const fn that performs the Montgomery reduction at compile
/// time, unlike `From<BigInt>`, which calls `from_bigint` at runtime. Emitting
/// `Fr::new` therefore moves the whole conversion out of the hot path.
fn get_fr_string(string: &str) -> String {
    let mut bytes = hex::decode(string.split_at(2).1).unwrap();
    bytes.reverse();

    // A short input would leave the high limbs zero and emit a wrong constant.
    // Fail loudly instead: a silently incorrect parameter is far worse than a
    // crashed generator.
    assert_eq!(
        bytes.len(),
        32,
        "expected a 32-byte field constant, got {} bytes from {string}",
        bytes.len()
    );

    let mut limbs = [0u64; 4];
    let (chunks, _rest) = bytes.as_chunks::<8>();
    for (limb, chunk) in limbs.iter_mut().zip(chunks) {
        *limb = u64::from_le_bytes(*chunk);
    }
    let [a, b, c, d] = limbs;

    format!("    Fr::new(BigInteger256::new([{a}, {b}, {c}, {d}])),\n")
}
