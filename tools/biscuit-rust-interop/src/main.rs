use std::env;
use std::error::Error;

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine as _;
use biscuit_auth::{
    builder::{Algorithm, AuthorizerBuilder, BlockBuilder},
    Biscuit, PrivateKey, PublicKey, UnverifiedBiscuit,
};

const ROOT_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const EXTERNAL_SEED_HEX: &str = "4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b";

fn required(name: &str) -> Result<String, Box<dyn Error>> {
    env::var(name).map_err(|error| format!("missing {name}: {error}").into())
}

fn private_key(seed_hex: &str) -> Result<PrivateKey, Box<dyn Error>> {
    let seed = hex::decode(seed_hex)?;
    Ok(PrivateKey::from_bytes(&seed, Algorithm::Ed25519)?)
}

fn public_key(key_hex: &str) -> Result<PublicKey, Box<dyn Error>> {
    let key = hex::decode(key_hex)?;
    Ok(PublicKey::from_bytes(&key, Algorithm::Ed25519)?)
}

fn authorize(token: &Biscuit, query: &str) -> Result<bool, Box<dyn Error>> {
    let mut authorizer = AuthorizerBuilder::new()
        .code(format!("allow if {query};"))?
        .build(token)?;
    Ok(authorizer.authorize().is_ok())
}

fn run_authorize() -> Result<(), Box<dyn Error>> {
    let root = public_key(&required("BISCUIT_ROOT_PUBLIC_KEY")?)?;
    let token = Biscuit::from_base64(required("BISCUIT_TOKEN")?, root)?;
    let allowed = authorize(&token, &required("BISCUIT_POLICY")?)?;
    println!("{}", if allowed { "ALLOW" } else { "DENY" });
    Ok(())
}

fn run_parse_datalog() -> Result<(), Box<dyn Error>> {
    let _block = BlockBuilder::new().code(required("BISCUIT_DATALOG_BLOCK")?)?;
    let _authorizer = AuthorizerBuilder::new().code(required("BISCUIT_DATALOG_POLICY")?)?;
    println!("PARSED");
    Ok(())
}

fn run_decision() -> Result<(), Box<dyn Error>> {
    use biscuit_auth::error::{Logic, MatchedPolicy, Token};
    let root = public_key(&required("BISCUIT_ROOT_PUBLIC_KEY")?)?;
    let token = Biscuit::from_base64(required("BISCUIT_TOKEN")?, root)?;
    let mut source = String::new();
    for name in [
        "BISCUIT_FACTS",
        "BISCUIT_RULES",
        "BISCUIT_CHECKS",
        "BISCUIT_POLICIES",
    ] {
        for line in required(name)?
            .lines()
            .filter(|line| !line.trim().is_empty())
        {
            source.push_str(line.trim());
            source.push_str(";\n");
        }
    }
    let mut authorizer = AuthorizerBuilder::new().code(source)?.build(&token)?;
    let result = match authorizer.authorize() {
        Ok(index) => format!("ALLOW:{index}"),
        Err(Token::FailedLogic(Logic::Unauthorized { checks, .. })) if !checks.is_empty() => {
            "CHECK_FAILED".to_owned()
        }
        Err(Token::FailedLogic(Logic::NoMatchingPolicy { checks })) if !checks.is_empty() => {
            "CHECK_FAILED".to_owned()
        }
        Err(Token::FailedLogic(Logic::Unauthorized {
            policy: MatchedPolicy::Deny(index),
            ..
        })) => {
            format!("DENY:{index}")
        }
        Err(Token::FailedLogic(Logic::NoMatchingPolicy { .. })) => "NO_MATCH".to_owned(),
        Err(error) => return Err(error.into()),
    };
    println!("{result}");
    Ok(())
}

fn run_mint() -> Result<(), Box<dyn Error>> {
    let root = private_key(ROOT_SEED_HEX)?;
    let authority = Biscuit::builder()
        .fact("interop_allow(true)")?
        .build(&root)?;
    let attenuation = BlockBuilder::new()
        .code("attenuated(true); check if attenuated(true) trusting previous;")?;
    let attenuated = authority.append(attenuation)?;
    let sealed = attenuated.seal()?;

    println!("ROOT_PUBLIC_KEY={}", root.public().to_bytes_hex());
    println!("RUST_TOKEN={}", authority.to_base64()?);
    println!("RUST_ATTENUATED={}", attenuated.to_base64()?);
    println!("RUST_SEALED={}", sealed.to_base64()?);
    Ok(())
}

fn run_mint_third_party() -> Result<(), Box<dyn Error>> {
    let root = private_key(ROOT_SEED_HEX)?;
    let external = private_key(EXTERNAL_SEED_HEX)?;
    let external_public_hex = external.public().to_bytes_hex();
    let check = format!("check if read(true) trusting ed25519/{external_public_hex}");
    let base = Biscuit::builder().code(format!("{check};"))?.build(&root)?;
    if authorize(&base, "true")? {
        return Err("third-party check unexpectedly passed before signing".into());
    }

    let request = base.third_party_request()?;
    let block = BlockBuilder::new().fact("read(true)")?;
    let response = request.create_block(&external, block)?;
    let appended = base.append_third_party(external.public(), response)?;
    if !authorize(&appended, "true")? {
        return Err("Rust third-party block did not satisfy its check".into());
    }

    println!("ROOT_PUBLIC_KEY={}", root.public().to_bytes_hex());
    println!("EXTERNAL_PUBLIC_KEY={external_public_hex}");
    println!("RUST_THIRD_PARTY_BASE={}", base.to_base64()?);
    println!("RUST_THIRD_PARTY_APPENDED={}", appended.to_base64()?);
    Ok(())
}

fn run_append_moonbit_third_party() -> Result<(), Box<dyn Error>> {
    let root = public_key(&required("BISCUIT_ROOT_PUBLIC_KEY")?)?;
    let unverified = UnverifiedBiscuit::from_base64(required("BISCUIT_TOKEN")?)?;
    let base = unverified.clone().verify(root)?;
    if authorize(&base, "true")? {
        return Err("third-party check unexpectedly passed before signing".into());
    }

    let encoded = required("BISCUIT_THIRD_PARTY_CONTENTS")?;
    let contents = URL_SAFE.decode(encoded)?;
    let appended = unverified.append_third_party(&contents)?.verify(root)?;
    if !authorize(&appended, "true")? {
        return Err("MoonBit third-party block did not satisfy its check".into());
    }

    println!("BASE=DENY");
    println!("APPENDED=ALLOW");
    println!("APPENDED_TOKEN={}", appended.to_base64()?);
    Ok(())
}

// Reference-only fixtures. Passing this matrix does not mean MoonBit supports P-256.
fn run_algorithm_matrix() -> Result<(), Box<dyn Error>> {
    use biscuit_auth::datalog::SymbolTable;
    let algorithms = [Algorithm::Ed25519, Algorithm::Secp256r1];
    for (root_index, root_algorithm) in algorithms.iter().enumerate() {
        for (next_index, next_algorithm) in algorithms.iter().enumerate() {
            for (external_index, external_algorithm) in algorithms.iter().enumerate() {
                let root = PrivateKey::from_bytes(&[0x21; 32], *root_algorithm)?;
                let next = PrivateKey::from_bytes(&[0x22; 32], *next_algorithm)?;
                let following_algorithm =
                    if root_index == next_index && root_index == external_index {
                        *next_algorithm
                    } else {
                        algorithms[1 - next_index]
                    };
                let following = PrivateKey::from_bytes(&[0x23; 32], following_algorithm)?;
                let external = PrivateKey::from_bytes(&[0x24; 32], *external_algorithm)?;
                let final_key = PrivateKey::from_bytes(&[0x25; 32], *root_algorithm)?;
                let name = if external_index == 0 {
                    "ed25519"
                } else {
                    "secp256r1"
                };
                let scope = format!("{name}/{}", external.public().to_bytes_hex());
                let base = Biscuit::builder()
                    .code(format!("right(\"read\"); check if approval(true) trusting {scope};"))?
                    .build_with_key_pair(&root, SymbolTable::default(), &next)?;
                if authorize(&base, "right(\"read\")")? {
                    return Err("missing third-party approval was accepted".into());
                }
                let attenuated = base.append_with_key(
                    &following,
                    BlockBuilder::new().code("check if right(\"read\");")?,
                )?;
                let response = attenuated.third_party_request()?.create_block(
                    &external,
                    BlockBuilder::new().fact("approval(true)")?,
                )?;
                let approved =
                    attenuated.append_third_party_with_key(external.public(), response, final_key)?;
                let sealed = approved.seal()?;
                for token in [&approved, &sealed] {
                    let verified = Biscuit::from_base64(token.to_base64()?, root.public())?;
                    if !authorize(&verified, "right(\"read\")")?
                        || authorize(&verified, "right(\"write\")")?
                    {
                        return Err("algorithm matrix authorization mismatch".into());
                    }
                }
                println!("REFERENCE_MATRIX {root_index}{next_index}{external_index}: PASS");
                println!("REFERENCE_ROOT={}", root.public().to_bytes_hex());
                println!("REFERENCE_TOKEN={}", approved.to_base64()?);
                println!("REFERENCE_SEALED={}", sealed.to_base64()?);
            }
        }
    }
    println!("Rust-only algorithm reference matrix: 8/8 passed");
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    match env::args().nth(1).as_deref() {
        Some("authorize") => run_authorize(),
        Some("decision") => run_decision(),
        Some("parse-datalog") => run_parse_datalog(),
        Some("mint") => run_mint(),
        Some("mint-third-party") => run_mint_third_party(),
        Some("algorithm-matrix") => run_algorithm_matrix(),
        Some("append-moonbit-third-party") => run_append_moonbit_third_party(),
        _ => {
            Err("expected authorize, parse-datalog, mint, mint-third-party, or append-moonbit-third-party".into())
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("biscuit-rust interoperability helper failed: {error}");
        std::process::exit(1);
    }
}
