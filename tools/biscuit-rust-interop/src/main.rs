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

fn run_mint() -> Result<(), Box<dyn Error>> {
    let root = private_key(ROOT_SEED_HEX)?;
    let authority = Biscuit::builder()
        .fact("interop_allow(true)")?
        .build(&root)?;
    let attenuation = BlockBuilder::new()
        .code("attenuated(true); check if attenuated(true) trusting previous;")?;
    let attenuated = authority.append(attenuation)?;

    println!("ROOT_PUBLIC_KEY={}", root.public().to_bytes_hex());
    println!("RUST_TOKEN={}", authority.to_base64()?);
    println!("RUST_ATTENUATED={}", attenuated.to_base64()?);
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

fn run() -> Result<(), Box<dyn Error>> {
    match env::args().nth(1).as_deref() {
        Some("authorize") => run_authorize(),
        Some("mint") => run_mint(),
        Some("mint-third-party") => run_mint_third_party(),
        Some("append-moonbit-third-party") => run_append_moonbit_third_party(),
        _ => {
            Err("expected authorize, mint, mint-third-party, or append-moonbit-third-party".into())
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("biscuit-rust interoperability helper failed: {error}");
        std::process::exit(1);
    }
}
