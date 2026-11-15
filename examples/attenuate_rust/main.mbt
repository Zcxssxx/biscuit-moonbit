///|
fn required_env(name : String) -> String {
  match @env.get_env_var(name) {
    Some(value) => value
    None => abort("missing environment variable: " + name)
  }
}

///|
fn main {
  try {
    let token = @biscuit.token_from_base64url(required_env("BISCUIT_TOKEN"))
    let root_key = @hex.decode(required_env("BISCUIT_ROOT_PUBLIC_KEY"))
    let next_seed = match @env.rand(32) {
      Some(seed) => seed
      None => abort("operating system entropy source is unavailable")
    }
    let check = @biscuit.parse_check_body(
      "moonbit_attenuated(true) trusting previous",
      @biscuit.Any,
    )
    let attenuated = @biscuit.attenuate_block(
      token,
      root_key,
      [@biscuit.parse_fact("moonbit_attenuated(true)")],
      [],
      [check],
      [],
      6,
      next_seed,
    )
    println("MOONBIT_ATTENUATED=" + @biscuit.token_to_base64url(attenuated))
  } catch {
    _ => println("MoonBit failed to attenuate the Rust token")
  }
}
