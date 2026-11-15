///|
fn required_env(name : String) -> String {
  match @env.get_env_var(name) {
    Some(value) => value
    None => abort("missing environment variable: " + name)
  }
}

///|
fn main {
  let token = @biscuit.token_from_base64url(required_env("BISCUIT_TOKEN")) catch {
    _ => {
      println("DENY")
      return
    }
  }
  let root_key = @hex.decode(required_env("BISCUIT_ROOT_PUBLIC_KEY")) catch {
    _ => {
      println("DENY")
      return
    }
  }
  let policy = @biscuit.parse_policy_body(
    required_env("BISCUIT_POLICY"),
    @biscuit.Allow,
  ) catch {
    _ => {
      println("DENY")
      return
    }
  }
  let allowed = try {
    @biscuit.authorize_token(token, root_key, [], [], [policy], 10000, 1000)
    true
  } catch {
    _ => false
  }
  println(if allowed { "ALLOW" } else { "DENY" })
}
