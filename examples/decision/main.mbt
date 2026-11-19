///|
fn required(name : String) -> String {
  @env.get_env_var(name).unwrap_or_else(() => abort("missing " + name))
}

///|
fn lines(name : String) -> Array[String] {
  required(name)
  .split("\n")
  .map(line => line.trim().to_owned())
  .filter(line => line != "")
  .collect()
}

///|
fn main {
  try {
    let token = @biscuit.token_from_base64url(required("BISCUIT_TOKEN"))
    let root = @hex.decode(required("BISCUIT_ROOT_PUBLIC_KEY"))
    let facts = lines("BISCUIT_FACTS").map(@biscuit.parse_fact)
    let rules = lines("BISCUIT_RULES").map(@biscuit.parse_rule)
    let checks = lines("BISCUIT_CHECKS").map(@biscuit.parse_check)
    let policies = lines("BISCUIT_POLICIES").map(@biscuit.parse_policy)
    try {
      let result = @biscuit.authorize_token_detailed(
        token,
        root,
        facts,
        rules,
        checks,
        policies,
        1000,
        100,
        @biscuit.ExternalFunctions::{ unary: Map([]), binary: Map([]), },
      )
      let kind = match result.decision {
        @biscuit.Allow => "ALLOW"
        @biscuit.Deny => "DENY"
      }
      println(kind + ":" + result.policy_index.to_string())
    } catch {
      @biscuit.FailedCheck(_) => println("CHECK_FAILED")
      @biscuit.NoMatchingPolicy => println("NO_MATCH")
      _ => abort("unexpected authorization error in differential fixture")
    }
  } catch {
    _ => abort("invalid differential fixture")
  }
}
