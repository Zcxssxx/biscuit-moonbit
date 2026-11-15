///|
priv struct SampleAuthorizer {
  facts : Array[@biscuit.Fact]
  rules : Array[@biscuit.Rule]
  checks : Array[@biscuit.Check]
  policies : Array[@biscuit.Policy]
}

///|
fn sample_substring(source : String, needle : String) -> Bool {
  let chars = source.to_array()
  let target = needle.to_array()
  if target.length() == 0 {
    return true
  }
  if target.length() > chars.length() {
    return false
  }
  for i = 0; i + target.length() <= chars.length(); i = i + 1 {
    if String::from_array(chars[i:i + target.length()]) == needle {
      return true
    }
  }
  false
}

///|
fn split_sample_statements(source : String) -> Array[String] {
  let chars = source.to_array()
  let result : Array[String] = []
  let mut start = 0
  let mut depth = 0
  let mut quoted = false
  let mut escaped = false
  for i = 0; i < chars.length(); i = i + 1 {
    let character = chars[i]
    if quoted {
      if escaped {
        escaped = false
      } else if character == '\\' {
        escaped = true
      } else if character == '"' {
        quoted = false
      }
    } else if character == '"' {
      quoted = true
    } else if character == '(' || character == '[' || character == '{' {
      depth += 1
    } else if character == ')' || character == ']' || character == '}' {
      depth -= 1
    } else if character == ';' && depth == 0 {
      let statement = String::from_array(chars[start:i]).trim().to_owned()
      if statement != "" {
        result.push(statement)
      }
      start = i + 1
    }
  }
  let final_statement = String::from_array(chars[start:]).trim().to_owned()
  if final_statement != "" {
    result.push(final_statement)
  }
  result
}

///|
fn split_sample_alternatives(source : String) -> Array[String] {
  let chars = source.to_array()
  let result : Array[String] = []
  let mut start = 0
  let mut depth = 0
  let mut quoted = false
  let mut escaped = false
  let mut i = 0
  while i < chars.length() {
    let character = chars[i]
    if quoted {
      if escaped {
        escaped = false
      } else if character == '\\' {
        escaped = true
      } else if character == '"' {
        quoted = false
      }
    } else if character == '"' {
      quoted = true
    } else if character == '(' || character == '[' || character == '{' {
      depth += 1
    } else if character == ')' || character == ']' || character == '}' {
      depth -= 1
    } else if depth == 0 &&
      i + 4 <= chars.length() &&
      String::from_array(chars[i:i + 4]) == " or " {
      result.push(String::from_array(chars[start:i]).trim().to_owned())
      i += 3
      start = i + 1
    }
    i += 1
  }
  result.push(String::from_array(chars[start:]).trim().to_owned())
  result
}

///|
fn strip_sample_prefix(source : String, prefix : String) -> String {
  let chars = source.to_array()
  String::from_array(chars[prefix.to_array().length():]).trim().to_owned()
}

///|
fn parse_sample_authorizer(
  source : String,
) -> SampleAuthorizer raise @biscuit.TokenError {
  let facts : Array[@biscuit.Fact] = []
  let rules : Array[@biscuit.Rule] = []
  let checks : Array[@biscuit.Check] = []
  let policies : Array[@biscuit.Policy] = []
  for statement in split_sample_statements(source) {
    if statement.has_prefix("check if ") ||
      statement.has_prefix("check all ") ||
      statement.has_prefix("reject if ") {
      let (mode, prefix) = if statement.has_prefix("check all ") {
        (@biscuit.CheckMode::All, "check all ")
      } else if statement.has_prefix("reject if ") {
        (@biscuit.CheckMode::Reject, "reject if ")
      } else {
        (@biscuit.CheckMode::Any, "check if ")
      }
      let queries = split_sample_alternatives(
        strip_sample_prefix(statement, prefix),
      ).map(body => @biscuit.parse_query_body(body))
      checks.push(@biscuit.Check::{ mode, queries, })
    } else if statement.has_prefix("allow if ") ||
      statement.has_prefix("deny if ") {
      let (kind, prefix) = if statement.has_prefix("deny if ") {
        (@biscuit.Deny, "deny if ")
      } else {
        (@biscuit.Allow, "allow if ")
      }
      let queries = split_sample_alternatives(
        strip_sample_prefix(statement, prefix),
      ).map(body => @biscuit.parse_query_body(body))
      policies.push(@biscuit.Policy::{ kind, queries, })
    } else if sample_substring(statement, "<-") {
      rules.push(@biscuit.parse_rule(statement))
    } else {
      facts.push(@biscuit.parse_fact(statement))
    }
  }
  { facts, rules, checks, policies, }
}

///|
fn official_sample_externals() -> @biscuit.ExternalFunctions {
  @biscuit.ExternalFunctions::{
    unary: Map([("test", fn(_value) { @biscuit.Boolean(true) })]),
    binary: Map([
      (
        "test",
        fn(left, right) {
          match (left, right) {
            (@biscuit.Text("a"), @biscuit.Text("a")) =>
              @biscuit.Text("equal strings")
            _ => @biscuit.Text("different strings")
          }
        },
      ),
    ]),
  }
}

///|
fn run_official_sample(
  token_text : String,
  authorizer_text : String,
  enable_ffi : Bool,
) -> String {
  let token = @biscuit.token_from_base64url(token_text) catch {
    @biscuit.Malformed(message) => return "token_text:" + message
    @biscuit.Unsupported(message) => return "token_text_unsupported:" + message
    _ => return "invalid_token_text"
  }
  let authorizer = parse_sample_authorizer(authorizer_text) catch {
    @biscuit.Malformed(message) => return "authorizer_parse:" + message
    @biscuit.Unsupported(message) => return "authorizer_unsupported:" + message
    _ => return "invalid_authorizer"
  }
  let externals = if enable_ffi {
    official_sample_externals()
  } else {
    @biscuit.ExternalFunctions::{ unary: Map([]), binary: Map([]), }
  }
  let root_key = b"\x10\x55\xc7\x50\xb1\xa1\x50\x59\x37\xaf\x15\x37\xc6\x26\xba\x32\x63\x99\x5c\x33\xa6\x47\x58\xaa\xaf\xb1\x27\x5b\x03\x12\xe2\x84"
  try {
    @biscuit.authorize_token_with_externals(
      token,
      root_key,
      authorizer.facts,
      authorizer.rules,
      authorizer.checks,
      authorizer.policies,
      10000,
      1000,
      externals,
    )
    "ok"
  } catch {
    @biscuit.TokenSignatureInvalid => "bad_signature"
    @biscuit.InvalidToken(_) => "invalid_token"
    @biscuit.UnsupportedTokenFeature(_) => "unsupported_token"
    @biscuit.FailedCheck(_) => "denied"
    @biscuit.Denied(_) => "denied"
    @biscuit.NoMatchingPolicy => "denied"
    @biscuit.Expression(@biscuit.IntegerOverflow) => "overflow"
    @biscuit.Expression(@biscuit.TypeMismatch(_)) => "expression_error"
    @biscuit.Expression(@biscuit.ShadowedVariable(_)) => "shadowed_variable"
    _ => "other_error"
  }
}
