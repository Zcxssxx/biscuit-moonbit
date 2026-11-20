///|
priv struct RenderedExpression {
  text : String
  precedence : Int32
  is_comparison : Bool
  is_closure : Bool
  callable : Bool
}

///|
fn join_datalog(items : Array[String], separator : String) -> String {
  let mut result = ""
  for i = 0; i < items.length(); i = i + 1 {
    if i > 0 {
      result = result + separator
    }
    result = result + items[i]
  }
  result
}

///|
fn validate_datalog_identifier(
  name : String,
  variable~ : Bool,
) -> Unit raise TokenError {
  let chars = name.to_array()
  if chars.length() == 0 {
    raise Malformed("empty Datalog identifier")
  }
  let first_is_valid = is_ident_start(chars[0]) ||
    (variable && chars[0].is_ascii_digit())
  if !first_is_valid {
    raise Unsupported("Datalog identifier cannot be printed")
  }
  for i = 1; i < chars.length(); i = i + 1 {
    if !is_ident_continue(chars[i]) {
      raise Unsupported("Datalog identifier cannot be printed")
    }
  }
}

///|
fn quote_datalog_string(value : String) -> String {
  let escaped : Array[Char] = ['"']
  for c in value.to_array() {
    match c {
      '"' =>
        for escaped_char in "\\\"".to_array() {
          escaped.push(escaped_char)
        }
      '\\' =>
        for escaped_char in "\\\\".to_array() {
          escaped.push(escaped_char)
        }
      '\n' =>
        for escaped_char in "\\n".to_array() {
          escaped.push(escaped_char)
        }
      '\r' =>
        for escaped_char in "\\r".to_array() {
          escaped.push(escaped_char)
        }
      '\t' =>
        for escaped_char in "\\t".to_array() {
          escaped.push(escaped_char)
        }
      _ => escaped.push(c)
    }
  }
  escaped.push('"')
  String::from_array(escaped)
}

///|
fn pad_date_component(value : Int64, width : Int32) -> String {
  let digits = value.to_string()
  let mut result = ""
  for _i = digits.length(); _i < width; _i = _i + 1 {
    result = result + "0"
  }
  result + digits
}

///|
fn print_date_seconds(timestamp : Int64) -> String raise TokenError {
  let mut days = timestamp / 86400L
  let mut second_of_day = timestamp % 86400L
  if second_of_day < 0L {
    days -= 1L
    second_of_day += 86400L
  }
  let shifted_days = days + 719468L
  let era = if shifted_days >= 0L {
    shifted_days / 146097L
  } else {
    (shifted_days - 146096L) / 146097L
  }
  let day_of_era = shifted_days - era * 146097L
  let year_of_era = (
      day_of_era -
      day_of_era / 1460L +
      day_of_era / 36524L -
      day_of_era / 146096L
    ) /
    365L
  let mut year = year_of_era + era * 400L
  let day_of_year = day_of_era -
    (365L * year_of_era + year_of_era / 4L - year_of_era / 100L)
  let month_prime = (5L * day_of_year + 2L) / 153L
  let day = day_of_year - (153L * month_prime + 2L) / 5L + 1L
  let month = month_prime + (if month_prime < 10L { 3L } else { -9L })
  if month <= 2L {
    year += 1L
  }
  if year < 0L || year > 9999L {
    raise Unsupported("date is outside the printable RFC 3339 year range")
  }
  let hour = second_of_day / 3600L
  let minute = second_of_day % 3600L / 60L
  let second = second_of_day % 60L
  pad_date_component(year, 4) +
  "-" +
  pad_date_component(month, 2) +
  "-" +
  pad_date_component(day, 2) +
  "T" +
  pad_date_component(hour, 2) +
  ":" +
  pad_date_component(minute, 2) +
  ":" +
  pad_date_component(second, 2) +
  "Z"
}

///|
fn print_value_at_depth(
  value : Value,
  depth : Int32,
) -> String raise TokenError {
  if depth > 32 {
    raise Malformed("value nesting exceeds 32 levels")
  }
  match value {
    Text(text) => quote_datalog_string(text)
    Number(number) => number.to_string()
    Date(seconds) => print_date_seconds(seconds)
    ByteString(bytes) => "hex:" + @hex.encode(bytes)
    Boolean(true) => "true"
    Boolean(false) => "false"
    Null => "null"
    ArrayValue(values) => {
      let rendered : Array[String] = []
      for item in values {
        rendered.push(print_value_at_depth(item, depth + 1))
      }
      "[" + join_datalog(rendered, ", ") + "]"
    }
    SetValue(values) => {
      let rendered : Array[String] = []
      let seen : Array[Value] = []
      for item in values {
        match item {
          SetValue(_) => raise Malformed("nested sets are not supported")
          _ =>
            if !seen.contains(item) {
              seen.push(item)
              rendered.push(print_value_at_depth(item, depth + 1))
            }
        }
      }
      if rendered.length() == 0 {
        "{,}"
      } else {
        "{" + join_datalog(rendered, ", ") + "}"
      }
    }
    MapValue(entries) => {
      let rendered : Array[String] = []
      let seen : Array[MapKey] = []
      for (key, item) in entries {
        if seen.contains(key) {
          raise Malformed("duplicate map key")
        }
        seen.push(key)
        let key_text = match key {
          IntegerKey(number) => number.to_string()
          StringKey(text) => quote_datalog_string(text)
        }
        rendered.push(key_text + ": " + print_value_at_depth(item, depth + 1))
      }
      "{" + join_datalog(rendered, ", ") + "}"
    }
  }
}

///|
/// Print a Datalog value using syntax accepted by `parse_fact` and expressions.
pub fn print_value(value : Value) -> String raise TokenError {
  print_value_at_depth(value, 0)
}

///|
/// Print a Datalog predicate, including its constants and variable names.
pub fn print_predicate(predicate : Predicate) -> String raise TokenError {
  validate_datalog_identifier(predicate.name, variable=false)
  let terms : Array[String] = []
  for term in predicate.terms {
    match term {
      Constant(value) => terms.push(print_value(value))
      Variable(name) => {
        validate_datalog_identifier(name, variable=true)
        terms.push("$" + name)
      }
    }
  }
  predicate.name + "(" + join_datalog(terms, ", ") + ")"
}

///|
/// Print a ground fact in canonical Datalog syntax.
pub fn print_fact(fact : Fact) -> String raise TokenError {
  let predicate = {
    name: fact.name,
    terms: fact.values.map(value => Constant(value)),
  }
  print_predicate(predicate)
}

///|
fn print_scopes(scopes : Array[TrustScope]) -> String raise TokenError {
  if scopes.length() == 0 {
    return ""
  }
  let rendered : Array[String] = []
  for scope in scopes {
    let item = match scope {
      TrustAuthority => "authority"
      TrustPrevious => "previous"
      TrustPublicKey(key) if key.length() == 32 => "ed25519/" + @hex.encode(key)
      TrustPublicKey(key) if key.length() == 34 && key[0] == b'\x01' =>
        "secp256r1/" + @hex.encode(key_bytes(key))
      TrustPublicKey(_) =>
        raise Malformed("scope Ed25519 public key must be 32 bytes")
    }
    if !rendered.contains(item) {
      rendered.push(item)
    }
  }
  " trusting " + join_datalog(rendered, ", ")
}

///|
fn print_query_body_parts(
  body : Array[Predicate],
  conditions : Array[Condition],
  scopes : Array[TrustScope],
) -> String raise TokenError {
  let parts : Array[String] = []
  for predicate in body {
    parts.push(print_predicate(predicate))
  }
  for condition in conditions {
    parts.push(print_expression(condition))
  }
  if parts.length() == 0 {
    raise Malformed("query body is empty")
  }
  join_datalog(parts, ", ") + print_scopes(scopes)
}

///|
/// Print a query body, preserving its trusted-origin scopes.
pub fn print_query_body(query : Query) -> String raise TokenError {
  print_query_body_parts(query.body, query.conditions, query.scopes)
}

///|
/// Print one safe Datalog rule.
pub fn print_rule(rule : Rule) -> String raise TokenError {
  validate_rule_safety(rule)
  print_predicate(rule.head) +
  " <- " +
  print_query_body_parts(rule.body, rule.conditions, rule.scopes)
}

///|
fn split_top_level_keyword(
  text : String,
  keyword : String,
) -> Array[String] raise TokenError {
  let chars = text.to_array()
  let marker = keyword.to_array()
  let parts : Array[String] = []
  let mut start = 0
  let mut depth = 0
  let mut quoted = false
  let mut escaped = false
  let mut i = 0
  while i < chars.length() {
    let c = chars[i]
    if quoted {
      if escaped {
        escaped = false
      } else if c == '\\' {
        escaped = true
      } else if c == '"' {
        quoted = false
      }
      i += 1
    } else if c == '"' {
      quoted = true
      i += 1
    } else if c == '(' || c == '[' || c == '{' {
      depth += 1
      i += 1
    } else if c == ')' || c == ']' || c == '}' {
      depth -= 1
      if depth < 0 {
        raise Malformed("unbalanced delimiters")
      }
      i += 1
    } else if depth == 0 &&
      i + marker.length() <= chars.length() &&
      String::from_array(chars[i:i + marker.length()]) == keyword {
      parts.push(String::from_array(chars[start:i]))
      i += marker.length()
      start = i
    } else {
      i += 1
    }
  }
  if quoted || depth != 0 {
    raise Malformed("unclosed string or delimiters")
  }
  parts.push(String::from_array(chars[start:]))
  parts
}

///|
fn without_final_semicolon(text : String) -> String {
  let trimmed = text.trim().to_owned()
  let chars = trimmed.to_array()
  if chars.length() > 0 && chars[chars.length() - 1] == ';' {
    String::from_array(chars[0:chars.length() - 1]).trim().to_owned()
  } else {
    trimmed
  }
}

///|
fn parse_alternative_queries(text : String) -> Array[Query] raise TokenError {
  let queries : Array[Query] = []
  for part in split_top_level_keyword(text, " or ") {
    queries.push(parse_query_body(part.trim().to_owned()))
  }
  if queries.length() == 0 {
    raise Malformed("check or policy has no query")
  }
  queries
}

///|
/// Parse biscuit-rust check syntax (`check if`, `check all`, or `reject if`).
pub fn parse_check(text : String) -> Check raise TokenError {
  let source = without_final_semicolon(text)
  let (mode, prefix) = if source.has_prefix("check if ") {
    (CheckMode::Any, "check if ")
  } else if source.has_prefix("check all ") {
    (CheckMode::All, "check all ")
  } else if source.has_prefix("reject if ") {
    (CheckMode::Reject, "reject if ")
  } else {
    raise Malformed("expected check if, check all, or reject if")
  }
  let body = String::from_array(source.to_array()[prefix.length():])
  { mode, queries: parse_alternative_queries(body), }
}

///|
/// Parse one biscuit-rust allow or deny policy statement.
pub fn parse_policy(text : String) -> Policy raise TokenError {
  let source = without_final_semicolon(text)
  let (kind, prefix) = if source.has_prefix("allow if ") {
    (Allow, "allow if ")
  } else if source.has_prefix("deny if ") {
    (Deny, "deny if ")
  } else {
    raise Malformed("expected allow if or deny if")
  }
  let body = String::from_array(source.to_array()[prefix.length():])
  { kind, queries: parse_alternative_queries(body), }
}

///|
/// Print a check statement. Multiple query bodies retain their OR semantics.
pub fn print_check(check : Check) -> String raise TokenError {
  if check.queries.length() == 0 {
    raise Malformed("check has no query")
  }
  let prefix = match check.mode {
    Any => "check if "
    All => "check all "
    Reject => "reject if "
  }
  prefix + join_datalog(check.queries.map(print_query_body), " or ")
}

///|
/// Print one allow or deny policy statement.
pub fn print_policy(policy : Policy) -> String raise TokenError {
  if policy.queries.length() == 0 {
    raise Malformed("policy has no query")
  }
  let prefix = match policy.kind {
    Allow => "allow if "
    Deny => "deny if "
  }
  prefix + join_datalog(policy.queries.map(print_query_body), " or ")
}

///|
fn binary_print_info(operator : BinaryOperator) -> (String, Int32, Bool, Bool) {
  match operator {
    Multiply => ("*", 8, false, false)
    Divide => ("/", 8, false, false)
    Add => ("+", 7, false, false)
    Subtract => ("-", 7, false, false)
    BitwiseAnd => ("&", 6, false, false)
    BitwiseOr => ("|", 5, false, false)
    BitwiseXor => ("^", 4, false, false)
    LessThan => ("<", 3, true, false)
    GreaterThan => (">", 3, true, false)
    LessOrEqual => ("<=", 3, true, false)
    GreaterOrEqual => (">=", 3, true, false)
    StrictEqual => ("===", 3, true, false)
    StrictNotEqual => ("!==", 3, true, false)
    LenientEqual => ("==", 3, true, false)
    LenientNotEqual => ("!=", 3, true, false)
    EagerAnd => ("&&!", 2, false, false)
    LazyAnd => ("&&", 2, false, true)
    EagerOr => ("||!", 1, false, false)
    LazyOr => ("||", 1, false, true)
    Contains => ("contains", 10, false, false)
    Prefix => ("starts_with", 10, false, false)
    Suffix => ("ends_with", 10, false, false)
    Regex => ("matches", 10, false, false)
    Intersection => ("intersection", 10, false, false)
    Union => ("union", 10, false, false)
    Get => ("get", 10, false, false)
    ExternalBinary(name) => ("extern::" + name, 10, false, false)
    Any => ("any", 10, false, false)
    All => ("all", 10, false, false)
    TryOr => ("try_or", 10, false, false)
  }
}

///|
fn rendered_child(
  child : RenderedExpression,
  parent_precedence : Int32,
  right_child : Bool,
  parent_is_comparison : Bool,
) -> String {
  let needs_parentheses = child.precedence < parent_precedence ||
    (right_child && child.precedence == parent_precedence) ||
    (parent_is_comparison && child.is_comparison)
  if needs_parentheses {
    "(" + child.text + ")"
  } else {
    child.text
  }
}

///|
fn render_expression_ops(
  operations : Array[ExpressionOp],
) -> String raise TokenError {
  let stack : Array[RenderedExpression] = []
  for operation in operations {
    match operation {
      Value(Literal(value)) =>
        stack.push({
          text: print_value(value),
          precedence: 10,
          is_comparison: false,
          is_closure: false,
          callable: true,
        })
      Value(Reference(name)) => {
        validate_datalog_identifier(name, variable=true)
        stack.push({
          text: "$" + name,
          precedence: 10,
          is_comparison: false,
          is_closure: false,
          callable: true,
        })
      }
      Closure(closure) => {
        let body = render_expression_ops(closure.operations)
        let params : Array[String] = []
        for parameter in closure.parameters {
          validate_datalog_identifier(parameter, variable=true)
          params.push("$" + parameter)
        }
        let text = if params.length() == 0 {
          body
        } else {
          join_datalog(params, ", ") + " -> " + body
        }
        stack.push({
          text,
          precedence: 0,
          is_comparison: false,
          is_closure: true,
          callable: false,
        })
      }
      Unary(operator) => {
        let child = match stack.pop() {
          Some(value) if !value.is_closure => value
          _ => raise Malformed("unary operator has an invalid operand")
        }
        let rendered = match operator {
          Negate => {
            let operand = if child.precedence < 9 {
              "(" + child.text + ")"
            } else {
              child.text
            }
            {
              text: "!" + operand,
              precedence: 9,
              is_comparison: false,
              is_closure: false,
              callable: false,
            }
          }
          Parens =>
            {
              text: "(" + child.text + ")",
              precedence: 10,
              is_comparison: false,
              is_closure: false,
              callable: true,
            }
          Length | TypeOf | ExternalUnary(_) => {
            if !child.callable {
              raise Unsupported("unary method receiver cannot be printed")
            }
            let method_name = match operator {
              Length => "length"
              TypeOf => "type"
              ExternalUnary(name) => {
                validate_datalog_identifier(name, variable=false)
                "extern::" + name
              }
              _ => ""
            }
            {
              text: child.text + "." + method_name + "()",
              precedence: 10,
              is_comparison: false,
              is_closure: false,
              callable: true,
            }
          }
        }
        stack.push(rendered)
      }
      Binary(operator) => {
        let right = match stack.pop() {
          Some(value) => value
          None =>
            raise Malformed("binary operator is missing its right operand")
        }
        let left = match stack.pop() {
          Some(value) => value
          None => raise Malformed("binary operator is missing its left operand")
        }
        let (symbol, precedence, is_comparison, is_lazy) = binary_print_info(
          operator,
        )
        if operator == Any || operator == All {
          if right.is_closure && left.callable {
            stack.push({
              text: left.text + "." + symbol + "(" + right.text + ")",
              precedence: 10,
              is_comparison: false,
              is_closure: false,
              callable: true,
            })
          } else {
            raise Malformed("any/all expects a collection and a closure")
          }
        } else if operator == TryOr {
          if left.is_closure && !right.is_closure {
            stack.push({
              text: left.text + ".try_or(" + right.text + ")",
              precedence: 10,
              is_comparison: false,
              is_closure: false,
              callable: true,
            })
          } else {
            raise Malformed("try_or expects a closure and a fallback value")
          }
        } else if symbol.has_prefix("extern::") {
          let name = String::from_array(symbol.to_array()[8:])
          validate_datalog_identifier(name, variable=false)
          if left.callable && !right.is_closure {
            stack.push({
              text: left.text + ".extern::" + name + "(" + right.text + ")",
              precedence: 10,
              is_comparison: false,
              is_closure: false,
              callable: true,
            })
          } else {
            raise Malformed("external binary operator has invalid operands")
          }
        } else if symbol == "contains" ||
          symbol == "starts_with" ||
          symbol == "ends_with" ||
          symbol == "matches" ||
          symbol == "intersection" ||
          symbol == "union" ||
          symbol == "get" {
          if left.callable && !right.is_closure {
            stack.push({
              text: left.text + "." + symbol + "(" + right.text + ")",
              precedence: 10,
              is_comparison: false,
              is_closure: false,
              callable: true,
            })
          } else {
            raise Malformed("Datalog method has invalid operands")
          }
        } else if !left.is_closure && right.is_closure == is_lazy {
          let lhs = rendered_child(left, precedence, false, is_comparison)
          let rhs = if is_lazy {
            right.text
          } else {
            rendered_child(right, precedence, true, is_comparison)
          }
          stack.push({
            text: lhs + " " + symbol + " " + rhs,
            precedence,
            is_comparison,
            is_closure: false,
            callable: false,
          })
        } else {
          raise Malformed("binary operator has invalid operands")
        }
      }
    }
  }
  match stack.pop() {
    Some(value) if stack.length() == 0 && !value.is_closure => value.text
    _ => raise Malformed("expression does not leave one printable value")
  }
}

///|
/// Print a parsed expression in canonical syntax that can be parsed again.
pub fn print_expression(condition : Condition) -> String raise TokenError {
  validate_expression_program(condition.operations, 0)
  render_expression_ops(condition.operations)
}
