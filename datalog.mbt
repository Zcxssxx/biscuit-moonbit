///|
/// Scalar values supported by the initial Datalog evaluator subset.
pub(all) enum Value {
  Text(String)
  Number(Int64)
  ByteString(Bytes)
  ArrayValue(Array[Value])
  Boolean(Bool)
  Null
} derive(Eq, @debug.Debug)

///|
pub extend Value with Eq::{equal, not_equal}

///|
pub extend Value with @debug.Debug::{to_repr}

///|
/// Query terms are constants or named variables.
pub(all) enum QueryTerm {
  Constant(Value)
  Variable(String)
} derive(Eq, @debug.Debug)

///|
pub extend QueryTerm with Eq::{equal, not_equal}

///|
pub extend QueryTerm with @debug.Debug::{to_repr}

///|
/// A predicate contains a name and zero or more terms.
pub(all) struct Predicate {
  name : String
  terms : Array[QueryTerm]
}

///|
/// A concrete fact contains no variables.
pub(all) struct Fact {
  name : String
  values : Array[Value]
} derive(Eq)

///|
pub extend Fact with Eq::{equal, not_equal}

///|
/// A positive Datalog rule with predicate-only body.
pub(all) struct Rule {
  head : Predicate
  body : Array[Predicate]
}

///|
/// A conjunction of positive predicates, the query unit used by checks and policies.
pub(all) struct Query {
  body : Array[Predicate]
}

///|
/// Whether one or every query in a check group must match.
pub(all) enum CheckMode {
  Any
  All
}

///|
pub(all) struct Check {
  mode : CheckMode
  queries : Array[Query]
}

///|
pub(all) enum PolicyKind {
  Allow
  Deny
}

///|
/// Ordered policy query. The first matching policy determines the decision.
pub(all) struct Policy {
  kind : PolicyKind
  queries : Array[Query]
}

///|
pub suberror AuthorizationError {
  FailedCheck(Int32)
  NoMatchingPolicy
  Denied(Int32)
  FactLimit
  IterationLimit
  EmptyCheck(Int32)
  EmptyPolicy(Int32)
}

///|
priv enum Lexeme {
  Word(String)
  VariableName(String)
  Literal(Value)
  LeftParen
  RightParen
  Comma
  LeftBracket
  RightBracket
  End
} derive(Eq)

///|
priv struct Lexer {
  chars : Array[Char]
  mut pos : Int32
}

///|
fn is_ident_start(c : Char) -> Bool {
  c.is_ascii_alphabetic() || c == '_'
}

///|
fn is_ident_continue(c : Char) -> Bool {
  is_ident_start(c) || c.is_ascii_digit() || c == ':'
}

///|
fn Lexer::next(self : Lexer) -> Lexeme raise TokenError {
  while self.pos < self.chars.length() && self.chars[self.pos].is_whitespace() {
    self.pos += 1
  }
  if self.pos >= self.chars.length() {
    return End
  }
  let c = self.chars[self.pos]
  if c == '(' {
    self.pos += 1
    return LeftParen
  }
  if c == ')' {
    self.pos += 1
    return RightParen
  }
  if c == ',' {
    self.pos += 1
    return Comma
  }
  if c == '[' {
    self.pos += 1
    return LeftBracket
  }
  if c == ']' {
    self.pos += 1
    return RightBracket
  }
  if c == '$' {
    self.pos += 1
    let start = self.pos
    if self.pos >= self.chars.length() || !is_ident_start(self.chars[self.pos]) {
      raise Malformed("expected variable name after '$'")
    }
    self.pos += 1
    while self.pos < self.chars.length() &&
          is_ident_continue(self.chars[self.pos]) {
      self.pos += 1
    }
    return VariableName(String::from_array(self.chars[start:self.pos]))
  }
  if c == '"' {
    self.pos += 1
    let result : Array[Char] = []
    let mut closed = false
    while self.pos < self.chars.length() && !closed {
      let ch = self.chars[self.pos]
      self.pos += 1
      if ch == '"' {
        closed = true
      } else if ch == '\\' {
        if self.pos >= self.chars.length() {
          raise Malformed("unterminated string escape")
        }
        let escaped = self.chars[self.pos]
        self.pos += 1
        match escaped {
          '"' => result.push('"')
          '\\' => result.push('\\')
          'n' => result.push('\n')
          'r' => result.push('\r')
          't' => result.push('\t')
          _ => raise Unsupported("string escape")
        }
      } else {
        result.push(ch)
      }
    }
    if !closed {
      raise Malformed("unterminated string")
    }
    return Literal(Text(String::from_array(result)))
  }
  if c == '-' || c.is_ascii_digit() {
    let start = self.pos
    if c == '-' {
      self.pos += 1
    }
    if self.pos >= self.chars.length() || !self.chars[self.pos].is_ascii_digit() {
      raise Malformed("expected digits after minus")
    }
    while self.pos < self.chars.length() &&
          self.chars[self.pos].is_ascii_digit() {
      self.pos += 1
    }
    let number = String::from_array(self.chars[start:self.pos])
    return Literal(
      Number(
        @string.parse_int64(number) catch {
          _ => raise Malformed("integer out of range")
        },
      ),
    )
  }
  if is_ident_start(c) {
    let start = self.pos
    self.pos += 1
    while self.pos < self.chars.length() &&
          is_ident_continue(self.chars[self.pos]) {
      self.pos += 1
    }
    let word = String::from_array(self.chars[start:self.pos])
    match word {
      "true" => return Literal(Boolean(true))
      "false" => return Literal(Boolean(false))
      "null" => return Literal(Null)
      _ => {
        let chars = word.to_array()
        if chars.length() >= 4 &&
          chars[0] == 'h' &&
          chars[1] == 'e' &&
          chars[2] == 'x' &&
          chars[3] == ':' {
          let encoded = String::from_array(chars[4:])
          return Literal(
            ByteString(
              @hex.decode(encoded) catch {
                _ => raise Malformed("invalid hex byte string")
              },
            ),
          )
        }
        return Word(word)
      }
    }
  }
  raise Unsupported("Datalog token")
}

///|
priv struct Parser {
  lexer : Lexer
  mut current : Lexeme
}

///|
fn Parser::advance(self : Parser) -> Unit raise TokenError {
  self.current = self.lexer.next()
}

///|
fn parse_value(parser : Parser, depth : Int32) -> Value raise TokenError {
  if depth > 32 {
    raise Malformed("array nesting exceeds 32 levels")
  }
  match parser.current {
    Literal(value) => {
      parser.advance()
      value
    }
    LeftBracket => {
      parser.advance()
      let values : Array[Value] = []
      if parser.current != RightBracket {
        let mut finished = false
        while !finished {
          if values.length() >= 1024 {
            raise Malformed("array exceeds 1024 items")
          }
          values.push(parse_value(parser, depth + 1))
          match parser.current {
            Comma => parser.advance()
            RightBracket => finished = true
            _ => raise Malformed("expected ',' or ']' in array")
          }
        }
      }
      if parser.current != RightBracket {
        raise Malformed("unclosed array")
      }
      parser.advance()
      ArrayValue(values)
    }
    _ => raise Malformed("expected constant value")
  }
}

///|
fn parse_predicate(
  text : String,
  allow_variables~ : Bool,
) -> Predicate raise TokenError {
  if text.length() > 65536 {
    raise Malformed("predicate exceeds 64 KiB")
  }
  let lexer = Lexer::{ chars: text.to_array(), pos: 0, }
  let parser = Parser::{ lexer, current: End, }
  parser.advance()
  let name = match parser.current {
    Word(value) => value
    _ => raise Malformed("expected predicate name")
  }
  parser.advance()
  if parser.current != LeftParen {
    raise Malformed("expected '('")
  }
  parser.advance()
  let terms : Array[QueryTerm] = []
  if parser.current != RightParen {
    let mut finished = false
    while !finished {
      match parser.current {
        Literal(_) | LeftBracket => terms.push(Constant(parse_value(parser, 0)))
        VariableName(name) if allow_variables => {
          terms.push(Variable(name))
          parser.advance()
        }
        VariableName(_) => raise Malformed("facts cannot contain variables")
        _ => raise Malformed("expected term")
      }
      match parser.current {
        Comma => parser.advance()
        RightParen => finished = true
        _ => raise Malformed("expected ',' or ')'")
      }
    }
  }
  parser.advance()
  if parser.current != End {
    raise Malformed("trailing input after predicate")
  }
  if terms.length() > 128 {
    raise Malformed("too many predicate terms")
  }
  { name, terms, }
}

///|
/// Parse one ground fact such as `right("/docs", "read")`.
pub fn parse_fact(text : String) -> Fact raise TokenError {
  let predicate = parse_predicate(text, allow_variables=false)
  let values : Array[Value] = []
  for term in predicate.terms {
    match term {
      Constant(value) => values.push(value)
      Variable(_) => raise Malformed("fact contains variable")
    }
  }
  { name: predicate.name, values, }
}

///|
/// Parse one simple query predicate such as `right($path, "read")`.
pub fn parse_query(text : String) -> Predicate raise TokenError {
  parse_predicate(text, allow_variables=true)
}

///|
/// Parse a conjunction used by a check or policy, e.g. `user($u), role($u, "admin")`.
pub fn parse_query_body(text : String) -> Query raise TokenError {
  let parts = split_top_level(text, ',')
  let body : Array[Predicate] = []
  for part in parts {
    body.push(parse_predicate(part.trim().to_owned(), allow_variables=true))
  }
  if body.length() == 0 {
    raise Malformed("query body is empty")
  }
  { body, }
}

///|
/// Split a rule at a top-level delimiter, respecting quoted strings and
/// nested parentheses.
fn split_top_level(
  text : String,
  delimiter : Char,
) -> Array[String] raise TokenError {
  let chars = text.to_array()
  let parts : Array[String] = []
  let mut start = 0
  let mut depth = 0
  let mut quoted = false
  let mut escaped = false
  for i = 0; i < chars.length(); i = i + 1 {
    let c = chars[i]
    if quoted {
      if escaped {
        escaped = false
      } else if c == '\\' {
        escaped = true
      } else if c == '"' {
        quoted = false
      }
    } else if c == '"' {
      quoted = true
    } else if c == '(' || c == '[' {
      depth += 1
    } else if c == ')' || c == ']' {
      depth -= 1
      if depth < 0 {
        raise Malformed("unbalanced parentheses")
      }
    } else if c == delimiter && depth == 0 {
      parts.push(String::from_array(chars[start:i]))
      start = i + 1
    }
  }
  if quoted || depth != 0 {
    raise Malformed("unclosed string or parentheses")
  }
  parts.push(String::from_array(chars[start:]))
  parts
}

///|
/// Parse a positive Datalog rule such as
/// `grandparent($x, $z) <- parent($x, $y), parent($y, $z)`.
/// Expressions, negation, scopes and disjunction are unsupported.
pub fn parse_rule(text : String) -> Rule raise TokenError {
  if text.length() > 65536 {
    raise Malformed("rule exceeds 64 KiB")
  }
  let parts = split_top_level(text, '<')
  if parts.length() != 2 {
    raise Malformed("expected '<-' in rule")
  }
  let right = parts[1].to_array()
  if right.length() == 0 || right[0] != '-' {
    raise Malformed("expected '<-' in rule")
  }
  let head = parse_predicate(parts[0].trim().to_owned(), allow_variables=true)
  let body_text = String::from_array(right[1:]).trim().to_owned()
  let body_parts = split_top_level(body_text, ',')
  let body : Array[Predicate] = []
  for part in body_parts {
    body.push(parse_predicate(part.trim().to_owned(), allow_variables=true))
  }
  if body.length() == 0 {
    raise Malformed("rule body is empty")
  }
  let bound : Array[String] = []
  for predicate in body {
    for term in predicate.terms {
      match term {
        Variable(name) => if !bound.contains(name) { bound.push(name) }
        Constant(_) => ()
      }
    }
  }
  for term in head.terms {
    match term {
      Variable(name) if !bound.contains(name) =>
        raise Malformed("unsafe rule head variable")
      _ => ()
    }
  }
  { head, body, }
}

///|
fn unify(
  predicate : Predicate,
  fact : Fact,
  bindings : Map[String, Value],
) -> Map[String, Value]? {
  if predicate.name != fact.name ||
    predicate.terms.length() != fact.values.length() {
    return None
  }
  let result : Map[String, Value] = Map([])
  for (name, value) in bindings {
    result[name] = value
  }
  for i = 0; i < predicate.terms.length(); i = i + 1 {
    match predicate.terms[i] {
      Constant(value) => if value != fact.values[i] { return None }
      Variable(name) =>
        match result.get(name) {
          Some(previous) => if previous != fact.values[i] { return None }
          None => result[name] = fact.values[i]
        }
    }
  }
  Some(result)
}

///|
fn rule_bindings(
  rule : Rule,
  facts : Array[Fact],
  max_bindings : Int32,
) -> Array[Map[String, Value]] raise AuthorizationError {
  let mut environments : Array[Map[String, Value]] = [Map([])]
  for predicate in rule.body {
    let next_environments : Array[Map[String, Value]] = []
    for environment in environments {
      for fact in facts {
        match unify(predicate, fact, environment) {
          Some(bindings) => {
            if next_environments.length() >= max_bindings {
              raise FactLimit
            }
            next_environments.push(bindings)
          }
          None => ()
        }
      }
    }
    environments = next_environments
    if environments.length() == 0 {
      break
    }
  }
  environments
}

///|
fn instantiate(rule : Rule, bindings : Map[String, Value]) -> Fact? {
  let values : Array[Value] = []
  for term in rule.head.terms {
    match term {
      Constant(value) => values.push(value)
      Variable(name) =>
        match bindings.get(name) {
          Some(value) => values.push(value)
          None => return None
        }
    }
  }
  Some({ name: rule.head.name, values, })
}

///|
/// Compute the least fixed point for positive, predicate-only rules.
/// Explicit limits bound work on recursive programs. Fact origins and Biscuit
/// execution scopes are not represented in this standalone evaluator.
pub fn derive_facts(
  initial : Array[Fact],
  rules : Array[Rule],
  max_facts : Int32,
  max_iterations : Int32,
) -> Array[Fact] raise AuthorizationError {
  if initial.length() > max_facts {
    raise FactLimit
  }
  let facts = initial.copy()
  let mut iteration : Int32 = 0
  let mut stable = false
  while iteration < max_iterations && !stable {
    stable = true
    for rule in rules {
      for bindings in rule_bindings(rule, facts, max_facts) {
        match instantiate(rule, bindings) {
          Some(fact) =>
            if !facts.contains(fact) {
              if facts.length() >= max_facts {
                raise FactLimit
              }
              facts.push(fact)
              stable = false
            }
          None => ()
        }
      }
    }
    iteration += 1
  }
  if !stable {
    raise IterationLimit
  }
  facts
}

///|
/// Query a finite set of facts. Returns each matching variable binding.
pub fn match_query(
  query : Predicate,
  facts : Array[Fact],
) -> Array[Map[String, Value]] {
  let results : Array[Map[String, Value]] = []
  for fact in facts {
    if fact.name == query.name && fact.values.length() == query.terms.length() {
      let bindings : Map[String, Value] = Map([])
      let mut matched = true
      for i = 0; i < query.terms.length(); i = i + 1 {
        match query.terms[i] {
          Constant(value) => if value != fact.values[i] { matched = false }
          Variable(name) =>
            match bindings.get(name) {
              Some(value) => if value != fact.values[i] { matched = false }
              None => bindings[name] = fact.values[i]
            }
        }
      }
      if matched {
        results.push(bindings)
      }
    }
  }
  results
}

///|
/// Evaluate a set of query-only checks and ordered policies over supplied facts.
/// Every check must pass. Policies use first-match semantics and default deny.
/// This primitive does not decode token blocks, scopes, rules or symbols.
pub fn evaluate_policy_set(
  facts : Array[Fact],
  checks : Array[Check],
  policies : Array[Policy],
) -> Unit raise AuthorizationError {
  for i = 0; i < checks.length(); i = i + 1 {
    let check = checks[i]
    if check.queries.length() == 0 {
      raise EmptyCheck(i)
    }
    let matched = match check.mode {
      Any => check.queries.any(q => query_matches(q, facts))
      All => check.queries.all(q => query_matches(q, facts))
    }
    if !matched {
      raise FailedCheck(i)
    }
  }
  for i = 0; i < policies.length(); i = i + 1 {
    let policy = policies[i]
    if policy.queries.length() == 0 {
      raise EmptyPolicy(i)
    }
    if policy.queries.any(q => query_matches(q, facts)) {
      match policy.kind {
        Allow => return
        Deny => raise Denied(i)
      }
    }
  }
  raise NoMatchingPolicy
}

///|
fn query_matches(
  query : Query,
  facts : Array[Fact],
) -> Bool raise AuthorizationError {
  let rule = Rule::{
    head: Predicate::{ name: "__query_result", terms: [], },
    body: query.body,
  }
  rule_bindings(rule, facts, 10000).length() > 0
}
