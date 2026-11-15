///|
pub(all) enum MapKey {
  IntegerKey(Int64)
  StringKey(String)
} derive(Eq, @debug.Debug)

///|
pub extend MapKey with Eq::{equal, not_equal}

///|
pub extend MapKey with @debug.Debug::{to_repr}

///|
/// Constants supported by the Datalog parser and evaluator subset.
pub(all) enum Value {
  Text(String)
  Number(Int64)
  Date(Int64)
  ByteString(Bytes)
  ArrayValue(Array[Value])
  SetValue(Array[Value])
  MapValue(Array[(MapKey, Value)])
  Boolean(Bool)
  Null
} derive(@debug.Debug)

///|
pub impl Eq for Value with fn equal(self, other) -> Bool {
  match (self, other) {
    (Text(a), Text(b)) => a == b
    (Number(a), Number(b)) => a == b
    (Date(a), Date(b)) => a == b
    (ByteString(a), ByteString(b)) => a == b
    (ArrayValue(a), ArrayValue(b)) => a == b
    (MapValue(a), MapValue(b)) =>
      a.length() == b.length() && a.all(entry => b.contains(entry))
    (Boolean(a), Boolean(b)) => a == b
    (Null, Null) => true
    (SetValue(a), SetValue(b)) =>
      a.length() == b.length() && a.all(value => b.contains(value))
    _ => false
  }
}

///|
pub extend Value with Eq::{not_equal}

///|
pub extend Value with Eq::{equal}

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
/// Trusted block origins used by Datalog scope annotations.
pub(all) enum TrustScope {
  TrustAuthority
  TrustPrevious
  TrustPublicKey(Bytes)
} derive(Eq, @debug.Debug)

///|
pub extend TrustScope with Eq::{equal, not_equal}

///|
pub extend TrustScope with @debug.Debug::{to_repr}

///|
/// A positive Datalog rule with predicate-only body.
pub(all) struct Rule {
  head : Predicate
  body : Array[Predicate]
  conditions : Array[Condition]
  scopes : Array[TrustScope]
}

///|
pub(all) enum ExpressionValue {
  Literal(Value)
  Reference(String)
}

///|
pub(all) enum UnaryOperator {
  Negate
  Parens
  Length
  TypeOf
  ExternalUnary(String)
}

///|
pub(all) enum BinaryOperator {
  LessThan
  GreaterThan
  LessOrEqual
  GreaterOrEqual
  StrictEqual
  Contains
  Prefix
  Suffix
  Regex
  Add
  Subtract
  Multiply
  Divide
  EagerAnd
  EagerOr
  Intersection
  Union
  BitwiseAnd
  BitwiseOr
  BitwiseXor
  StrictNotEqual
  LenientEqual
  LenientNotEqual
  LazyAnd
  LazyOr
  All
  Any
  Get
  ExternalBinary(String)
  TryOr
}

///|
pub(all) struct ExpressionClosure {
  parameters : Array[String]
  operations : Array[ExpressionOp]
}

///|
/// Datalog expression bytecode, kept in its protocol-defined postfix order.
pub(all) enum ExpressionOp {
  Value(ExpressionValue)
  Unary(UnaryOperator)
  Binary(BinaryOperator)
  Closure(ExpressionClosure)
}

///|
pub(all) struct Condition {
  operations : Array[ExpressionOp]
}

///|
pub(all) struct Query {
  body : Array[Predicate]
  conditions : Array[Condition]
  scopes : Array[TrustScope]
}

///|
/// How queries in a check group are combined.
pub(all) enum CheckMode {
  Any
  All
  Reject
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
pub suberror ExpressionError {
  TypeMismatch(String)
  IntegerOverflow
  DivisionByZero
  UnboundVariable(String)
  InvalidRegex(String)
  MissingExternal(String)
  ShadowedVariable(String)
  MalformedProgram
  StepLimit
}

///|
pub suberror AuthorizationError {
  InvalidToken(String)
  UnsupportedTokenFeature(String)
  TokenSignatureInvalid
  FailedCheck(Int32)
  NoMatchingPolicy
  Denied(Int32)
  FactLimit
  IterationLimit
  EmptyCheck(Int32)
  EmptyPolicy(Int32)
  Expression(ExpressionError)
}

///|
pub type UnaryExternalFn = (Value) -> Value raise AuthorizationError

///|
pub type BinaryExternalFn = (Value, Value) -> Value raise AuthorizationError

///|
pub(all) struct ExternalFunctions {
  unary : Map[String, UnaryExternalFn]
  binary : Map[String, BinaryExternalFn]
}

///|
priv enum Lexeme {
  Word(String)
  VariableName(String)
  Literal(Value)
  LeftParen
  RightParen
  Comma
  Colon
  LeftBracket
  RightBracket
  LeftBrace
  RightBrace
  Dot
  Arrow
  Operator(String)
  End
} derive(Eq)

///|
priv struct Lexer {
  chars : Array[Char]
  mut pos : Int32
  mut expect_value : Bool
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
fn Lexer::emit(self : Lexer, token : Lexeme, expect_value : Bool) -> Lexeme {
  self.expect_value = expect_value
  token
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
    return self.emit(LeftParen, true)
  }
  if c == ')' {
    self.pos += 1
    return self.emit(RightParen, false)
  }
  if c == ',' {
    self.pos += 1
    return self.emit(Comma, true)
  }
  if c == ':' {
    self.pos += 1
    return self.emit(Colon, true)
  }
  if c == '[' {
    self.pos += 1
    return self.emit(LeftBracket, true)
  }
  if c == ']' {
    self.pos += 1
    return self.emit(RightBracket, false)
  }
  if c == '{' {
    self.pos += 1
    return self.emit(LeftBrace, true)
  }
  if c == '}' {
    self.pos += 1
    return self.emit(RightBrace, false)
  }
  if c == '.' {
    self.pos += 1
    return self.emit(Dot, true)
  }
  if c == '$' {
    self.pos += 1
    let start = self.pos
    if self.pos >= self.chars.length() ||
      !(is_ident_start(self.chars[self.pos]) ||
      self.chars[self.pos].is_ascii_digit()) {
      raise Malformed("expected variable name after '$'")
    }
    self.pos += 1
    while self.pos < self.chars.length() &&
          is_ident_continue(self.chars[self.pos]) {
      self.pos += 1
    }
    return self.emit(
      VariableName(String::from_array(self.chars[start:self.pos])),
      false,
    )
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
    return self.emit(Literal(Text(String::from_array(result))), false)
  }
  if c == '-' &&
    self.pos + 1 < self.chars.length() &&
    self.chars[self.pos + 1] == '>' {
    self.pos += 2
    return self.emit(Arrow, true)
  }
  if c.is_ascii_digit() && looks_like_date(self.chars, self.pos) {
    let start = self.pos
    while self.pos < self.chars.length() &&
          !self.chars[self.pos].is_whitespace() &&
          self.chars[self.pos] != ',' &&
          self.chars[self.pos] != ')' &&
          self.chars[self.pos] != ']' &&
          self.chars[self.pos] != '}' &&
          self.chars[self.pos] != ';' &&
          self.chars[self.pos] != '.' {
      self.pos += 1
    }
    let date_text = String::from_array(self.chars[start:self.pos])
    return self.emit(Literal(Date(parse_date_seconds(date_text))), false)
  }
  if c == '-' &&
    self.expect_value &&
    self.pos + 1 < self.chars.length() &&
    self.chars[self.pos + 1].is_ascii_digit() {
    let start = self.pos
    self.pos += 1
    while self.pos < self.chars.length() &&
          self.chars[self.pos].is_ascii_digit() {
      self.pos += 1
    }
    let number = String::from_array(self.chars[start:self.pos])
    return self.emit(
      Literal(
        Number(
          @string.parse_int64(number) catch {
            _ => raise Malformed("integer out of range")
          },
        ),
      ),
      false,
    )
  }
  if c == '-' &&
    (
      !self.expect_value ||
      self.pos + 1 >= self.chars.length() ||
      !self.chars[self.pos + 1].is_ascii_digit()
    ) {
    self.pos += 1
    return self.emit(Operator("-"), true)
  }
  if c.is_ascii_digit() {
    let start = self.pos
    while self.pos < self.chars.length() &&
          self.chars[self.pos].is_ascii_digit() {
      self.pos += 1
    }
    let number = String::from_array(self.chars[start:self.pos])
    return self.emit(
      Literal(
        Number(
          @string.parse_int64(number) catch {
            _ => raise Malformed("integer out of range")
          },
        ),
      ),
      false,
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
      "true" => return self.emit(Literal(Boolean(true)), false)
      "false" => return self.emit(Literal(Boolean(false)), false)
      "null" => return self.emit(Literal(Null), false)
      _ => {
        let chars = word.to_array()
        if chars.length() >= 4 &&
          chars[0] == 'h' &&
          chars[1] == 'e' &&
          chars[2] == 'x' &&
          chars[3] == ':' {
          let encoded = String::from_array(chars[4:])
          return self.emit(
            Literal(
              ByteString(
                @hex.decode(encoded) catch {
                  _ => raise Malformed("invalid hex byte string")
                },
              ),
            ),
            false,
          )
        }
        return self.emit(Word(word), false)
      }
    }
  }
  let operator = match c {
    '=' | '!' | '<' | '>' | '&' | '|' | '^' | '+' | '*' | '/' => {
      let start = self.pos
      self.pos += 1
      if self.pos < self.chars.length() &&
        (
          (c == '=' && self.chars[self.pos] == '=') ||
          (c == '!' && self.chars[self.pos] == '=') ||
          ((c == '<' || c == '>') && self.chars[self.pos] == '=') ||
          ((c == '&' || c == '|') && self.chars[self.pos] == c)
        ) {
        self.pos += 1
        if (c == '=' || c == '!') &&
          self.pos < self.chars.length() &&
          self.chars[self.pos] == '=' {
          self.pos += 1
        }
      }
      Some(String::from_array(self.chars[start:self.pos]))
    }
    _ => None
  }
  match operator {
    Some(value) => self.emit(Operator(value), true)
    None => raise Unsupported("Datalog token")
  }
}

///|
fn looks_like_date(chars : Array[Char], start : Int32) -> Bool {
  start + 10 < chars.length() &&
  chars[start + 4] == '-' &&
  chars[start + 7] == '-' &&
  chars[start + 10] == 'T'
}

///|
fn parse_date_seconds(text : String) -> Int64 raise TokenError {
  let chars = text.to_array()
  if chars.length() < 20 ||
    chars[4] != '-' ||
    chars[7] != '-' ||
    chars[10] != 'T' ||
    chars[13] != ':' ||
    chars[16] != ':' {
    raise Malformed("invalid RFC 3339 date")
  }
  let year = parse_date_part(chars, 0, 4)
  let month = parse_date_part(chars, 5, 2)
  let day = parse_date_part(chars, 8, 2)
  let hour = parse_date_part(chars, 11, 2)
  let minute = parse_date_part(chars, 14, 2)
  let second = parse_date_part(chars, 17, 2)
  if month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59 {
    raise Malformed("RFC 3339 date component is out of range")
  }
  let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
  let month_days = [
    31,
    if leap {
      29
    } else {
      28
    },
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ]
  if day < 1 || day > month_days[month - 1] {
    raise Malformed("RFC 3339 day is out of range")
  }
  let mut offset_seconds = 0
  if chars[chars.length() - 1] != 'Z' {
    let offset_start = 19
    if chars.length() != 25 ||
      (chars[offset_start] != '+' && chars[offset_start] != '-') ||
      chars[22] != ':' {
      raise Malformed("invalid RFC 3339 timezone")
    }
    let offset_hour = parse_date_part(chars, 20, 2)
    let offset_minute = parse_date_part(chars, 23, 2)
    if offset_hour > 23 || offset_minute > 59 {
      raise Malformed("RFC 3339 timezone is out of range")
    }
    let sign = if chars[offset_start] == '+' { 1 } else { -1 }
    offset_seconds = (offset_hour * 3600 + offset_minute * 60) * sign
  } else if chars.length() != 20 {
    raise Malformed("invalid RFC 3339 UTC date")
  }
  let year_offset = if month <= 2 { 1 } else { 0 }
  let adjusted_year = year - year_offset
  let era = adjusted_year / 400
  let year_of_era = adjusted_year - era * 400
  let month_offset = if month > 2 { -3 } else { 9 }
  let adjusted_month = month + month_offset
  let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1
  let day_of_era = year_of_era * 365 +
    year_of_era / 4 -
    year_of_era / 100 +
    day_of_year
  let days = era.to_int64() * 146097L + day_of_era.to_int64() - 719468L
  days * 86400L +
  hour.to_int64() * 3600L +
  minute.to_int64() * 60L +
  second.to_int64() -
  offset_seconds.to_int64()
}

///|
fn parse_date_part(
  chars : Array[Char],
  start : Int32,
  length : Int32,
) -> Int32 raise TokenError {
  let mut value = 0
  for i = start; i < start + length; i = i + 1 {
    if i >= chars.length() || !chars[i].is_ascii_digit() {
      raise Malformed("invalid RFC 3339 date digits")
    }
    value = value * 10 + chars[i].to_int() - '0'.to_int()
  }
  value
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
fn to_map_key(value : Value) -> MapKey raise TokenError {
  match value {
    Number(value) => IntegerKey(value)
    Text(value) => StringKey(value)
    _ => raise Malformed("map keys must be strings or integers")
  }
}

///|
fn parse_map(
  parser : Parser,
  first_key : Value,
  depth : Int32,
) -> Value raise TokenError {
  let entries : Array[(MapKey, Value)] = []
  let mut key_value = first_key
  let mut finished = false
  while !finished {
    if entries.length() >= 1024 {
      raise Malformed("map exceeds 1024 entries")
    }
    let key = to_map_key(key_value)
    if parser.current != Colon {
      raise Malformed("expected ':' after map key")
    }
    parser.advance()
    let value = parse_value(parser, depth + 1)
    for (existing, _) in entries {
      if existing == key {
        raise Malformed("duplicate map key")
      }
    }
    entries.push((key, value))
    match parser.current {
      Comma => {
        parser.advance()
        key_value = parse_value(parser, depth + 1)
      }
      RightBrace => finished = true
      _ => raise Malformed("expected ',' or '}' in map")
    }
  }
  if parser.current != RightBrace {
    raise Malformed("unclosed map")
  }
  parser.advance()
  MapValue(entries)
}

///|
fn parse_set(
  parser : Parser,
  first : Value,
  depth : Int32,
) -> Value raise TokenError {
  let values : Array[Value] = []
  let mut value = first
  let mut finished = false
  while !finished {
    if values.length() >= 1024 {
      raise Malformed("set exceeds 1024 items")
    }
    match value {
      SetValue(_) => raise Malformed("nested sets are not supported")
      _ => ()
    }
    if !values.contains(value) {
      values.push(value)
    }
    match parser.current {
      Comma => {
        parser.advance()
        value = parse_value(parser, depth + 1)
      }
      RightBrace => finished = true
      _ => raise Malformed("expected ',' or '}' in set")
    }
  }
  if parser.current != RightBrace {
    raise Malformed("unclosed set")
  }
  parser.advance()
  SetValue(values)
}

///|
fn parse_value(parser : Parser, depth : Int32) -> Value raise TokenError {
  if depth > 32 {
    raise Malformed("value nesting exceeds 32 levels")
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
    LeftBrace => {
      parser.advance()
      if parser.current == Comma {
        parser.advance()
        if parser.current != RightBrace {
          raise Malformed("invalid empty set")
        }
        parser.advance()
        SetValue([])
      } else if parser.current == RightBrace {
        parser.advance()
        MapValue([])
      } else {
        let first = parse_value(parser, depth + 1)
        if parser.current == Colon {
          parse_map(parser, first, depth + 1)
        } else {
          parse_set(parser, first, depth + 1)
        }
      }
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
  let lexer = Lexer::{ chars: text.to_array(), pos: 0, expect_value: true, }
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
        Literal(_) | LeftBracket | LeftBrace =>
          terms.push(Constant(parse_value(parser, 0)))
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
/// Parse the scope list after `trusting`, e.g. `authority, previous` or
/// `ed25519/0011...`.
pub fn parse_trust_scopes(text : String) -> Array[TrustScope] raise TokenError {
  let scopes : Array[TrustScope] = []
  for part in split_top_level(text, ',') {
    let entry = part.trim().to_owned()
    let scope = match entry {
      "authority" => TrustAuthority
      "previous" => TrustPrevious
      _ if entry.has_prefix("ed25519/") => {
        let encoded = String::from_array(entry.to_array()[8:])
        let key = @hex.decode(encoded) catch {
          _ => raise Malformed("invalid Ed25519 scope public key")
        }
        if key.length() != 32 {
          raise Malformed("Ed25519 scope public key must be 32 bytes")
        }
        TrustPublicKey(key)
      }
      _ if entry.has_prefix("secp256r1/") =>
        raise Unsupported("P-256 scope public keys are not supported")
      _ => raise Malformed("unknown trusted-origin scope")
    }
    if !scopes.contains(scope) {
      scopes.push(scope)
    }
  }
  if scopes.length() == 0 {
    raise Malformed("empty trusted-origin scope")
  }
  scopes
}

///|
fn split_scope_suffix(
  text : String,
) -> (String, Array[TrustScope]) raise TokenError {
  let chars = text.to_array()
  let mut depth = 0
  let mut quoted = false
  let mut escaped = false
  let mut index = 0
  while index < chars.length() {
    let c = chars[index]
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
    } else if c == '(' || c == '[' || c == '{' {
      depth += 1
    } else if c == ')' || c == ']' || c == '}' {
      depth -= 1
    } else if depth == 0 &&
      c.is_whitespace() &&
      index + 9 <= chars.length() &&
      String::from_array(chars[index + 1:index + 9]) == "trusting" &&
      index + 9 < chars.length() &&
      chars[index + 9].is_whitespace() {
      let source = String::from_array(chars[0:index]).trim().to_owned()
      let scope_text = String::from_array(chars[index + 10:]).trim().to_owned()
      return (source, parse_trust_scopes(scope_text))
    }
    index += 1
  }
  (text, [])
}

///|
/// Parse a conjunction used by a check or policy, e.g. `user($u), role($u, "admin")`.
pub fn parse_query_body(text : String) -> Query raise TokenError {
  let (query_text, scopes) = split_scope_suffix(text)
  let parts = split_top_level(query_text, ',')
  let body : Array[Predicate] = []
  let conditions : Array[Condition] = []
  for part in parts {
    let term = part.trim().to_owned()
    if looks_like_predicate(term) {
      body.push(parse_predicate(term, allow_variables=true))
    } else {
      conditions.push(parse_condition(term))
    }
  }
  if body.length() == 0 && conditions.length() == 0 {
    raise Malformed("query body is empty")
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
  for condition in conditions {
    validate_condition_bindings(condition, bound)
  }
  { body, conditions, scopes, }
}

///|
/// Enforce the range restriction shared by text and protobuf-decoded rules.
fn validate_rule_safety(rule : Rule) -> Unit raise TokenError {
  let bound : Array[String] = []
  for predicate in rule.body {
    for term in predicate.terms {
      match term {
        Variable(name) => if !bound.contains(name) { bound.push(name) }
        Constant(_) => ()
      }
    }
  }
  for term in rule.head.terms {
    match term {
      Variable(name) if !bound.contains(name) =>
        raise Malformed("unsafe rule head variable")
      _ => ()
    }
  }
  for condition in rule.conditions {
    validate_condition_bindings(condition, bound)
  }
}

///|
fn looks_like_predicate(text : String) -> Bool {
  let chars = text.to_array()
  if chars.length() == 0 || !is_ident_start(chars[0]) {
    return false
  }
  let mut index = 1
  while index < chars.length() && is_ident_continue(chars[index]) {
    index += 1
  }
  while index < chars.length() && chars[index].is_whitespace() {
    index += 1
  }
  index < chars.length() && chars[index] == '('
}

///|
fn validate_condition_bindings(
  condition : Condition,
  bound : Array[String],
) -> Unit raise TokenError {
  for name in condition_references(condition) {
    if !bound.contains(name) {
      raise Malformed("expression references an unbound variable")
    }
  }
  for operation in condition.operations {
    match operation {
      Closure(closure) =>
        for name in closure.parameters {
          if bound.contains(name) {
            raise Malformed("closure parameter shadows an existing variable")
          }
        }
      _ => ()
    }
  }
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
    } else if c == '(' || c == '[' || c == '{' {
      depth += 1
    } else if c == ')' || c == ']' || c == '}' {
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

///|
fn expression_operator(source : String) -> (Int32, BinaryOperator, Bool, Bool)? {
  match source {
    "*" => Some((8, Multiply, false, false))
    "/" => Some((8, Divide, false, false))
    "+" => Some((7, Add, false, false))
    "-" => Some((7, Subtract, false, false))
    "&" => Some((6, BitwiseAnd, false, false))
    "|" => Some((5, BitwiseOr, false, false))
    "^" => Some((4, BitwiseXor, false, false))
    "<" => Some((3, LessThan, true, false))
    ">" => Some((3, GreaterThan, true, false))
    "<=" => Some((3, LessOrEqual, true, false))
    ">=" => Some((3, GreaterOrEqual, true, false))
    "===" => Some((3, StrictEqual, true, false))
    "!==" => Some((3, StrictNotEqual, true, false))
    "==" => Some((3, LenientEqual, true, false))
    "!=" => Some((3, LenientNotEqual, true, false))
    "&&" => Some((2, LazyAnd, false, true))
    "||" => Some((1, LazyOr, false, true))
    _ => None
  }
}

///|
fn parse_expression_primary(
  parser : Parser,
) -> Array[ExpressionOp] raise TokenError {
  let operations : Array[ExpressionOp] = match parser.current {
    VariableName(name) => {
      parser.advance()
      [Value(Reference(name))]
    }
    Literal(_) | LeftBracket | LeftBrace =>
      [Value(Literal(parse_value(parser, 0)))]
    Operator("!") => {
      parser.advance()
      let nested = parse_expression_ops(parser, 9)
      nested.push(Unary(Negate))
      nested
    }
    LeftParen => {
      parser.advance()
      let nested = parse_expression_ops(parser, 0)
      if parser.current != RightParen {
        raise Malformed("unclosed parenthesized expression")
      }
      parser.advance()
      let result = nested.copy()
      result.push(Unary(Parens))
      result
    }
    _ => raise Malformed("expected Datalog expression operand")
  }
  parse_expression_methods(parser, operations)
}

///|
fn parse_expression_methods(
  parser : Parser,
  initial : Array[ExpressionOp],
) -> Array[ExpressionOp] raise TokenError {
  let operations = initial
  while parser.current == Dot {
    parser.advance()
    let method_name = match parser.current {
      Word(name) => name
      _ => raise Malformed("expected method_name name after '.'")
    }
    parser.advance()
    if parser.current != LeftParen {
      raise Malformed("expected '(' after method_name name")
    }
    parser.advance()
    if method_name == "length" || method_name == "type" {
      if parser.current != RightParen {
        raise Malformed("method_name takes no arguments")
      }
      parser.advance()
      operations.push(
        Unary(if method_name == "length" { Length } else { TypeOf }),
      )
    } else if method_name == "any" || method_name == "all" {
      let parameter = match parser.current {
        VariableName(name) => name
        _ =>
          raise Malformed("collection method_name expects a closure parameter")
      }
      parser.advance()
      if parser.current != Arrow {
        raise Malformed("expected '->' in closure")
      }
      parser.advance()
      let body = parse_expression_ops(parser, 0)
      if parser.current != RightParen {
        raise Malformed("unclosed closure argument")
      }
      parser.advance()
      operations.push(Closure({ parameters: [parameter], operations: body, }))
      operations.push(Binary(if method_name == "any" { Any } else { All }))
    } else if method_name == "try_or" {
      let fallback = parse_expression_ops(parser, 0)
      if parser.current != RightParen {
        raise Malformed("try_or expects one argument")
      }
      parser.advance()
      let left = operations.copy()
      operations.clear()
      operations.push(Closure({ parameters: [], operations: left, }))
      for operation in fallback {
        operations.push(operation)
      }
      operations.push(Binary(TryOr))
    } else if method_name.has_prefix("extern::") {
      let name = String::from_array(method_name.to_array()[8:])
      if parser.current == RightParen {
        parser.advance()
        operations.push(Unary(ExternalUnary(name)))
      } else {
        let argument = parse_expression_ops(parser, 0)
        if parser.current != RightParen {
          raise Malformed("external binary call expects one argument")
        }
        parser.advance()
        for operation in argument {
          operations.push(operation)
        }
        operations.push(Binary(ExternalBinary(name)))
      }
    } else {
      let argument = parse_expression_ops(parser, 0)
      if parser.current != RightParen {
        raise Malformed("method_name expects one argument")
      }
      parser.advance()
      for operation in argument {
        operations.push(operation)
      }
      let operator = match method_name {
        "contains" => Contains
        "starts_with" => Prefix
        "ends_with" => Suffix
        "matches" => Regex
        "intersection" => Intersection
        "union" => Union
        "get" => Get
        _ => raise Unsupported("Datalog method_name " + method_name)
      }
      operations.push(Binary(operator))
    }
  }
  operations
}

///|
fn parse_expression_ops(
  parser : Parser,
  minimum_precedence : Int32,
) -> Array[ExpressionOp] raise TokenError {
  let result = parse_expression_primary(parser)
  let mut saw_comparison = false
  while true {
    let (precedence, operator, is_comparison, is_lazy) = match parser.current {
      Operator(source) =>
        match expression_operator(source) {
          Some(info) => info
          None => break
        }
      _ => break
    }
    if precedence < minimum_precedence {
      break
    }
    if is_comparison && saw_comparison {
      raise Malformed("comparison operators are not associative")
    }
    parser.advance()
    let right = parse_expression_ops(parser, precedence + 1)
    if is_lazy {
      result.push(Closure({ parameters: [], operations: right, }))
    } else {
      for operation in right {
        result.push(operation)
      }
    }
    result.push(Binary(operator))
    saw_comparison = saw_comparison || is_comparison
  }
  result
}

///|
fn parse_condition(text : String) -> Condition raise TokenError {
  if text.trim().length() == 0 {
    raise Malformed("empty Datalog expression")
  }
  let parser = Parser::{
    lexer: Lexer::{ chars: text.to_array(), pos: 0, expect_value: true, },
    current: End,
  }
  parser.advance()
  let operations = parse_expression_ops(parser, 0)
  if parser.current != End {
    raise Malformed("trailing input after Datalog expression")
  }
  validate_expression_program(operations, 0)
  { operations, }
}

///|
/// Parse a positive Datalog rule such as
/// `grandparent($x, $z) <- parent($x, $y), parent($y, $z)`.
/// The body may contain predicates and full postfix-compatible expressions.
pub fn parse_rule(text : String) -> Rule raise TokenError {
  if text.length() > 65536 {
    raise Malformed("rule exceeds 64 KiB")
  }
  let separator = match find_rule_separator(text) {
    Some(index) => index
    None => raise Malformed("expected '<-' in rule")
  }
  let chars = text.to_array()
  let head_text = String::from_array(chars[0:separator]).trim().to_owned()
  let body_source = String::from_array(chars[separator + 2:]).trim().to_owned()
  let (body_text, scopes) = split_scope_suffix(body_source)
  let head = parse_predicate(head_text, allow_variables=true)
  let body_parts = split_top_level(body_text, ',')
  let body : Array[Predicate] = []
  let conditions : Array[Condition] = []
  for part in body_parts {
    let item = part.trim().to_owned()
    if looks_like_predicate(item) {
      body.push(parse_predicate(item, allow_variables=true))
    } else {
      conditions.push(parse_condition(item))
    }
  }
  if body.length() == 0 && conditions.length() == 0 {
    raise Malformed("rule body is empty")
  }
  let rule = { head, body, conditions, scopes, }
  validate_rule_safety(rule)
  rule
}

///|
/// Locate the top-level rule arrow while ignoring strings and nested values.
fn find_rule_separator(text : String) -> Int32? {
  let chars = text.to_array()
  let mut quoted = false
  let mut escaped = false
  let mut depth = 0
  let mut i = 0
  while i + 1 < chars.length() {
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
      i += 1
    } else if depth == 0 && c == '<' && chars[i + 1] == '-' {
      return Some(i)
    } else {
      i += 1
    }
  }
  None
}

///|
/// Parse one conjunctive check body. Use `Check::{queries: [...]}` directly
/// when a check needs multiple alternative query bodies.
pub fn parse_check_body(
  text : String,
  mode : CheckMode,
) -> Check raise TokenError {
  { mode, queries: [parse_query_body(text)], }
}

///|
/// Parse one conjunctive policy body. Policies are evaluated in caller order.
pub fn parse_policy_body(
  text : String,
  kind : PolicyKind,
) -> Policy raise TokenError {
  { kind, queries: [parse_query_body(text)], }
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
  derive_facts_with_externals(initial, rules, max_facts, max_iterations, ExternalFunctions::{
    unary: Map([]),
    binary: Map([]),
  })
}

///|
/// Compute rule closures while resolving registered external functions.
pub fn derive_facts_with_externals(
  initial : Array[Fact],
  rules : Array[Rule],
  max_facts : Int32,
  max_iterations : Int32,
  externals : ExternalFunctions,
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
        if rule.conditions.all(condition => {
            condition_matches_with_externals(condition, bindings, externals)
          }) {
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
  evaluate_policy_set_with_externals(facts, checks, policies, ExternalFunctions::{
    unary: Map([]),
    binary: Map([]),
  })
}

///|
/// Evaluate checks and policies with an explicit, caller-controlled FFI table.
pub fn evaluate_policy_set_with_externals(
  facts : Array[Fact],
  checks : Array[Check],
  policies : Array[Policy],
  externals : ExternalFunctions,
) -> Unit raise AuthorizationError {
  for i = 0; i < checks.length(); i = i + 1 {
    let check = checks[i]
    if check.queries.length() == 0 {
      raise EmptyCheck(i)
    }
    let matched = match check.mode {
      Any =>
        check.queries.any(q => query_matches_with_externals(q, facts, externals))
      All =>
        check.queries.any(q => {
          query_all_matches_with_externals(q, facts, externals)
        })
      // Queries in a reject check are alternatives: any matching query rejects.
      // The check succeeds only when none of them match.
      Reject =>
        !check.queries.any(q => {
          query_matches_with_externals(q, facts, externals)
        })
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
    if policy.queries.any(q => query_matches_with_externals(q, facts, externals)) {
      match policy.kind {
        Allow => return
        Deny => raise Denied(i)
      }
    }
  }
  raise NoMatchingPolicy
}

///|
fn query_matches_with_externals(
  query : Query,
  facts : Array[Fact],
  externals : ExternalFunctions,
) -> Bool raise AuthorizationError {
  let rule = Rule::{
    head: Predicate::{ name: "__query_result", terms: [], },
    body: query.body,
    conditions: query.conditions,
    scopes: [],
  }
  for bindings in rule_bindings(rule, facts, 10000) {
    if query.conditions.all(condition => {
        condition_matches_with_externals(condition, bindings, externals)
      }) {
      return true
    }
  }
  false
}

///|
/// `check all` requires at least one body match and every matched binding to
/// satisfy every condition in the query.
fn query_all_matches_with_externals(
  query : Query,
  facts : Array[Fact],
  externals : ExternalFunctions,
) -> Bool raise AuthorizationError {
  let rule = Rule::{
    head: Predicate::{ name: "__query_result", terms: [], },
    body: query.body,
    conditions: query.conditions,
    scopes: [],
  }
  let bindings = rule_bindings(rule, facts, 10000)
  if bindings.length() == 0 {
    return false
  }
  for binding in bindings {
    if !query.conditions.all(condition => {
        condition_matches_with_externals(condition, binding, externals)
      }) {
      return false
    }
  }
  true
}

///|

///|
fn condition_matches_with_externals(
  condition : Condition,
  bindings : Map[String, Value],
  externals : ExternalFunctions,
) -> Bool raise AuthorizationError {
  match
    evaluate_expression_with_externals(
      condition.operations,
      bindings,
      10000,
      externals,
    ) {
    Boolean(result) => result
    _ =>
      raise Expression(
        TypeMismatch("Datalog expression did not return a boolean"),
      )
  }
}

///|
fn condition_references(condition : Condition) -> Array[String] {
  expression_references(condition.operations, [])
}

///|
fn expression_references(
  operations : Array[ExpressionOp],
  local_names : Array[String],
) -> Array[String] {
  let result : Array[String] = []
  for operation in operations {
    match operation {
      Value(Reference(name)) if !local_names.contains(name) =>
        if !result.contains(name) {
          result.push(name)
        }
      Closure(closure) => {
        let nested_names = local_names.copy()
        for name in closure.parameters {
          if !nested_names.contains(name) {
            nested_names.push(name)
          }
        }
        for name in expression_references(closure.operations, nested_names) {
          if !local_names.contains(name) && !result.contains(name) {
            result.push(name)
          }
        }
      }
      _ => ()
    }
  }
  result
}
