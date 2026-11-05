///|
priv struct EncoderSymbols {
  indices : Map[String, UInt64]
  custom : Array[String]
  mut offset : UInt64
}

///|
fn EncoderSymbols::new() -> EncoderSymbols {
  let indices : Map[String, UInt64] = Map([])
  let defaults = [
    "read", "write", "resource", "operation", "right", "time", "role", "owner", "tenant",
    "namespace", "user", "team", "service", "admin", "email", "group", "member",
    "ip_address", "client", "client_ip", "domain", "path", "version", "cluster",
    "node", "hostname", "nonce", "query",
  ]
  for i = 0; i < defaults.length(); i = i + 1 {
    indices[defaults[i]] = i.to_uint64()
  }
  { indices, custom: [], offset: 0UL, }
}

///|
fn EncoderSymbols::with_existing(
  existing : Array[String],
) -> EncoderSymbols raise TokenError {
  let symbols = EncoderSymbols::new()
  if existing.length() > 3072 {
    raise Malformed("existing symbol table exceeds 4096 entries")
  }
  for i = 0; i < existing.length(); i = i + 1 {
    let value = existing[i]
    if symbols.indices.contains(value) {
      raise Malformed("duplicate existing symbol")
    }
    symbols.indices[value] = 1024UL + i.to_uint64()
  }
  symbols.offset = existing.length().to_uint64()
  symbols
}

///|
fn EncoderSymbols::intern(
  self : EncoderSymbols,
  value : String,
) -> UInt64 raise TokenError {
  match self.indices.get(value) {
    Some(index) => index
    None => {
      if self.offset + self.custom.length().to_uint64() >= 3072UL {
        raise Malformed("symbol table exceeds 4096 entries")
      }
      let index = 1024UL + self.offset + self.custom.length().to_uint64()
      self.custom.push(value)
      self.indices[value] = index
      index
    }
  }
}

///|
fn encode_varint64(value : UInt64) -> Bytes {
  let bytes : Array[Byte] = []
  let mut rest = value
  while rest >= 128 {
    bytes.push(((rest & 127) | 128).to_byte())
    rest = rest >> 7
  }
  bytes.push(rest.to_byte())
  Bytes::from_array(bytes)
}

///|
fn encode_varint_field(tag : Int32, value : UInt64) -> Bytes {
  encode_varint64(tag.to_uint64()) + encode_varint64(value)
}

///|
fn encode_bytes_field64(tag : Int32, value : Bytes) -> Bytes {
  encode_varint64(tag.to_uint64()) +
  encode_varint64(value.length().to_uint64()) +
  value
}

///|
fn extend_bytes(target : Array[Byte], source : Bytes) -> Unit {
  for index = 0; index < source.length(); index = index + 1 {
    target.push(source[index])
  }
}

///|
fn encode_utf8(value : String) -> Bytes {
  let output : Array[Byte] = []
  for character in value.to_array() {
    let code = character.to_int()
    if code <= 0x7f {
      output.push(code.to_byte())
    } else if code <= 0x7ff {
      output.push((0xc0 | (code >> 6)).to_byte())
      output.push((0x80 | (code & 0x3f)).to_byte())
    } else if code <= 0xffff {
      output.push((0xe0 | (code >> 12)).to_byte())
      output.push((0x80 | ((code >> 6) & 0x3f)).to_byte())
      output.push((0x80 | (code & 0x3f)).to_byte())
    } else {
      output.push((0xf0 | (code >> 18)).to_byte())
      output.push((0x80 | ((code >> 12) & 0x3f)).to_byte())
      output.push((0x80 | ((code >> 6) & 0x3f)).to_byte())
      output.push((0x80 | (code & 0x3f)).to_byte())
    }
  }
  Bytes::from_array(output)
}

///|
fn validate_value_version(
  value : Value,
  version : Int32,
  depth : Int32,
) -> Unit raise TokenError {
  if depth > 16 {
    raise Malformed("term nesting exceeds 16 levels")
  }
  match value {
    Null | ArrayValue(_) | SetValue(_) | MapValue(_) if version < 6 =>
      raise Unsupported(
        "null, collections and maps require Datalog version 3.3",
      )
    ArrayValue(values) | SetValue(values) =>
      for item in values {
        validate_value_version(item, version, depth + 1)
      }
    MapValue(entries) =>
      for (_, item) in entries {
        validate_value_version(item, version, depth + 1)
      }
    _ => ()
  }
}

///|
fn encode_term(
  value : Value,
  symbols : EncoderSymbols,
  version : Int32,
  depth : Int32,
) -> Bytes raise TokenError {
  validate_value_version(value, version, depth)
  match value {
    Number(number) => encode_varint_field(16, number.reinterpret_as_uint64())
    Text(text) => encode_varint_field(24, symbols.intern(text))
    Date(timestamp) =>
      encode_varint_field(32, timestamp.reinterpret_as_uint64())
    ByteString(bytes) => encode_bytes_field64(42, bytes)
    Boolean(value) => encode_varint_field(48, if value { 1UL } else { 0UL })
    SetValue(values) => {
      let content : Array[Byte] = []
      let unique : Array[Value] = []
      for item in values {
        if item is SetValue(_) {
          raise Malformed("nested sets are not supported")
        }
        if !unique.contains(item) {
          unique.push(item)
          extend_bytes(
            content,
            encode_bytes_field64(
              10,
              encode_term(item, symbols, version, depth + 1),
            ),
          )
        }
      }
      encode_bytes_field64(58, Bytes::from_array(content))
    }
    Null => encode_bytes_field64(66, b"")
    ArrayValue(values) => {
      let content : Array[Byte] = []
      if values.length() > 1024 {
        raise Malformed("array exceeds 1024 items")
      }
      for item in values {
        extend_bytes(
          content,
          encode_bytes_field64(
            10,
            encode_term(item, symbols, version, depth + 1),
          ),
        )
      }
      encode_bytes_field64(74, Bytes::from_array(content))
    }
    MapValue(entries) => {
      if entries.length() > 1024 {
        raise Malformed("map exceeds 1024 entries")
      }
      let content : Array[Byte] = []
      let keys : Array[MapKey] = []
      for (key, value) in entries {
        if keys.contains(key) {
          raise Malformed("duplicate map key")
        }
        keys.push(key)
        let encoded_key = match key {
          IntegerKey(number) =>
            encode_varint_field(8, number.reinterpret_as_uint64())
          StringKey(text) => encode_varint_field(16, symbols.intern(text))
        }
        let entry = encode_bytes_field64(10, encoded_key) +
          encode_bytes_field64(
            18,
            encode_term(value, symbols, version, depth + 1),
          )
        extend_bytes(content, encode_bytes_field64(10, entry))
      }
      encode_bytes_field64(82, Bytes::from_array(content))
    }
  }
}

///|
fn encode_predicate(
  predicate : Predicate,
  symbols : EncoderSymbols,
  version : Int32,
) -> Bytes raise TokenError {
  if predicate.terms.length() > 128 {
    raise Malformed("predicate has too many terms")
  }
  let content : Array[Byte] = []
  extend_bytes(content, encode_varint_field(8, symbols.intern(predicate.name)))
  for term in predicate.terms {
    let encoded = match term {
      Constant(value) => encode_term(value, symbols, version, 0)
      Variable(name) => encode_varint_field(8, symbols.intern(name))
    }
    extend_bytes(content, encode_bytes_field64(18, encoded))
  }
  Bytes::from_array(content)
}

///|
fn encode_fact(
  fact : Fact,
  symbols : EncoderSymbols,
  version : Int32,
) -> Bytes raise TokenError {
  let terms : Array[QueryTerm] = []
  for value in fact.values {
    terms.push(Constant(value))
  }
  let predicate = Predicate::{ name: fact.name, terms, }
  encode_bytes_field64(10, encode_predicate(predicate, symbols, version))
}

///|
fn validate_rule(rule : Rule) -> Unit raise TokenError {
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
    for operand in [condition.left, condition.right] {
      match operand {
        Reference(name) if !bound.contains(name) =>
          raise Malformed("rule expression references an unbound variable")
        _ => ()
      }
    }
  }
}

///|
fn encode_expression_value(
  operand : ExpressionValue,
  symbols : EncoderSymbols,
  version : Int32,
) -> Bytes raise TokenError {
  let term = match operand {
    Literal(value) => encode_term(value, symbols, version, 0)
    Reference(name) => encode_varint_field(8, symbols.intern(name))
  }
  let operand = encode_bytes_field64(10, term)
  encode_bytes_field64(10, operand)
}

///|
fn encode_condition(
  condition : Condition,
  symbols : EncoderSymbols,
  version : Int32,
) -> Bytes raise TokenError {
  let operator = match condition.operator {
    LessThan => 0
    GreaterThan => 1
    LessOrEqual => 2
    GreaterOrEqual => 3
    Equal => 4
    NotEqual if version >= 4 => 20
    NotEqual => raise Unsupported("not-equal requires Datalog version 3.1")
  }
  let binary = encode_varint_field(8, operator.to_uint64())
  let content = encode_expression_value(condition.left, symbols, version) +
    encode_expression_value(condition.right, symbols, version) +
    encode_bytes_field64(10, encode_bytes_field64(26, binary))
  encode_bytes_field64(26, content)
}

///|
fn encode_rule(
  rule : Rule,
  symbols : EncoderSymbols,
  version : Int32,
) -> Bytes raise TokenError {
  validate_rule(rule)
  let content : Array[Byte] = []
  extend_bytes(
    content,
    encode_bytes_field64(10, encode_predicate(rule.head, symbols, version)),
  )
  for predicate in rule.body {
    extend_bytes(
      content,
      encode_bytes_field64(18, encode_predicate(predicate, symbols, version)),
    )
  }
  for condition in rule.conditions {
    extend_bytes(content, encode_condition(condition, symbols, version))
  }
  Bytes::from_array(content)
}

///|
fn encode_query_rule(
  query : Query,
  symbols : EncoderSymbols,
  version : Int32,
) -> Bytes raise TokenError {
  if query.body.length() == 0 && query.conditions.length() > 0 {
    raise Malformed("query expressions need a predicate body")
  }
  let content : Array[Byte] = []
  let head = Predicate::{ name: "query", terms: [], }
  extend_bytes(
    content,
    encode_bytes_field64(10, encode_predicate(head, symbols, version)),
  )
  for predicate in query.body {
    extend_bytes(
      content,
      encode_bytes_field64(18, encode_predicate(predicate, symbols, version)),
    )
  }
  let bound : Array[String] = []
  for predicate in query.body {
    for term in predicate.terms {
      match term {
        Variable(name) => if !bound.contains(name) { bound.push(name) }
        Constant(_) => ()
      }
    }
  }
  for condition in query.conditions {
    for operand in [condition.left, condition.right] {
      match operand {
        Reference(name) if !bound.contains(name) =>
          raise Malformed("check expression references an unbound variable")
        _ => ()
      }
    }
    extend_bytes(content, encode_condition(condition, symbols, version))
  }
  Bytes::from_array(content)
}

///|
fn encode_check(
  check : Check,
  symbols : EncoderSymbols,
  version : Int32,
) -> Bytes raise TokenError {
  if check.queries.length() == 0 {
    raise Malformed("check has no queries")
  }
  let content : Array[Byte] = []
  for query in check.queries {
    extend_bytes(
      content,
      encode_bytes_field64(10, encode_query_rule(query, symbols, version)),
    )
  }
  match check.mode {
    Any => ()
    All if version >= 4 => extend_bytes(content, encode_varint_field(16, 1UL))
    All => raise Unsupported("check all requires Datalog version 3.1")
    Reject if version >= 6 =>
      extend_bytes(content, encode_varint_field(16, 2UL))
    Reject => raise Unsupported("reject checks require Datalog version 3.3")
  }
  encode_bytes_field64(50, Bytes::from_array(content))
}

///|
/// Serialize a v3 block containing facts, positive rules and checks.
/// Policies are authorizer input and are not stored in token blocks.
fn encode_block_with_symbols(
  facts : Array[Fact],
  rules : Array[Rule],
  checks : Array[Check],
  version : Int32,
  existing_symbols : Array[String],
) -> Bytes raise TokenError {
  if version < 3 || version > 6 {
    raise Unsupported("Datalog version outside the supported v3.0-v3.3 range")
  }
  if facts.length() > 10000 || rules.length() > 10000 || checks.length() > 1000 {
    raise Malformed("block exceeds an item limit")
  }
  let symbols = EncoderSymbols::with_existing(existing_symbols)
  let encoded_facts : Array[Bytes] = []
  let encoded_rules : Array[Bytes] = []
  let encoded_checks : Array[Bytes] = []
  for fact in facts {
    encoded_facts.push(encode_fact(fact, symbols, version))
  }
  for rule in rules {
    encoded_rules.push(encode_rule(rule, symbols, version))
  }
  for check in checks {
    encoded_checks.push(encode_check(check, symbols, version))
  }
  let content : Array[Byte] = []
  for symbol in symbols.custom {
    extend_bytes(content, encode_bytes_field64(10, encode_utf8(symbol)))
  }
  extend_bytes(content, encode_varint_field(24, version.to_uint64()))
  for fact in encoded_facts {
    extend_bytes(content, encode_bytes_field64(34, fact))
  }
  for rule in encoded_rules {
    extend_bytes(content, encode_bytes_field64(42, rule))
  }
  for check in encoded_checks {
    extend_bytes(content, check)
  }
  let block = Bytes::from_array(content)
  if block.length() > 1048000 {
    raise Malformed("encoded block exceeds 1 MiB")
  }
  block
}

///|
/// Serialize a v3 block with a token's shared custom symbol table.
pub fn encode_block(
  facts : Array[Fact],
  rules : Array[Rule],
  checks : Array[Check],
  version : Int32,
) -> Bytes raise TokenError {
  encode_block_with_symbols(facts, rules, checks, version, [])
}

///|
/// Create a token from structured Datalog data and caller-supplied seeds.
/// Seeds must be independent, fresh, cryptographically random 32-byte values.
pub fn issue(
  facts : Array[Fact],
  rules : Array[Rule],
  checks : Array[Check],
  version : Int32,
  root_seed : Bytes,
  next_seed : Bytes,
) -> Bytes raise TokenError {
  issue_raw(encode_block(facts, rules, checks, version), root_seed, next_seed)
}

///|
/// Attenuate a token by appending checks only. This helper never adds facts or
/// rules, so its output cannot broaden rights through those block contents.
pub fn attenuate(
  token : Bytes,
  root_key : Bytes,
  checks : Array[Check],
  version : Int32,
  next_seed : Bytes,
) -> Bytes raise TokenError {
  if checks.length() == 0 {
    raise Malformed("attenuation requires at least one check")
  }
  let signed = verify_signed_chain(token, root_key)
  let existing_symbols : Array[String] = []
  for block in signed {
    let encoded = parse_encoded_fact_block(block.data)
    for symbol in encoded.symbols {
      let value = @utf8.decode(symbol) catch {
        _ => raise Malformed("invalid UTF-8 symbol")
      }
      if existing_symbols.contains(value) {
        raise Malformed("duplicate symbol in existing token")
      }
      existing_symbols.push(value)
    }
  }
  append_raw(
    token,
    root_key,
    encode_block_with_symbols([], [], checks, version, existing_symbols),
    next_seed,
  )
}
