///|
/// Signature verification does not evaluate Biscuit checks or authorize access.
pub suberror TokenError {
  Malformed(String)
  Unsupported(String)
  InvalidSignature
}

///|
priv struct Reader {
  data : Bytes
  mut pos : Int32
}

///|
fn Reader::varint(self : Reader) -> Int32 raise TokenError {
  let mut value = 0
  for i = 0; i < 5; i = i + 1 {
    if self.pos >= self.data.length() {
      raise Malformed("truncated varint")
    }
    let byte = self.data[self.pos].to_int()
    self.pos += 1
    if i == 4 && byte > 7 {
      raise Malformed("varint exceeds limit")
    }
    value = value | ((byte & 127) << (7 * i))
    if byte < 128 {
      return value
    }
  }
  raise Malformed("invalid varint")
}

///|
fn Reader::bytes(self : Reader) -> Bytes raise TokenError {
  let field_offset = self.pos
  let length = self.varint()
  if length > self.data.length() - self.pos {
    raise Malformed(
      "truncated field: length " +
      length.to_string() +
      ", remaining " +
      (self.data.length() - self.pos).to_string() +
      ", field offset " +
      field_offset.to_string() +
      ", message size " +
      self.data.length().to_string(),
    )
  }
  let start = self.pos
  self.pos += length
  self.data[start:self.pos].to_owned()
}

///|
fn Reader::varint64(self : Reader) -> UInt64 raise TokenError {
  let mut value : UInt64 = 0
  for i = 0; i < 10; i = i + 1 {
    if self.pos >= self.data.length() {
      raise Malformed("truncated varint")
    }
    let byte = self.data[self.pos].to_int()
    self.pos += 1
    if i == 9 && byte > 1 {
      raise Malformed("varint exceeds 64 bits")
    }
    value = value | ((byte & 127).to_uint64() << (7 * i))
    if byte < 128 {
      return value
    }
  }
  raise Malformed("invalid varint")
}

///|
fn default_symbols() -> Array[String] {
  let symbols = Array::make(1024, "")
  let defaults = [
    "read", "write", "resource", "operation", "right", "time", "role", "owner", "tenant",
    "namespace", "user", "team", "service", "admin", "email", "group", "member",
    "ip_address", "client", "client_ip", "domain", "path", "version", "cluster",
    "node", "hostname", "nonce", "query",
  ]
  for i = 0; i < defaults.length(); i = i + 1 {
    symbols[i] = defaults[i]
  }
  symbols
}

///|
fn symbol_at(
  symbols : Array[String],
  index : UInt64,
) -> String raise TokenError {
  if index >= symbols.length().to_uint64() {
    raise Malformed("symbol index out of range")
  }
  symbols[index.to_int()]
}

///|
fn parse_symbols(
  data : Bytes,
  symbols : Array[String],
) -> Unit raise TokenError {
  if symbols.length() >= 4096 {
    raise Malformed("symbol table exceeds 4096 entries")
  }
  let value = @utf8.decode(data) catch {
    _ => raise Malformed("invalid UTF-8 symbol")
  }
  if symbols.contains(value) {
    raise Malformed("duplicate symbol")
  }
  symbols.push(value)
}

///|
fn value_kind(value : Value) -> Int32 {
  match value {
    Text(_) => 0
    Number(_) => 1
    Boolean(_) => 2
    ByteString(_) => 3
    ArrayValue(_) => 4
    Date(_) => 5
    Null => 6
    SetValue(_) => 7
    MapValue(_) => 8
  }
}

///|
fn parse_proto_term(
  data : Bytes,
  symbols : Array[String],
  depth : Int32,
  version : Int32,
) -> Value raise TokenError {
  if depth > 16 {
    raise Malformed("term nesting exceeds 16 levels")
  }
  let r = Reader::{ data, pos: 0, }
  let mut result : Value? = None
  while r.pos < data.length() {
    let tag = r.varint()
    let value : Value? = match tag {
      8 => raise Malformed("fact term contains a variable")
      16 => Some(Number(r.varint64().reinterpret_as_int64()))
      24 => Some(Text(symbol_at(symbols, r.varint64())))
      32 => Some(Date(r.varint64().reinterpret_as_int64()))
      42 => Some(ByteString(r.bytes()))
      48 =>
        Some(
          match r.varint64() {
            0 => Boolean(false)
            1 => Boolean(true)
            _ => raise Malformed("invalid boolean term")
          },
        )
      58 => {
        if version < 3 {
          raise Unsupported("sets require Datalog version 3.0")
        }
        let nested = Reader::{ data: r.bytes(), pos: 0, }
        let values : Array[Value] = []
        while nested.pos < nested.data.length() {
          let nested_tag = nested.varint()
          if nested_tag == 10 {
            if values.length() >= 1024 {
              raise Malformed("set exceeds 1024 items")
            }
            let item = parse_proto_term(
              nested.bytes(),
              symbols,
              depth + 1,
              version,
            )
            if value_kind(item) == 7 {
              raise Malformed("nested sets are not supported")
            }
            if !values.contains(item) {
              values.push(item)
            }
          } else {
            raise Unsupported("unknown set term field")
          }
        }
        Some(SetValue(values))
      }
      66 => {
        if version < 6 {
          raise Unsupported("null requires Datalog version 3.3")
        }
        if r.bytes().length() != 0 {
          raise Malformed("null term payload must be empty")
        }
        Some(Null)
      }
      74 => {
        if version < 6 {
          raise Unsupported("arrays require Datalog version 3.3")
        }
        let nested = Reader::{ data: r.bytes(), pos: 0, }
        let values : Array[Value] = []
        while nested.pos < nested.data.length() {
          let nested_tag = nested.varint()
          if nested_tag == 10 {
            if values.length() >= 1024 {
              raise Malformed("array exceeds 1024 items")
            }
            values.push(
              parse_proto_term(nested.bytes(), symbols, depth + 1, version),
            )
          } else {
            raise Unsupported("unknown array term field")
          }
        }
        Some(ArrayValue(values))
      }
      82 => {
        if version < 6 {
          raise Unsupported("maps require Datalog version 3.3")
        }
        Some(parse_proto_map(r.bytes(), symbols, depth + 1, version))
      }
      _ => raise Unsupported("unknown or malformed term variant")
    }
    match value {
      Some(item) =>
        match result {
          None => result = Some(item)
          Some(_) => raise Malformed("multiple terms in oneof")
        }
      None => ()
    }
  }
  match result {
    Some(value) => value
    None => raise Malformed("term has no value")
  }
}

///|
fn parse_proto_map_key(
  data : Bytes,
  symbols : Array[String],
) -> MapKey raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut key : MapKey? = None
  while r.pos < data.length() {
    let tag = r.varint()
    let parsed = match tag {
      8 => IntegerKey(r.varint64().reinterpret_as_int64())
      16 => StringKey(symbol_at(symbols, r.varint64()))
      _ => raise Unsupported("unknown or malformed map key")
    }
    match key {
      None => key = Some(parsed)
      Some(_) => raise Malformed("map key contains multiple values")
    }
  }
  match key {
    Some(value) => value
    None => raise Malformed("map entry has no key")
  }
}

///|
fn parse_proto_map_entry(
  data : Bytes,
  symbols : Array[String],
  depth : Int32,
  version : Int32,
) -> (MapKey, Value) raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut key : MapKey? = None
  let mut value : Value? = None
  while r.pos < data.length() {
    let tag = r.varint()
    match tag {
      10 if key is None => key = Some(parse_proto_map_key(r.bytes(), symbols))
      10 => raise Malformed("duplicate map entry key")
      18 if value is None =>
        value = Some(parse_proto_term(r.bytes(), symbols, depth, version))
      18 => raise Malformed("duplicate map entry value")
      _ => raise Unsupported("unknown map entry field")
    }
  }
  match (key, value) {
    (Some(k), Some(v)) => (k, v)
    (None, _) => raise Malformed("map entry has no key")
    (_, None) => raise Malformed("map entry has no value")
  }
}

///|
fn parse_proto_map(
  data : Bytes,
  symbols : Array[String],
  depth : Int32,
  version : Int32,
) -> Value raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let entries : Array[(MapKey, Value)] = []
  while r.pos < data.length() {
    let tag = r.varint()
    if tag != 10 {
      raise Unsupported("unknown map field")
    }
    if entries.length() >= 1024 {
      raise Malformed("map exceeds 1024 entries")
    }
    let entry = parse_proto_map_entry(r.bytes(), symbols, depth, version)
    for (key, _) in entries {
      if key == entry.0 {
        raise Malformed("duplicate map key")
      }
    }
    entries.push(entry)
  }
  MapValue(entries)
}

///|
fn parse_proto_query_term(
  data : Bytes,
  symbols : Array[String],
  version : Int32,
) -> QueryTerm raise TokenError {
  let r = Reader::{ data, pos: 0, }
  if r.varint() == 8 {
    let index = r.varint64()
    if r.pos != data.length() {
      raise Malformed("variable term has trailing fields")
    }
    Variable(symbol_at(symbols, index))
  } else {
    Constant(parse_proto_term(data, symbols, 0, version))
  }
}

///|
fn parse_proto_predicate(
  data : Bytes,
  symbols : Array[String],
  version : Int32,
) -> Predicate raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut name : String? = None
  let terms : Array[QueryTerm] = []
  while r.pos < data.length() {
    let tag = r.varint()
    match tag {
      8 if name is None => name = Some(symbol_at(symbols, r.varint64()))
      8 => raise Malformed("duplicate predicate name")
      18 => {
        if terms.length() >= 128 {
          raise Malformed("predicate has too many terms")
        }
        terms.push(parse_proto_query_term(r.bytes(), symbols, version))
      }
      _ => raise Unsupported("unknown predicate field")
    }
  }
  match name {
    Some(value) => { name: value, terms, }
    None => raise Malformed("predicate has no name")
  }
}

///|
fn parse_proto_fact(
  data : Bytes,
  symbols : Array[String],
  version : Int32,
) -> Fact raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut fact : Fact? = None
  while r.pos < data.length() {
    let tag = r.varint()
    if tag == 10 {
      if fact is Some(_) {
        raise Malformed("fact has duplicate predicate")
      }
      let predicate = parse_proto_predicate(r.bytes(), symbols, version)
      let values : Array[Value] = []
      for term in predicate.terms {
        match term {
          Constant(value) => values.push(value)
          Variable(_) => raise Malformed("fact contains a variable")
        }
      }
      fact = Some({ name: predicate.name, values, })
    } else {
      raise Unsupported("unknown fact field")
    }
  }
  match fact {
    Some(value) => value
    None => raise Malformed("fact has no predicate")
  }
}

///|
fn parse_proto_unary(
  data : Bytes,
  symbols : Array[String],
  version : Int32,
) -> UnaryOperator raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut kind : Int32? = None
  let mut ffi_name : String? = None
  while r.pos < data.length() {
    match r.varint() {
      8 if kind is None => kind = Some(r.varint())
      8 => raise Malformed("duplicate unary operator kind")
      16 if ffi_name is None =>
        ffi_name = Some(symbol_at(symbols, r.varint64()))
      16 => raise Malformed("duplicate unary external function name")
      _ => raise Unsupported("unary operator metadata")
    }
  }
  let operator = match kind {
    Some(0) => Negate
    Some(1) => Parens
    Some(2) => Length
    Some(3) if version >= 6 => TypeOf
    Some(3) => raise Unsupported("typeof requires Datalog version 3.3")
    Some(4) if version >= 6 =>
      match ffi_name {
        Some(name) => ExternalUnary(name)
        None => raise Malformed("unary external call has no function name")
      }
    Some(4) => raise Unsupported("external calls require Datalog version 3.3")
    Some(_) => raise Unsupported("unary operator")
    None => raise Malformed("unary operator has no kind")
  }
  if kind != Some(4) && ffi_name is Some(_) {
    raise Malformed("non-external unary operator carries a function name")
  }
  operator
}

///|
fn parse_proto_binary(
  data : Bytes,
  symbols : Array[String],
  version : Int32,
) -> BinaryOperator raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut kind : Int32? = None
  let mut ffi_name : String? = None
  while r.pos < data.length() {
    match r.varint() {
      8 if kind is None => kind = Some(r.varint())
      8 => raise Malformed("duplicate binary operator kind")
      16 if ffi_name is None =>
        ffi_name = Some(symbol_at(symbols, r.varint64()))
      16 => raise Malformed("duplicate binary external function name")
      _ => raise Unsupported("binary operator metadata")
    }
  }
  let operator = match kind {
    Some(0) => LessThan
    Some(1) => GreaterThan
    Some(2) => LessOrEqual
    Some(3) => GreaterOrEqual
    Some(4) => StrictEqual
    Some(5) => Contains
    Some(6) => Prefix
    Some(7) => Suffix
    Some(8) => Regex
    Some(9) => Add
    Some(10) => Subtract
    Some(11) => Multiply
    Some(12) => Divide
    Some(13) => EagerAnd
    Some(14) => EagerOr
    Some(15) => Intersection
    Some(16) => Union
    Some(17) if version >= 4 => BitwiseAnd
    Some(18) if version >= 4 => BitwiseOr
    Some(19) if version >= 4 => BitwiseXor
    Some(17 | 18 | 19) =>
      raise Unsupported("bitwise operators require Datalog version 3.1")
    Some(20) if version >= 4 => StrictNotEqual
    Some(20) =>
      raise Unsupported("strict not-equal requires Datalog version 3.1")
    Some(21) if version >= 6 => LenientEqual
    Some(22) if version >= 6 => LenientNotEqual
    Some(21 | 22) =>
      raise Unsupported("lenient equality requires Datalog version 3.3")
    Some(23) if version >= 6 => LazyAnd
    Some(24) if version >= 6 => LazyOr
    Some(23 | 24) =>
      raise Unsupported("short-circuit operators require Datalog version 3.3")
    Some(25) if version >= 6 => All
    Some(26) if version >= 6 => Any
    Some(25 | 26) =>
      raise Unsupported("array operators require Datalog version 3.3")
    Some(27) if version >= 6 => Get
    Some(27) => raise Unsupported("get requires Datalog version 3.3")
    Some(28) if version >= 6 =>
      match ffi_name {
        Some(name) => ExternalBinary(name)
        None => raise Malformed("binary external call has no function name")
      }
    Some(28) => raise Unsupported("external calls require Datalog version 3.3")
    Some(29) if version >= 6 => TryOr
    Some(29) => raise Unsupported("try requires Datalog version 3.3")
    Some(_) => raise Unsupported("binary operator")
    None => raise Malformed("binary operator has no kind")
  }
  if kind != Some(28) && ffi_name is Some(_) {
    raise Malformed("non-external binary operator carries a function name")
  }
  operator
}

///|
fn parse_proto_closure(
  data : Bytes,
  symbols : Array[String],
  version : Int32,
  depth : Int32,
) -> ExpressionClosure raise TokenError {
  if depth >= 32 {
    raise Malformed("expression closure nesting exceeds 32 levels")
  }
  let r = Reader::{ data, pos: 0, }
  let parameters : Array[String] = []
  let operations : Array[ExpressionOp] = []
  while r.pos < data.length() {
    match r.varint() {
      8 => {
        if parameters.length() >= 32 {
          raise Malformed("closure has too many parameters")
        }
        let name = symbol_at(symbols, r.varint64())
        if parameters.contains(name) {
          raise Malformed("closure has duplicate parameter")
        }
        parameters.push(name)
      }
      18 => {
        if operations.length() >= 256 {
          raise Malformed("closure has too many operations")
        }
        operations.push(
          parse_proto_expression_op(r.bytes(), symbols, version, depth + 1),
        )
      }
      _ => raise Unsupported("unknown closure field")
    }
  }
  validate_expression_program(operations, parameters.length())
  { parameters, operations, }
}

///|
fn parse_proto_expression_op(
  data : Bytes,
  symbols : Array[String],
  version : Int32,
  depth : Int32,
) -> ExpressionOp raise TokenError {
  if depth > 32 {
    raise Malformed("expression closure nesting exceeds 32 levels")
  }
  let r = Reader::{ data, pos: 0, }
  let mut operation : ExpressionOp? = None
  while r.pos < data.length() {
    let tag = r.varint()
    let parsed = match tag {
      10 =>
        match parse_proto_query_term(r.bytes(), symbols, version) {
          Constant(value) => Value(Literal(value))
          Variable(name) => Value(Reference(name))
        }
      18 => Unary(parse_proto_unary(r.bytes(), symbols, version))
      26 => Binary(parse_proto_binary(r.bytes(), symbols, version))
      34 => Closure(parse_proto_closure(r.bytes(), symbols, version, depth + 1))
      _ => raise Unsupported("unknown expression operation")
    }
    match operation {
      None => operation = Some(parsed)
      Some(_) => raise Malformed("expression op contains multiple variants")
    }
  }
  match operation {
    Some(value) => value
    None => raise Malformed("empty expression op")
  }
}

///|
fn parse_proto_expression(
  data : Bytes,
  symbols : Array[String],
  version : Int32,
) -> Condition raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let operations : Array[ExpressionOp] = []
  while r.pos < data.length() {
    let tag = r.varint()
    if tag != 10 {
      raise Unsupported("unknown expression field")
    }
    if operations.length() >= 256 {
      raise Malformed("expression exceeds 256 operations")
    }
    operations.push(parse_proto_expression_op(r.bytes(), symbols, version, 0))
  }
  validate_expression_program(operations, 0)
  { operations, }
}

///|
priv struct ParsedRule {
  rule : Rule
  has_head : Bool
  has_unsupported_expressions : Bool
  has_scopes : Bool
}

///|
fn parse_proto_rule(
  data : Bytes,
  symbols : Array[String],
  public_keys : Array[Bytes],
  version : Int32,
) -> ParsedRule raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut head : Predicate? = None
  let body : Array[Predicate] = []
  let conditions : Array[Condition] = []
  let scope_data : Array[Bytes] = []
  let mut has_unsupported_expressions = false
  let mut has_scopes = false
  while r.pos < data.length() {
    let tag = r.varint()
    match tag {
      10 if head is None =>
        head = Some(parse_proto_predicate(r.bytes(), symbols, version))
      10 => raise Malformed("duplicate rule head")
      18 => {
        if body.length() >= 128 {
          raise Malformed("rule has too many predicates")
        }
        body.push(parse_proto_predicate(r.bytes(), symbols, version))
      }
      26 => {
        let condition = Some(
          parse_proto_expression(r.bytes(), symbols, version),
        ) catch {
          Unsupported(_) => None
          error => raise error
        }
        match condition {
          Some(value) => conditions.push(value)
          None => has_unsupported_expressions = true
        }
      }
      34 => {
        has_scopes = true
        scope_data.push(r.bytes())
      }
      _ => raise Unsupported("unknown rule field")
    }
  }
  let has_head = head is Some(_)
  let rule_head = match head {
    Some(value) => value
    None => { name: "", terms: [], }
  }
  let scopes = parse_scope_list(scope_data, public_keys)
  {
    rule: { head: rule_head, body, conditions, scopes, },
    has_head,
    has_unsupported_expressions,
    has_scopes,
  }
}

///|
priv struct ParsedCheck {
  check : Check
  has_unsupported_expressions : Bool
  has_scopes : Bool
}

///|
fn parse_proto_check(
  data : Bytes,
  symbols : Array[String],
  public_keys : Array[Bytes],
  version : Int32,
) -> ParsedCheck raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let queries : Array[Query] = []
  let mut mode : CheckMode = Any
  let mut kind_seen = false
  let mut has_unsupported_expressions = false
  let mut has_scopes = false
  while r.pos < data.length() {
    let tag = r.varint()
    match tag {
      10 => {
        if queries.length() >= 1000 {
          raise Malformed("check has too many queries")
        }
        let parsed = parse_proto_rule(r.bytes(), symbols, public_keys, version)
        has_unsupported_expressions = has_unsupported_expressions ||
          parsed.has_unsupported_expressions
        has_scopes = has_scopes || parsed.has_scopes
        queries.push({
          body: parsed.rule.body,
          conditions: parsed.rule.conditions,
          scopes: parsed.rule.scopes,
        })
      }
      16 if !kind_seen => {
        kind_seen = true
        mode = match r.varint() {
          0 => Any
          1 if version >= 4 => All
          1 => raise Unsupported("check all requires Datalog version 3.1")
          2 if version >= 6 => Reject
          2 => raise Unsupported("reject checks require Datalog version 3.3")
          _ => raise Unsupported("check kind")
        }
      }
      16 => raise Malformed("duplicate check kind")
      _ => raise Unsupported("unknown check field")
    }
  }
  { check: { mode, queries, }, has_unsupported_expressions, has_scopes, }
}

///|
priv struct EncodedFactBlock {
  version : Int32
  symbols : Array[Bytes]
  facts : Array[Bytes]
  rules : Array[Bytes]
  checks : Array[Bytes]
  scopes : Array[Bytes]
  public_keys : Array[Bytes]
}

///|
fn parse_encoded_fact_block(data : Bytes) -> EncodedFactBlock raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let symbols : Array[Bytes] = []
  let facts : Array[Bytes] = []
  let rules : Array[Bytes] = []
  let checks : Array[Bytes] = []
  let scopes : Array[Bytes] = []
  let public_keys : Array[Bytes] = []
  let mut version : Int32 = 0
  let mut version_seen = false
  while r.pos < data.length() {
    let tag = r.varint()
    match tag {
      10 => {
        if symbols.length() >= 3072 {
          raise Malformed("block symbol table exceeds 3072 entries")
        }
        symbols.push(r.bytes())
      }
      24 if !version_seen => {
        version = r.varint()
        version_seen = true
      }
      24 => raise Malformed("duplicate block version")
      34 => {
        if facts.length() >= 10000 {
          raise Malformed("block has too many facts")
        }
        facts.push(r.bytes())
      }
      42 => {
        if rules.length() >= 10000 {
          raise Malformed("block has too many rules")
        }
        rules.push(r.bytes())
      }
      50 => {
        if checks.length() >= 1000 {
          raise Malformed("block has too many checks")
        }
        checks.push(r.bytes())
      }
      58 => scopes.push(r.bytes())
      18 => ignore(r.bytes()) // optional context
      66 => public_keys.push(r.bytes())
      _ => raise Unsupported("unknown block field")
    }
  }
  if version < 3 {
    raise Unsupported("legacy Datalog block")
  }
  if version > 6 {
    raise Unsupported("Datalog version above 3.3")
  }
  { version, symbols, facts, rules, checks, scopes, public_keys, }
}

///|
fn parse_scope_list(
  data : Array[Bytes],
  public_keys : Array[Bytes],
) -> Array[TrustScope] raise TokenError {
  let scopes : Array[TrustScope] = []
  for encoded in data {
    let r = Reader::{ data: encoded, pos: 0, }
    let mut scope : TrustScope? = None
    while r.pos < encoded.length() {
      match r.varint() {
        8 if scope is None =>
          scope = Some(
            match r.varint() {
              0 => TrustAuthority
              1 => TrustPrevious
              _ => raise Unsupported("unknown scope type")
            },
          )
        16 if scope is None => {
          let index = r.varint64()
          if index >= public_keys.length().to_uint64() {
            raise Malformed(
              "scope public key index " +
              index.to_string() +
              " is out of range for " +
              public_keys.length().to_string() +
              " keys",
            )
          }
          scope = Some(TrustPublicKey(parse_key(public_keys[index.to_int()])))
        }
        8 | 16 => raise Malformed("scope contains multiple variants")
        _ => raise Unsupported("unknown scope field")
      }
    }
    scopes.push(
      match scope {
        Some(value) => value
        None => raise Malformed("empty scope")
      },
    )
  }
  scopes
}

///|
/// Biscuit public-key identifiers are interned over the token chain. Each
/// block contributes its key declarations in order, while repeated keys reuse
/// the first token-wide index.
fn intern_public_key_table(
  blocks : Array[EncodedFactBlock],
) -> Array[Bytes] raise TokenError {
  let table : Array[Bytes] = []
  let values : Array[Bytes] = []
  for block in blocks {
    for encoded_key in block.public_keys {
      let value = parse_key(encoded_key)
      if !values.contains(value) {
        values.push(value)
        table.push(encoded_key)
      }
    }
  }
  table
}

///|
priv struct SignedBlock {
  data : Bytes
  next_key : Bytes
  signature : Bytes
  version : Int32
  external_signature : ExternalSignature?
}

///|
pub(all) struct ExternalSignature {
  public_key : Bytes
  signature : Bytes
  encoded : Bytes
}

///|
pub(all) struct ThirdPartyBlockContents {
  payload : Bytes
  external_signature : ExternalSignature
}

///|
fn parse_key(data : Bytes) -> Bytes raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut algorithm : Int32? = None
  let mut key : Bytes? = None
  while r.pos < data.length() {
    match r.varint() {
      8 if algorithm is None => algorithm = Some(r.varint())
      18 if key is None => key = Some(r.bytes())
      _ => raise Malformed("invalid public key field")
    }
  }
  match (algorithm, key) {
    (Some(0), Some(k)) if k.length() == 32 => k
    (Some(0), Some(_)) => raise Malformed("invalid public key length")
    (Some(_), _) => raise Unsupported("public key algorithm")
    _ => raise Malformed("missing public key field")
  }
}

///|
fn parse_block(data : Bytes) -> SignedBlock raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut content : Bytes? = None
  let mut key : Bytes? = None
  let mut signature : Bytes? = None
  let mut external_signature : ExternalSignature? = None
  let mut version : Int32? = None
  while r.pos < data.length() {
    match r.varint() {
      10 if content is None => content = Some(r.bytes())
      18 if key is None => key = Some(parse_key(r.bytes()))
      26 if signature is None => signature = Some(r.bytes())
      34 if external_signature is None =>
        external_signature = Some(parse_external_signature(r.bytes()))
      34 => raise Malformed("duplicate external signature")
      40 if version is None => version = Some(r.varint())
      _ => raise Malformed("invalid signed block field")
    }
  }
  match (content, key, signature) {
    (Some(d), Some(k), Some(s)) if s.length() == 64 => {
      let v = version.unwrap_or(0)
      if v != 0 && v != 1 {
        raise Unsupported("signature payload version")
      }
      { data: d, next_key: k, signature: s, version: v, external_signature, }
    }
    _ => raise Malformed("missing or invalid signed block field")
  }
}

///|
fn parse_external_signature(data : Bytes) -> ExternalSignature raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut signature : Bytes? = None
  let mut public_key : Bytes? = None
  while r.pos < data.length() {
    match r.varint() {
      10 if signature is None => signature = Some(r.bytes())
      18 if public_key is None => public_key = Some(parse_key(r.bytes()))
      _ => raise Malformed("invalid external signature message")
    }
  }
  match (signature, public_key) {
    (Some(sig), Some(key)) if sig.length() == 64 =>
      { public_key: key, signature: sig, encoded: data, }
    (Some(_), Some(_)) => raise Malformed("invalid external signature length")
    _ => raise Malformed("missing external signature field")
  }
}

///|
fn block_payload(block : SignedBlock, previous : Bytes?) -> Bytes {
  if block.version == 0 {
    block.data + b"\x00\x00\x00\x00" + block.next_key
  } else {
    let payload = authority_payload_v1(block.data, block.next_key)
    match previous {
      None => payload
      Some(sig) => {
        let chained = payload + b"\x00PREVSIG\x00" + sig
        match block.external_signature {
          Some(external) =>
            chained + b"\x00EXTERNALSIG\x00" + external.signature
          None => chained
        }
      }
    }
  }
}

///|
/// Construct the external-signature payload for Datalog v3.2+ blocks.
pub fn external_signature_payload_v1(
  data : Bytes,
  previous_signature : Bytes,
) -> Bytes {
  b"\x00EXTERNAL\x00\x00VERSION\x00\x01\x00\x00\x00\x00PAYLOAD\x00" +
  data +
  b"\x00PREVSIG\x00" +
  previous_signature
}

///|
/// Verify the signature chain and final proof of an Ed25519 Biscuit token.
/// This does NOT evaluate the token's checks or authorize a request.
/// Unsupported algorithms and third-party blocks are rejected.
fn verify_signed_chain(
  token : Bytes,
  root_key : Bytes,
) -> Array[SignedBlock] raise TokenError {
  if token.length() > 1048576 {
    raise Malformed("token exceeds 1 MiB")
  }
  if root_key.length() != 32 {
    raise Malformed("invalid root key length")
  }
  let r = Reader::{ data: token, pos: 0, }
  let mut authority : SignedBlock? = None
  let blocks : Array[SignedBlock] = []
  let mut proof : Bytes? = None
  let mut root_id_seen = false
  while r.pos < token.length() {
    match r.varint() {
      8 if !root_id_seen => {
        ignore(r.varint())
        root_id_seen = true
      }
      18 if authority is None => authority = Some(parse_block(r.bytes()))
      26 => {
        if blocks.length() >= 128 {
          raise Malformed("too many blocks")
        }
        blocks.push(parse_block(r.bytes()))
      }
      34 if proof is None => proof = Some(r.bytes())
      _ => raise Malformed("invalid token field")
    }
  }
  let first = match authority {
    Some(block) => block
    None => raise Malformed("missing authority")
  }
  if first.external_signature is Some(_) {
    raise Malformed("authority block cannot carry an external signature")
  }
  if !@ed25519.verify(root_key, block_payload(first, None), first.signature) {
    raise InvalidSignature
  }
  let mut last = first
  let verified : Array[SignedBlock] = [first]
  for block in blocks {
    match block.external_signature {
      Some(external) => {
        if block.version != 1 {
          raise Unsupported("third-party blocks require signature payload v1")
        }
        if parse_encoded_fact_block(block.data).version < 5 {
          raise Unsupported("third-party blocks require Datalog version 3.2")
        }
        let payload = external_signature_payload_v1(block.data, last.signature)
        if !@ed25519.verify(external.public_key, payload, external.signature) {
          raise InvalidSignature
        }
      }
      None => ()
    }
    if !@ed25519.verify(
        last.next_key,
        block_payload(block, Some(last.signature)),
        block.signature,
      ) {
      raise InvalidSignature
    }
    last = block
    verified.push(block)
  }
  let p = match proof {
    Some(value) => value
    None => raise Malformed("missing proof")
  }
  let pr = Reader::{ data: p, pos: 0, }
  let tag = pr.varint()
  let value = pr.bytes()
  if pr.pos != p.length() {
    raise Malformed("invalid proof")
  }
  match tag {
    10 => {
      let derived = @ed25519.derive_public_key(value) catch {
        _ => raise Malformed("invalid proof secret")
      }
      if derived != last.next_key {
        raise InvalidSignature
      }
    }
    18 => {
      let payload = last.data +
        b"\x00\x00\x00\x00" +
        last.next_key +
        last.signature
      if !@ed25519.verify(last.next_key, payload, value) {
        raise InvalidSignature
      }
    }
    _ => raise Malformed("invalid proof type")
  }
  verified
}

///|
/// Verify the signature chain and final proof for a supported token.
pub fn verify_signatures(
  token : Bytes,
  root_key : Bytes,
) -> Unit raise TokenError {
  ignore(verify_signed_chain(token, root_key))
}

///|
/// Facts decoded from one signature-verified token block.
pub(all) struct VerifiedBlockFacts {
  index : Int32
  signature : Bytes
  facts : Array[Fact]
}

///|
/// Signature-verified block data for the currently decoded Datalog subset.
/// Unsupported execution features are reported as flags and never evaluated.
pub(all) struct VerifiedBlockProgram {
  index : Int32
  datalog_version : Int32
  signature : Bytes
  external_public_key : Bytes?
  scopes : Array[TrustScope]
  facts : Array[Fact]
  rules : Array[Rule]
  checks : Array[Check]
  has_scopes : Bool
  has_unsupported_expressions : Bool
}

///|
/// Verify a token and decode its v3 ground facts for inspection.
/// This is not an authorization decision: rules, checks, policies, scopes,
/// expressions and revocation are not evaluated.
pub fn verify_block_facts(
  token : Bytes,
  root_key : Bytes,
) -> Array[VerifiedBlockFacts] raise TokenError {
  let signed = verify_signed_chain(token, root_key)
  let encoded : Array[EncodedFactBlock] = []
  for block in signed {
    encoded.push(parse_encoded_fact_block(block.data))
  }
  let symbols = default_symbols()
  for block in encoded {
    for symbol in block.symbols {
      parse_symbols(symbol, symbols)
    }
  }
  let result : Array[VerifiedBlockFacts] = []
  let mut total_facts = 0
  for i = 0; i < signed.length(); i = i + 1 {
    let facts : Array[Fact] = []
    for data in encoded[i].facts {
      total_facts += 1
      if total_facts > 100000 {
        raise Malformed("token has too many facts")
      }
      facts.push(parse_proto_fact(data, symbols, encoded[i].version))
    }
    result.push({ index: i, signature: signed[i].signature, facts, })
  }
  result
}

///|
/// Verify and decode facts, predicate-only rules, and check queries from each
/// v3 block. Expression bytecode and scope annotations are surfaced as flags;
/// callers must not authorize a program that contains unsupported features.
pub fn verify_block_programs(
  token : Bytes,
  root_key : Bytes,
) -> Array[VerifiedBlockProgram] raise TokenError {
  let signed = verify_signed_chain(token, root_key)
  let encoded : Array[EncodedFactBlock] = []
  for block in signed {
    encoded.push(parse_encoded_fact_block(block.data))
  }
  let symbols = default_symbols()
  for block in encoded {
    for symbol in block.symbols {
      parse_symbols(symbol, symbols)
    }
  }
  let public_key_table = intern_public_key_table(encoded)
  let programs : Array[VerifiedBlockProgram] = []
  let mut total_facts = 0
  let mut total_rules = 0
  let mut total_checks = 0
  for i = 0; i < signed.length(); i = i + 1 {
    let block_public_keys = if encoded[i].version >= 5 {
      encoded[i].public_keys
    } else {
      public_key_table
    }
    let facts : Array[Fact] = []
    for data in encoded[i].facts {
      total_facts += 1
      if total_facts > 100000 {
        raise Malformed("token has too many facts")
      }
      facts.push(parse_proto_fact(data, symbols, encoded[i].version))
    }
    let rules : Array[Rule] = []
    let mut has_scopes = encoded[i].scopes.length() > 0
    let mut has_unsupported_expressions = false
    for data in encoded[i].rules {
      total_rules += 1
      if total_rules > 50000 {
        raise Malformed("token has too many rules")
      }
      let parsed = parse_proto_rule(
        data,
        symbols,
        block_public_keys,
        encoded[i].version,
      )
      if !parsed.has_head {
        raise Malformed("rule has no head")
      }
      validate_rule_safety(parsed.rule)
      rules.push(parsed.rule)
      has_scopes = has_scopes || parsed.has_scopes
      has_unsupported_expressions = has_unsupported_expressions ||
        parsed.has_unsupported_expressions
    }
    let checks : Array[Check] = []
    for data in encoded[i].checks {
      total_checks += 1
      if total_checks > 10000 {
        raise Malformed("token has too many checks")
      }
      let parsed = parse_proto_check(
        data,
        symbols,
        block_public_keys,
        encoded[i].version,
      )
      checks.push(parsed.check)
      has_scopes = has_scopes || parsed.has_scopes
      has_unsupported_expressions = has_unsupported_expressions ||
        parsed.has_unsupported_expressions
    }
    programs.push({
      index: i,
      datalog_version: encoded[i].version,
      signature: signed[i].signature,
      external_public_key: signed[i].external_signature.map(sig => {
        sig.public_key
      }),
      scopes: parse_scope_list(encoded[i].scopes, block_public_keys),
      facts,
      rules,
      checks,
      has_scopes,
      has_unsupported_expressions,
    })
  }
  programs
}

///|
/// Verify a token and evaluate it with default Biscuit scopes.
pub fn authorize_token(
  token : Bytes,
  root_key : Bytes,
  ambient_facts : Array[Fact],
  ambient_rules : Array[Rule],
  policies : Array[Policy],
  max_facts : Int32,
  max_iterations : Int32,
) -> Unit raise AuthorizationError {
  authorize_token_with_checks(
    token,
    root_key,
    ambient_facts,
    ambient_rules,
    [],
    policies,
    max_facts,
    max_iterations,
  )
}

///|
/// Verify a token and evaluate token and authorizer Datalog with fact origins.
pub fn authorize_token_with_checks(
  token : Bytes,
  root_key : Bytes,
  ambient_facts : Array[Fact],
  ambient_rules : Array[Rule],
  ambient_checks : Array[Check],
  policies : Array[Policy],
  max_facts : Int32,
  max_iterations : Int32,
) -> Unit raise AuthorizationError {
  authorize_token_with_externals(
    token,
    root_key,
    ambient_facts,
    ambient_rules,
    ambient_checks,
    policies,
    max_facts,
    max_iterations,
    ExternalFunctions::{ unary: Map([]), binary: Map([]), },
  )
}

///|
/// Verify and authorize a token with caller-provided, deterministic FFI
/// callbacks for Datalog expressions.
pub fn authorize_token_with_externals(
  token : Bytes,
  root_key : Bytes,
  ambient_facts : Array[Fact],
  ambient_rules : Array[Rule],
  ambient_checks : Array[Check],
  policies : Array[Policy],
  max_facts : Int32,
  max_iterations : Int32,
  externals : ExternalFunctions,
) -> Unit raise AuthorizationError {
  let result = authorize_token_detailed(
    token, root_key, ambient_facts, ambient_rules, ambient_checks, policies, max_facts,
    max_iterations, externals,
  )
  match result.decision {
    Allow => ()
    Deny => raise Denied(result.policy_index)
  }
}

///|
/// Verify a token and return the first matching allow/deny policy as data.
/// Token, check, expression, and resource failures remain structured errors.
pub fn authorize_token_detailed(
  token : Bytes,
  root_key : Bytes,
  ambient_facts : Array[Fact],
  ambient_rules : Array[Rule],
  ambient_checks : Array[Check],
  policies : Array[Policy],
  max_facts : Int32,
  max_iterations : Int32,
  externals : ExternalFunctions,
) -> AuthorizationResult raise AuthorizationError {
  let programs = verify_block_programs(token, root_key) catch {
    Malformed(message) => raise InvalidToken(message)
    Unsupported(message) => raise UnsupportedTokenFeature(message)
    InvalidSignature => raise TokenSignatureInvalid
  }
  if programs.length() == 0 {
    raise InvalidToken("token contains no authority block")
  }
  for program in programs {
    if program.has_unsupported_expressions {
      raise UnsupportedTokenFeature("expression bytecode")
    }
  }

  let authorizer_origin = programs.length()
  let facts : Array[FactOrigin] = []
  for program in programs {
    for fact in program.facts {
      facts.push({ fact, origins: [program.index], })
    }
  }
  for fact in ambient_facts {
    facts.push({ fact, origins: [authorizer_origin], })
  }

  let scoped_rules : Array[ScopedRule] = []
  for program in programs {
    for rule in program.rules {
      let inherited_scopes = if rule.scopes.length() > 0 {
        rule.scopes
      } else {
        program.scopes
      }
      scoped_rules.push({
        rule,
        origin: program.index,
        visible_origins: resolve_visible_origins(
          inherited_scopes,
          program.index,
          authorizer_origin,
          programs,
        ),
      })
    }
  }
  for rule in ambient_rules {
    scoped_rules.push({
      rule,
      origin: authorizer_origin,
      visible_origins: resolve_visible_origins(
        rule.scopes,
        authorizer_origin,
        authorizer_origin,
        programs,
      ),
    })
  }
  let derived = derive_scoped_facts(
    facts, scoped_rules, max_facts, max_iterations, externals,
  )

  let mut check_index = 0
  for program in programs {
    for check in program.checks {
      if !scoped_check_matches(
          check,
          derived,
          program.index,
          program.scopes,
          authorizer_origin,
          programs,
          check_index,
          externals,
        ) {
        raise FailedCheck(check_index)
      }
      check_index += 1
    }
  }
  for check in ambient_checks {
    if !scoped_check_matches(
        check,
        derived,
        authorizer_origin,
        [],
        authorizer_origin,
        programs,
        check_index,
        externals,
      ) {
      raise FailedCheck(check_index)
    }
    check_index += 1
  }

  for i = 0; i < policies.length(); i = i + 1 {
    let policy = policies[i]
    if policy.queries.length() == 0 {
      raise EmptyPolicy(i)
    }
    let matched = policy.queries.any(query => {
      scoped_query_matches(
        query,
        derived,
        resolve_visible_origins(
          query.scopes,
          authorizer_origin,
          authorizer_origin,
          programs,
        ),
        externals,
      )
    })
    if matched {
      match policy.kind {
        Allow => return { decision: Allow, policy_index: i, }
        Deny => return { decision: Deny, policy_index: i, }
      }
    }
  }
  raise NoMatchingPolicy
}

///|
fn add_origin(origins : Array[Int32], value : Int32) -> Unit {
  if !origins.contains(value) {
    origins.push(value)
  }
}

///|
fn resolve_visible_origins(
  scopes : Array[TrustScope],
  current_origin : Int32,
  authorizer_origin : Int32,
  programs : Array[VerifiedBlockProgram],
) -> Array[Int32] {
  let visible : Array[Int32] = []
  add_origin(visible, current_origin)
  add_origin(visible, authorizer_origin)
  let effective_scopes = if scopes.length() == 0 {
    [TrustAuthority]
  } else {
    scopes
  }
  for scope in effective_scopes {
    match scope {
      TrustAuthority => add_origin(visible, 0)
      TrustPrevious if current_origin < authorizer_origin =>
        for origin = 0; origin < current_origin; origin = origin + 1 {
          add_origin(visible, origin)
        }
      TrustPrevious => () // Policies run at the authorizer origin.
      TrustPublicKey(key) =>
        for program in programs {
          if program.external_public_key == Some(key) {
            add_origin(visible, program.index)
          }
        }
    }
  }
  visible
}

///|
fn scoped_check_matches(
  check : Check,
  facts : Array[FactOrigin],
  current_origin : Int32,
  block_scopes : Array[TrustScope],
  authorizer_origin : Int32,
  programs : Array[VerifiedBlockProgram],
  _index : Int32,
  externals : ExternalFunctions,
) -> Bool raise AuthorizationError {
  if check.queries.length() == 0 {
    raise EmptyCheck(_index)
  }
  let query_matches_under_scope = fn(
    query : Query,
  ) -> Bool raise AuthorizationError {
    let scopes = if query.scopes.length() > 0 {
      query.scopes
    } else {
      block_scopes
    }
    let visible = resolve_visible_origins(
      scopes, current_origin, authorizer_origin, programs,
    )
    match check.mode {
      Any | Reject => scoped_query_matches(query, facts, visible, externals)
      All => scoped_query_all_matches(query, facts, visible, externals)
    }
  }
  match check.mode {
    Any | All => check.queries.any(query_matches_under_scope)
    Reject => !check.queries.any(query_matches_under_scope)
  }
}

///|
/// Verify the token and decode only its authority block's ground facts.
/// Appended blocks and authorization conditions are not evaluated.
pub fn verify_authority_facts(
  token : Bytes,
  root_key : Bytes,
) -> Array[Fact] raise TokenError {
  verify_block_facts(token, root_key)[0].facts
}
