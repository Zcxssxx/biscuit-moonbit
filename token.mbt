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
        if version < 6 {
          raise Unsupported("sets require Datalog version 3.3")
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
priv enum ExpressionOp {
  Operand(ExpressionValue)
  Binary(CompareOperator)
}

///|
fn parse_proto_binary(
  data : Bytes,
  version : Int32,
) -> CompareOperator raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut kind : Int32? = None
  while r.pos < data.length() {
    match r.varint() {
      8 if kind is None => kind = Some(r.varint())
      8 => raise Malformed("duplicate binary operator")
      _ => raise Unsupported("binary operator metadata")
    }
  }
  match kind {
    Some(0) => LessThan
    Some(1) => GreaterThan
    Some(2) => LessOrEqual
    Some(3) => GreaterOrEqual
    Some(4) => Equal
    Some(20) if version >= 4 => NotEqual
    Some(20) => raise Unsupported("not-equal requires Datalog version 3.1")
    Some(21) if version >= 6 => Equal
    Some(22) if version >= 6 => NotEqual
    Some(21 | 22) =>
      raise Unsupported("heterogeneous equality requires Datalog version 3.3")
    Some(_) => raise Unsupported("binary operator")
    None => raise Malformed("binary operator has no kind")
  }
}

///|
fn parse_proto_expression_op(
  data : Bytes,
  symbols : Array[String],
  version : Int32,
) -> ExpressionOp raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut operation : ExpressionOp? = None
  while r.pos < data.length() {
    let tag = r.varint()
    let parsed = match tag {
      10 =>
        match parse_proto_query_term(r.bytes(), symbols, version) {
          Constant(value) => Operand(Literal(value))
          Variable(name) => Operand(Reference(name))
        }
      18 => raise Unsupported("unary expression operators")
      26 => Binary(parse_proto_binary(r.bytes(), version))
      34 => raise Unsupported("closure expression operators")
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
    if operations.length() >= 64 {
      raise Malformed("expression exceeds 64 operations")
    }
    operations.push(parse_proto_expression_op(r.bytes(), symbols, version))
  }
  if operations.length() != 3 {
    raise Unsupported("only one binary comparison is supported per expression")
  }
  match (operations[0], operations[1], operations[2]) {
    (Operand(left), Operand(right), Binary(operator)) =>
      { left, right, operator, }
    _ => raise Unsupported("expression is not a binary comparison")
  }
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
  version : Int32,
) -> ParsedRule raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut head : Predicate? = None
  let body : Array[Predicate] = []
  let conditions : Array[Condition] = []
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
        ignore(r.bytes())
      }
      _ => raise Unsupported("unknown rule field")
    }
  }
  let has_head = head is Some(_)
  let rule_head = match head {
    Some(value) => value
    None => { name: "", terms: [], }
  }
  {
    rule: { head: rule_head, body, conditions, },
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
        let parsed = parse_proto_rule(r.bytes(), symbols, version)
        has_unsupported_expressions = has_unsupported_expressions ||
          parsed.has_unsupported_expressions
        has_scopes = has_scopes || parsed.has_scopes
        queries.push({
          body: parsed.rule.body,
          conditions: parsed.rule.conditions,
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
  has_scopes : Bool
}

///|
fn parse_encoded_fact_block(data : Bytes) -> EncodedFactBlock raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let symbols : Array[Bytes] = []
  let facts : Array[Bytes] = []
  let rules : Array[Bytes] = []
  let checks : Array[Bytes] = []
  let mut has_scopes = false
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
      58 => {
        has_scopes = true
        ignore(r.bytes())
      }
      18 => ignore(r.bytes()) // optional context
      66 => ignore(r.bytes()) // public key table used by scope annotations
      _ => raise Unsupported("unknown block field")
    }
  }
  if version < 3 {
    raise Unsupported("legacy Datalog block")
  }
  if version > 6 {
    raise Unsupported("Datalog version above 3.3")
  }
  { version, symbols, facts, rules, checks, has_scopes, }
}

///|
priv struct SignedBlock {
  data : Bytes
  next_key : Bytes
  signature : Bytes
  version : Int32
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
  let mut version : Int32? = None
  while r.pos < data.length() {
    match r.varint() {
      10 if content is None => content = Some(r.bytes())
      18 if key is None => key = Some(parse_key(r.bytes()))
      26 if signature is None => signature = Some(r.bytes())
      34 => raise Unsupported("third-party block")
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
      { data: d, next_key: k, signature: s, version: v, }
    }
    _ => raise Malformed("missing or invalid signed block field")
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
      Some(sig) => payload + b"\x00PREVSIG\x00" + sig
    }
  }
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
  if !@ed25519.verify(root_key, block_payload(first, None), first.signature) {
    raise InvalidSignature
  }
  let mut last = first
  let verified : Array[SignedBlock] = [first]
  for block in blocks {
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
  let programs : Array[VerifiedBlockProgram] = []
  let mut total_facts = 0
  let mut total_rules = 0
  let mut total_checks = 0
  for i = 0; i < signed.length(); i = i + 1 {
    let facts : Array[Fact] = []
    for data in encoded[i].facts {
      total_facts += 1
      if total_facts > 100000 {
        raise Malformed("token has too many facts")
      }
      facts.push(parse_proto_fact(data, symbols, encoded[i].version))
    }
    let rules : Array[Rule] = []
    let mut has_scopes = encoded[i].has_scopes
    let mut has_unsupported_expressions = false
    for data in encoded[i].rules {
      total_rules += 1
      if total_rules > 50000 {
        raise Malformed("token has too many rules")
      }
      let parsed = parse_proto_rule(data, symbols, encoded[i].version)
      if !parsed.has_head {
        raise Malformed("rule has no head")
      }
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
      let parsed = parse_proto_check(data, symbols, encoded[i].version)
      checks.push(parsed.check)
      has_scopes = has_scopes || parsed.has_scopes
      has_unsupported_expressions = has_unsupported_expressions ||
        parsed.has_unsupported_expressions
    }
    programs.push({
      index: i,
      datalog_version: encoded[i].version,
      signature: signed[i].signature,
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
/// Verify and authorize the restricted predicate/comparison, no-scope subset.
/// Appended blocks may add checks but not facts or rules. Those limits make
/// the default authority/current/authorizer scopes explicit in this first
/// end-to-end authorization path; unsupported tokens fail closed.
pub fn authorize_token(
  token : Bytes,
  root_key : Bytes,
  ambient_facts : Array[Fact],
  ambient_rules : Array[Rule],
  policies : Array[Policy],
  max_facts : Int32,
  max_iterations : Int32,
) -> Unit raise AuthorizationError {
  let programs = verify_block_programs(token, root_key) catch {
    Malformed(message) => raise InvalidToken(message)
    Unsupported(message) => raise UnsupportedTokenFeature(message)
    InvalidSignature => raise TokenSignatureInvalid
  }
  if programs.length() == 0 {
    raise InvalidToken("token contains no authority block")
  }
  for program in programs {
    if program.has_scopes {
      raise UnsupportedTokenFeature("explicit scope annotations")
    }
    if program.has_unsupported_expressions {
      raise UnsupportedTokenFeature("expression bytecode")
    }
    if program.index > 0 && program.facts.length() > 0 {
      raise UnsupportedTokenFeature("facts in appended blocks")
    }
    if program.index > 0 && program.rules.length() > 0 {
      raise UnsupportedTokenFeature("rules in appended blocks")
    }
  }
  let facts = ambient_facts.copy()
  for fact in programs[0].facts {
    facts.push(fact)
  }
  let rules = ambient_rules.copy()
  for rule in programs[0].rules {
    rules.push(rule)
  }
  let derived = derive_facts(facts, rules, max_facts, max_iterations)
  let checks : Array[Check] = []
  for program in programs {
    for check in program.checks {
      checks.push(check)
    }
  }
  evaluate_policy_set(derived, checks, policies)
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
