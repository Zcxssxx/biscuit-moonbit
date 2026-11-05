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
  let length = self.varint()
  if length > self.data.length() - self.pos {
    raise Malformed("truncated field")
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
fn Reader::skip(self : Reader, wire : Int32) -> Unit raise TokenError {
  match wire {
    0 => ignore(self.varint64())
    1 => {
      if self.data.length() - self.pos < 8 {
        raise Malformed("truncated fixed64")
      }
      self.pos += 8
    }
    2 => ignore(self.bytes())
    5 => {
      if self.data.length() - self.pos < 4 {
        raise Malformed("truncated fixed32")
      }
      self.pos += 4
    }
    _ => raise Unsupported("protobuf wire type")
  }
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
  }
}

///|
fn parse_proto_term(
  data : Bytes,
  symbols : Array[String],
  depth : Int32,
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
        let nested = Reader::{ data: r.bytes(), pos: 0, }
        let values : Array[Value] = []
        while nested.pos < nested.data.length() {
          let nested_tag = nested.varint()
          if nested_tag == 10 {
            if values.length() >= 1024 {
              raise Malformed("set exceeds 1024 items")
            }
            let item = parse_proto_term(nested.bytes(), symbols, depth + 1)
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
        if r.bytes().length() != 0 {
          raise Malformed("null term payload must be empty")
        }
        Some(Null)
      }
      74 => {
        let nested = Reader::{ data: r.bytes(), pos: 0, }
        let values : Array[Value] = []
        while nested.pos < nested.data.length() {
          let nested_tag = nested.varint()
          if nested_tag == 10 {
            if values.length() >= 1024 {
              raise Malformed("array exceeds 1024 items")
            }
            values.push(parse_proto_term(nested.bytes(), symbols, depth + 1))
          } else {
            raise Unsupported("unknown array term field")
          }
        }
        Some(ArrayValue(values))
      }
      82 => raise Unsupported("map terms are not supported")
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
fn parse_proto_predicate(
  data : Bytes,
  symbols : Array[String],
) -> Fact raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut name : String? = None
  let values : Array[Value] = []
  while r.pos < data.length() {
    let tag = r.varint()
    match tag {
      8 if name is None => name = Some(symbol_at(symbols, r.varint64()))
      8 => raise Malformed("duplicate predicate name")
      18 => {
        if values.length() >= 128 {
          raise Malformed("predicate has too many terms")
        }
        values.push(parse_proto_term(r.bytes(), symbols, 0))
      }
      _ => r.skip(tag & 7)
    }
  }
  match name {
    Some(value) => { name: value, values, }
    None => raise Malformed("predicate has no name")
  }
}

///|
fn parse_proto_fact(
  data : Bytes,
  symbols : Array[String],
) -> Fact raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let mut fact : Fact? = None
  while r.pos < data.length() {
    let tag = r.varint()
    if tag == 10 {
      if fact is Some(_) {
        raise Malformed("fact has duplicate predicate")
      }
      fact = Some(parse_proto_predicate(r.bytes(), symbols))
    } else {
      r.skip(tag & 7)
    }
  }
  match fact {
    Some(value) => value
    None => raise Malformed("fact has no predicate")
  }
}

///|
fn parse_authority_facts(data : Bytes) -> Array[Fact] raise TokenError {
  let r = Reader::{ data, pos: 0, }
  let symbols = default_symbols()
  let encoded_facts : Array[Bytes] = []
  let facts : Array[Fact] = []
  let mut version : Int32 = 0
  let mut version_seen = false
  while r.pos < data.length() {
    let tag = r.varint()
    match tag {
      10 => parse_symbols(r.bytes(), symbols)
      24 if !version_seen => {
        version = r.varint()
        version_seen = true
      }
      24 => raise Malformed("duplicate block version")
      34 => {
        if encoded_facts.length() >= 10000 {
          raise Malformed("block has too many facts")
        }
        encoded_facts.push(r.bytes())
      }
      _ => r.skip(tag & 7)
    }
  }
  if version < 3 {
    raise Unsupported("legacy Datalog block")
  }
  for encoded in encoded_facts {
    facts.push(parse_proto_fact(encoded, symbols))
  }
  facts
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
pub fn verify_signatures(
  token : Bytes,
  root_key : Bytes,
) -> Unit raise TokenError {
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
  for block in blocks {
    if !@ed25519.verify(
        last.next_key,
        block_payload(block, Some(last.signature)),
        block.signature,
      ) {
      raise InvalidSignature
    }
    last = block
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
}

///|
/// Verify the token and decode only the authority block's ground facts.
/// This is an inspection helper, not an authorization decision: appended
/// blocks, rules, checks, policies, scopes and ambient facts are not evaluated.
pub fn verify_authority_facts(
  token : Bytes,
  root_key : Bytes,
) -> Array[Fact] raise TokenError {
  verify_signatures(token, root_key)
  let r = Reader::{ data: token, pos: 0, }
  while r.pos < token.length() {
    match r.varint() {
      8 => ignore(r.varint())
      18 => return parse_authority_facts(parse_block(r.bytes()).data)
      26 => ignore(r.bytes())
      34 => ignore(r.bytes())
      _ => raise Malformed("invalid token field")
    }
  }
  raise Malformed("missing authority")
}
