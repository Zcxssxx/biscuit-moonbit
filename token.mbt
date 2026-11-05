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
