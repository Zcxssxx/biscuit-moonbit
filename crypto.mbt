///|
#derive(Eq)
pub(all) enum SignatureAlgorithm {
  Ed25519
  Secp256r1
}

///|
pub extend SignatureAlgorithm with Eq::{equal, not_equal}

///|
pub(all) struct SigningKey {
  algorithm : SignatureAlgorithm
  secret : Bytes
}

///|
pub(all) struct VerificationKey {
  algorithm : SignatureAlgorithm
  key : Bytes
}

///|
// Private representation: legacy Ed25519 bytes remain unchanged; P-256 carries
// an explicit algorithm tag before its compressed SEC1 bytes.
fn key_algorithm(key : Bytes) -> SignatureAlgorithm raise TokenError {
  if key.length() == 32 {
    Ed25519
  } else if key.length() == 34 && key[0] == b'\x01' {
    Secp256r1
  } else {
    raise Malformed("invalid tagged verification key")
  }
}

///|
fn key_bytes(key : Bytes) -> Bytes {
  if key.length() == 34 {
    key[1:].to_owned()
  } else {
    key
  }
}

///|
fn algorithm_bytes(key : Bytes) -> Bytes {
  if key.length() == 34 {
    b"\x01\x00\x00\x00"
  } else {
    b"\x00\x00\x00\x00"
  }
}

///|
fn pack_key(key : VerificationKey) -> Bytes raise TokenError {
  match key.algorithm {
    Ed25519 => {
      if key.key.length() != 32 {
        raise Malformed("Ed25519 key must be 32 bytes")
      }
      key.key
    }
    Secp256r1 => {
      if key.key.length() != 33 ||
        (key.key[0] != b'\x02' && key.key[0] != b'\x03') {
        raise Malformed("P-256 key must be compressed SEC1")
      }
      ignore(@ecdsa.PublicKey::new(key.key[:])) catch {
        _ => raise Malformed("invalid P-256 point")
      }
      b"\x01" + key.key
    }
  }
}

///|
pub fn verification_key(
  signing : SigningKey,
) -> VerificationKey raise TokenError {
  match signing.algorithm {
    Ed25519 => {
      let key = @ed25519.derive_public_key(signing.secret) catch {
        _ => raise Malformed("invalid Ed25519 secret")
      }
      { algorithm: Ed25519, key, }
    }
    Secp256r1 => {
      let private_key = @ecdsa.PrivateKey::new(signing.secret[:]) catch {
        _ => raise Malformed("invalid P-256 scalar")
      }
      let (x, y) = private_key.public().xy()
      let prefix = if (y[31].to_int() & 1) == 0 { b"\x02" } else { b"\x03" }
      { algorithm: Secp256r1, key: prefix + x, }
    }
  }
}

///|
fn der_integer(value : Bytes) -> Bytes {
  let mut start = 0
  while start < value.length() - 1 && value[start] == b'\x00' {
    start += 1
  }
  let bytes = value[start:].to_owned()
  let positive = if bytes[0].to_int() >= 128 { b"\x00" + bytes } else { bytes }
  encode_bytes_field(b'\x02', positive)
}

///|
fn signature_der(raw : Bytes) -> Bytes {
  encode_bytes_field(
    b'\x30',
    der_integer(raw[0:32].to_owned()) + der_integer(raw[32:].to_owned()),
  )
}

///|
fn signature_raw(der : Bytes) -> Bytes? {
  if der.length() < 8 ||
    der.length() > 72 ||
    der[0] != b'\x30' ||
    der[1].to_int() != der.length() - 2 {
    return None
  }
  let result : Array[Byte] = []
  let mut pos = 2
  for _i = 0; _i < 2; _i = _i + 1 {
    if pos + 2 > der.length() || der[pos] != b'\x02' {
      return None
    }
    let length = der[pos + 1].to_int()
    pos += 2
    if length < 1 ||
      length > 33 ||
      length > der.length() - pos ||
      der[pos].to_int() >= 128 {
      return None
    }
    let mut start = pos
    if length > 1 && der[start] == b'\x00' {
      if der[start + 1].to_int() < 128 {
        return None
      }
      start += 1
    }
    let count = pos + length - start
    if count > 32 {
      return None
    }
    for _j = count; _j < 32; _j = _j + 1 {
      result.push(b'\x00')
    }
    for j = start; j < pos + length; j = j + 1 {
      result.push(der[j])
    }
    pos += length
  }
  if pos != der.length() {
    return None
  }
  Some(Bytes::from_array(result))
}

///|
fn crypto_sign(key : SigningKey, message : Bytes) -> Bytes raise TokenError {
  match key.algorithm {
    Ed25519 =>
      @ed25519.sign(key.secret, message) catch {
        _ => raise Malformed("invalid Ed25519 signing key")
      }
    Secp256r1 => {
      let private_key = @ecdsa.PrivateKey::new(key.secret[:]) catch {
        _ => raise Malformed("invalid P-256 signing key")
      }
      signature_der(private_key.sign(message[:]))
    }
  }
}

///|
fn crypto_verify(key : Bytes, message : Bytes, signature : Bytes) -> Bool {
  if key.length() == 32 {
    @ed25519.verify(key, message, signature)
  } else if key.length() == 34 && key[0] == b'\x01' {
    let public_key = @ecdsa.PublicKey::new(key[1:]) catch { _ => return false }
    match signature_raw(signature) {
      Some(raw) => public_key.verify(message[:], raw[:])
      None => false
    }
  } else {
    false
  }
}

///|
fn encode_public_key(key : Bytes) -> Bytes {
  let algorithm = if key.length() == 34 { b"\x08\x01" } else { b"\x08\x00" }
  algorithm + encode_bytes_field(b'\x12', key_bytes(key))
}
