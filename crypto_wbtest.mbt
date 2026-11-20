///|
test "P-256 backend DER roundtrip and malformed inputs" {
  let signing = SigningKey::{
    algorithm: Secp256r1,
    secret: Bytes::make(32, b'\x21'),
  }
  let key = pack_key(verification_key(signing))
  let signature = crypto_sign(signing, b"message")
  assert_true(crypto_verify(key, b"message", signature))
  assert_false(crypto_verify(key, b"other message", signature))
  assert_eq(signature_der(signature_raw(signature).unwrap()), signature)
  assert_eq(crypto_sign(signing, b"message"), signature)
  for
    malformed in [
      b"", b"\x30\x06\x02\x01\x80\x02\x01\x01", b"\x30\x07\x02\x02\x00\x01\x02\x01\x01",
    ] {
    assert_true(signature_raw(malformed) is None)
    assert_false(crypto_verify(key, b"message", malformed))
  }
  let zero = try {
    ignore(
      verification_key({
        algorithm: Secp256r1,
        secret: Bytes::make(32, b'\x00'),
      }),
    )
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(zero)
  let invalid_point = try {
    ignore(
      pack_key({
        algorithm: Secp256r1,
        key: b"\x02" + Bytes::make(32, b'\xff'),
      }),
    )
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(invalid_point)
}
