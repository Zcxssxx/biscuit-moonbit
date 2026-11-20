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

///|
test "P-256 third-party signatures bind to the request and trusted algorithm" {
  let root = SigningKey::{
    algorithm: Secp256r1,
    secret: Bytes::make(32, b'\x31'),
  }
  let trusted = verification_key(root)
  let next = SigningKey::{
    algorithm: Ed25519,
    secret: Bytes::make(32, b'\x32'),
  }
  let base = issue_with_keys([], [], [], [], 6, root, next)
  let other = issue_with_keys([], [], [], [], 6, root, {
    algorithm: Ed25519,
    secret: Bytes::make(32, b'\x33'),
  })
  let signer = SigningKey::{
    algorithm: Secp256r1,
    secret: Bytes::make(32, b'\x34'),
  }
  let public_key = verification_key(signer)
  let scope = trust_verification_key(public_key)
  let printed = print_check({
    mode: Any,
    queries: [
      {
        body: [parse_query("approval(true)")],
        conditions: [],
        scopes: [scope],
      },
    ],
  })
  assert_true(parse_check(printed).queries[0].scopes == [scope])
  let payload = encode_block([parse_fact("approval(true)")], [], [], 6)
  let signature = sign_third_party_with_key(
    third_party_request_with_key(base, trusted),
    payload,
    signer,
  )
  let contents = ThirdPartyBlockContents::{
    payload,
    external_signature: signature,
  }
  let final_key = SigningKey::{
    algorithm: Secp256r1,
    secret: Bytes::make(32, b'\x35'),
  }
  let approved = append_third_party_with_key(base, trusted, contents, final_key)
  verify_with_key(approved, trusted)
  let replay_rejected = try {
    ignore(append_third_party_with_key(other, trusted, contents, final_key))
    false
  } catch {
    InvalidSignature => true
    _ => false
  }
  assert_true(replay_rejected)
  let wrong_root = verification_key({ algorithm: Ed25519, secret: root.secret, })
  let wrong_algorithm = try {
    verify_with_key(approved, wrong_root)
    false
  } catch {
    InvalidSignature => true
    _ => false
  }
  assert_true(wrong_algorithm)
}
