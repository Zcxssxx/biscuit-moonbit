///|
test "seal and append accept proof before signed blocks" {
  let root = SigningKey::{
    algorithm: Ed25519,
    secret: Bytes::make(32, b'\x51'),
  }
  let trusted = verification_key(root)
  let first = SigningKey::{
    algorithm: Secp256r1,
    secret: Bytes::make(32, b'\x52'),
  }
  let token = issue_with_keys(
    [parse_fact("right(true)")],
    [],
    [],
    [],
    6,
    root,
    first,
  )
  let (blocks, proof) = split_verified_proof(token)
  let reordered = encode_bytes_field(b'\x22', proof) + blocks
  let next = SigningKey::{
    algorithm: Ed25519,
    secret: Bytes::make(32, b'\x53'),
  }
  let data = encode_block([], [], [parse_check("check if right(true)")], 6)
  assert_eq(
    append_with_key(reordered, trusted, data, next),
    append_with_key(token, trusted, data, next),
  )
  assert_eq(seal_with_key(reordered, trusted), seal_with_key(token, trusted))
  verify_with_key(seal_with_key(reordered, trusted), trusted)
}
