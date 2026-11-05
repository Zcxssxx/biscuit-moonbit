///|
test "v1 authority payload uses domain separation and little endian fields" {
  let payload = @biscuit.authority_payload_v1(b"abc", b"key")
  assert_eq(
    payload, b"\x00BLOCK\x00\x00VERSION\x00\x01\x00\x00\x00\x00PAYLOAD\x00abc\x00ALGORITHM\x00\x00\x00\x00\x00\x00NEXTKEY\x00key",
  )
}

///|
test "issue a raw block and verify its signature chain" {
  // RFC 8032 test seed and public key. Never use test keys in production.
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let next_seed = Bytes::make(32, b'\x42')
  let token = @biscuit.issue_raw(b"\x18\x03", root_seed, next_seed)
  @biscuit.verify_signatures(token, root_key)
}

///|
test "issue rejects malformed or repeated seeds" {
  let seed = Bytes::make(32, b'\x42')
  for (root, next) in [(b"short", seed), (seed, seed)] {
    let rejected = try {
      ignore(@biscuit.issue_raw(b"\x18\x03", root, next))
      false
    } catch {
      @biscuit.Malformed(_) => true
      _ => false
    }
    assert_true(rejected)
  }
}
