///|
test "v1 authority payload uses domain separation and little endian fields" {
  let payload = @biscuit.authority_payload_v1(b"abc", b"key")
  assert_eq(
    payload, b"\x00BLOCK\x00\x00VERSION\x00\x01\x00\x00\x00\x00PAYLOAD\x00abc\x00ALGORITHM\x00\x00\x00\x00\x00\x00NEXTKEY\x00key",
  )
}
