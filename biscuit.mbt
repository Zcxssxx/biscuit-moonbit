///|
/// Construct the version 1 Ed25519 authority-block signature payload.
/// This only constructs bytes; it does not verify a token or authorize access.
pub fn authority_payload_v1(data : Bytes, next_key : Bytes) -> Bytes {
  b"\x00BLOCK\x00\x00VERSION\x00\x01\x00\x00\x00\x00PAYLOAD\x00" +
  data +
  b"\x00ALGORITHM\x00\x00\x00\x00\x00\x00NEXTKEY\x00" +
  next_key
}
