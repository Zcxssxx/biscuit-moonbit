///|
const MAX_TOKEN_SIZE = 1048576

///|
const MAX_BASE64URL_SIZE = 1398102

///|
/// Encode token bytes as canonical unpadded Base64URL for bearer-token
/// transport. This function does not verify the token or its signature.
pub fn token_to_base64url(token : Bytes) -> String {
  @base64.encode(token, padding=false)
  .replace_all(old="+", new="-")
  .replace_all(old="/", new="_")
}

///|
/// Decode canonical unpadded Base64URL token bytes. This validates only the
/// representation and size; callers must still verify the token signature.
pub fn token_from_base64url(encoded : String) -> Bytes raise TokenError {
  if encoded.length() == 0 {
    raise Malformed("empty token encoding")
  }
  if encoded.length() > MAX_BASE64URL_SIZE {
    raise Malformed("encoded token exceeds size limit")
  }
  if encoded.length() % 4 == 1 {
    raise Malformed("invalid base64url length")
  }
  for character in encoded.to_array() {
    let valid = character.is_ascii_alphabetic() ||
      character.is_ascii_digit() ||
      character == '-' ||
      character == '_'
    if !valid {
      raise Malformed("base64url contains a non-url-safe character")
    }
  }
  let standard = encoded
    .replace_all(old="-", new="+")
    .replace_all(old="_", new="/")
  let token = @base64.decode(standard) catch {
    _ => raise Malformed("invalid base64url token")
  }
  if token.length() > MAX_TOKEN_SIZE {
    raise Malformed("decoded token exceeds size limit")
  }
  if token_to_base64url(token) != encoded {
    raise Malformed("noncanonical base64url token")
  }
  token
}
