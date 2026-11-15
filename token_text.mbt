///|
const MAX_TOKEN_SIZE = 1048576

///|
const MAX_BASE64URL_SIZE = 1398104

///|
/// Encode token bytes as canonical padded Base64URL, matching biscuit-rust's
/// textual form. This function does not verify the token or its signature.
pub fn token_to_base64url(token : Bytes) -> String {
  @base64.encode(token, padding=true)
  .replace_all(old="+", new="-")
  .replace_all(old="/", new="_")
}

///|
fn token_to_base64url_unpadded(token : Bytes) -> String {
  @base64.encode(token, padding=false)
  .replace_all(old="+", new="-")
  .replace_all(old="/", new="_")
}

///|
/// Decode canonical Base64URL token bytes, accepting optional RFC 4648 padding.
/// This validates only the representation and size; callers must still verify
/// the token signature.
pub fn token_from_base64url(encoded : String) -> Bytes raise TokenError {
  if encoded.length() == 0 {
    raise Malformed("empty token encoding")
  }
  if encoded.length() > MAX_BASE64URL_SIZE {
    raise Malformed("encoded token exceeds size limit")
  }
  let mut padding_count = 0
  let mut saw_padding = false
  for character in encoded.to_array() {
    if character == '=' {
      saw_padding = true
      padding_count += 1
    } else {
      if saw_padding {
        raise Malformed("base64url padding must be at the end")
      }
      let valid = character.is_ascii_alphabetic() ||
        character.is_ascii_digit() ||
        character == '-' ||
        character == '_'
      if !valid {
        raise Malformed("base64url contains a non-url-safe character")
      }
    }
  }
  if padding_count > 2 {
    raise Malformed("base64url has too much padding")
  }
  let unpadded = encoded.replace_all(old="=", new="")
  if unpadded.length() == 0 {
    raise Malformed("empty token encoding")
  }
  if unpadded.length() % 4 == 1 {
    raise Malformed("invalid base64url length")
  }
  if padding_count > 0 {
    let required_padding = (4 - unpadded.length() % 4) % 4
    if encoded.length() % 4 != 0 || padding_count != required_padding {
      raise Malformed("base64url padding is not canonical")
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
  if token_to_base64url_unpadded(token) != unpadded {
    raise Malformed("noncanonical base64url token")
  }
  token
}
