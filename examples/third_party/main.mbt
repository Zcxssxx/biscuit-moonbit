///|
fn main {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_public_key = @ed25519.derive_public_key(root_seed) catch {
    _ => abort("could not derive root public key")
  }
  let external_seed = Bytes::make(32, b'\x4b')
  let external_public_key = @ed25519.derive_public_key(external_seed) catch {
    _ => abort("could not derive external public key")
  }
  let external_public_key_hex = @hex.encode(external_public_key)
  let check = @biscuit.parse_check_body(
    "read(true) trusting ed25519/" + external_public_key_hex,
    @biscuit.Any,
  ) catch {
    _ => abort("could not parse third-party check")
  }
  let token = @biscuit.issue(
    [],
    [],
    [check],
    6,
    root_seed,
    Bytes::make(32, b'\x4a'),
  ) catch {
    _ => abort("could not create third-party test token")
  }
  let request = @biscuit.create_third_party_request(token, root_public_key) catch {
    _ => abort("could not create third-party request")
  }
  let block_data = @biscuit.encode_block(
    [@biscuit.parse_fact("read(true)")],
    [],
    [],
    6,
  ) catch {
    _ => abort("could not encode third-party block")
  }
  let contents = @biscuit.build_third_party_block(
    request, block_data, external_seed,
  ) catch {
    _ => abort("could not sign third-party block")
  }
  let serialized_contents = @biscuit.serialize_third_party_block(contents)
  let appended = @biscuit.append_serialized_third_party_block(
    token,
    root_public_key,
    serialized_contents,
    Bytes::make(32, b'\x4c'),
  ) catch {
    _ => abort("could not append third-party block")
  }
  let allow_all = @biscuit.parse_policy_body("true", @biscuit.Allow) catch {
    _ => abort("could not create third-party authorization policy")
  }
  let programs = @biscuit.verify_block_programs(appended, root_public_key) catch {
    @biscuit.Malformed(message) =>
      abort("third-party program malformed: " + message)
    @biscuit.Unsupported(message) =>
      abort("third-party program unsupported: " + message)
    @biscuit.InvalidSignature =>
      abort("third-party program has invalid signature")
  }
  ignore(programs)
  @biscuit.authorize_token(
    appended,
    root_public_key,
    [],
    [],
    [allow_all],
    1000,
    100,
  ) catch {
    @biscuit.FailedCheck(index) =>
      abort("MoonBit failed third-party check " + index.to_string())
    @biscuit.NoMatchingPolicy => abort("MoonBit found no third-party policy")
    @biscuit.UnsupportedTokenFeature(message) =>
      abort("Unsupported third-party token: " + message)
    _ => abort("MoonBit could not authorize its third-party block")
  }
  println("ROOT_PUBLIC_KEY=" + @hex.encode(root_public_key))
  println("EXTERNAL_PUBLIC_KEY=" + external_public_key_hex)
  println("MOONBIT_TOKEN=" + @biscuit.token_to_base64url(token))
  println("MOONBIT_APPENDED_TOKEN=" + @biscuit.token_to_base64url(appended))
  println(
    "THIRD_PARTY_CONTENTS=" + @biscuit.token_to_base64url(serialized_contents),
  )
}
