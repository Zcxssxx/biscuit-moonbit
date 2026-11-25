///|
/// Return the standard public-key bytes and explicit algorithm of an external signer.
pub fn external_verification_key(
  signature : ExternalSignature,
) -> VerificationKey raise TokenError {
  {
    algorithm: key_algorithm(signature.public_key),
    key: key_bytes(signature.public_key),
  }
}

///|
pub fn trust_verification_key(
  key : VerificationKey,
) -> TrustScope raise TokenError {
  TrustPublicKey(pack_key(key))
}

///|
pub fn issue_with_keys(
  facts : Array[Fact],
  rules : Array[Rule],
  checks : Array[Check],
  scopes : Array[TrustScope],
  version : Int32,
  root : SigningKey,
  next : SigningKey,
) -> Bytes raise TokenError {
  issue_raw_with_keys(
    encode_block_with_scopes(facts, rules, checks, scopes, version),
    root,
    next,
  )
}

///|
pub fn attenuate_with_key(
  token : Bytes,
  root : VerificationKey,
  facts : Array[Fact],
  rules : Array[Rule],
  checks : Array[Check],
  scopes : Array[TrustScope],
  version : Int32,
  next : SigningKey,
) -> Bytes raise TokenError {
  attenuate_structured(
    token,
    pack_key(root),
    facts,
    rules,
    checks,
    scopes,
    version,
    next,
  )
}

///|
/// Append a serialized Datalog block, selecting the next proof key's algorithm.
pub fn append_with_key(
  token : Bytes,
  root : VerificationKey,
  block_data : Bytes,
  next : SigningKey,
) -> Bytes raise TokenError {
  append_raw_with_external(token, pack_key(root), block_data, next, None)
}

///|
pub fn verify_with_key(
  token : Bytes,
  root : VerificationKey,
) -> Unit raise TokenError {
  verify_signatures(token, pack_key(root))
}

///|
pub fn seal_with_key(
  token : Bytes,
  root : VerificationKey,
) -> Bytes raise TokenError {
  seal_token(token, pack_key(root))
}

///|
pub fn third_party_request_with_key(
  token : Bytes,
  root : VerificationKey,
) -> Bytes raise TokenError {
  create_third_party_request(token, pack_key(root))
}

///|
pub fn append_third_party_with_key(
  token : Bytes,
  root : VerificationKey,
  contents : ThirdPartyBlockContents,
  next : SigningKey,
) -> Bytes raise TokenError {
  append_third_party_typed(
    token,
    pack_key(root),
    contents.payload,
    next,
    contents.external_signature,
  )
}

///|
pub fn authorize_with_key(
  token : Bytes,
  root : VerificationKey,
  facts : Array[Fact],
  rules : Array[Rule],
  checks : Array[Check],
  policies : Array[Policy],
  max_facts : Int32,
  max_iterations : Int32,
  externals : ExternalFunctions,
) -> AuthorizationResult raise AuthorizationError {
  prepare_with_key(token, root).authorize(
    facts, rules, checks, policies, max_facts, max_iterations, externals,
  )
}

///|
/// Authenticate and decode a token using an explicitly typed trusted root.
pub fn prepare_with_key(
  token : Bytes,
  root : VerificationKey,
) -> PreparedToken raise AuthorizationError {
  let key = pack_key(root) catch {
    _ => raise InvalidToken("invalid trusted root key")
  }
  prepare_token(token, key)
}
