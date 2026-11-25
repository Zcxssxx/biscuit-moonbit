///|
test "prepared mixed token evaluates each request independently" {
  let root = @biscuit.SigningKey::{
    algorithm: @biscuit.Ed25519,
    secret: Bytes::make(32, b'\x31'),
  }
  let trusted = @biscuit.verification_key(root)
  let token = @biscuit.issue_with_keys(
    [@biscuit.parse_fact("right(\"logs\", \"read\")")],
    [],
    [@biscuit.parse_check("check if time($t), $t < 10")],
    [],
    6,
    root,
    { algorithm: @biscuit.Secp256r1, secret: Bytes::make(32, b'\x32'), },
  )
  let prepared = @biscuit.prepare_with_key(token, trusted)
  let policies = [
    @biscuit.parse_policy(
      "allow if right($file, $op), resource($file), operation($op)",
    ),
    @biscuit.parse_policy("deny if true"),
  ]
  let externals = @biscuit.ExternalFunctions::{
    unary: Map([]),
    binary: Map([]),
  }
  let read = [
    @biscuit.parse_fact("resource(\"logs\")"),
    @biscuit.parse_fact("operation(\"read\")"),
    @biscuit.parse_fact("time(9)"),
  ]
  let write = [
    @biscuit.parse_fact("resource(\"logs\")"),
    @biscuit.parse_fact("operation(\"write\")"),
    @biscuit.parse_fact("time(9)"),
  ]
  let expired = [read[0], read[1], @biscuit.parse_fact("time(10)")]
  for (request, expected) in [(read, 0), (write, 1), (read, 0), (write, 1)] {
    let result = prepared.authorize(
      request,
      [],
      [],
      policies,
      30,
      10,
      externals,
    )
    let one_shot = @biscuit.authorize_with_key(
      token,
      trusted,
      request,
      [],
      [],
      policies,
      30,
      10,
      externals,
    )
    assert_true(result == one_shot)
    assert_eq(result.policy_index, expected)
  }
  let expired_rejected = try {
    ignore(prepared.authorize(expired, [], [], policies, 30, 10, externals))
    false
  } catch {
    @biscuit.FailedCheck(0) => true
    _ => false
  }
  assert_true(expired_rejected)
  let limit_rejected = try {
    ignore(prepared.authorize(read, [], [], policies, 1, 10, externals))
    false
  } catch {
    @biscuit.FactLimit => true
    _ => false
  }
  assert_true(limit_rejected)
  assert_eq(
    prepared.authorize(read, [], [], policies, 30, 10, externals).policy_index,
    0,
  )
}

///|
test "prepared token requires the matching root on construction" {
  let root = @biscuit.SigningKey::{
    algorithm: @biscuit.Secp256r1,
    secret: Bytes::make(32, b'\x44'),
  }
  let trusted = @biscuit.verification_key(root)
  let token = @biscuit.issue_with_keys([], [], [], [], 6, root, {
    algorithm: @biscuit.Ed25519,
    secret: Bytes::make(32, b'\x45'),
  })
  ignore(@biscuit.prepare_with_key(token, trusted))
  let wrong = @biscuit.verification_key({
    algorithm: @biscuit.Secp256r1,
    secret: Bytes::make(32, b'\x46'),
  })
  let rejected = try {
    ignore(@biscuit.prepare_with_key(token, wrong))
    false
  } catch {
    @biscuit.TokenSignatureInvalid => true
    _ => false
  }
  assert_true(rejected)
}
