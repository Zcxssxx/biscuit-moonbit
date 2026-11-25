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

///|
test "external callbacks receive copies of signed collections" {
  let root = @biscuit.SigningKey::{
    algorithm: @biscuit.Ed25519,
    secret: Bytes::make(32, b'\x51'),
  }
  let token = @biscuit.issue_with_keys(
    [@biscuit.parse_fact("grant({\"files\": [\"logs\"]})")],
    [],
    [],
    [],
    6,
    root,
    { algorithm: @biscuit.Ed25519, secret: Bytes::make(32, b'\x52'), },
  )
  let prepared = @biscuit.prepare_with_key(
    token,
    @biscuit.verification_key(root),
  )
  let edit = fn(value : @biscuit.Value) -> @biscuit.Value {
    match value {
      @biscuit.MapValue(entries) =>
        match entries[0].1 {
          @biscuit.ArrayValue(files) => {
            files.push(@biscuit.Text("scratch"))
            @biscuit.Boolean(true)
          }
          _ => @biscuit.Boolean(false)
        }
      _ => @biscuit.Boolean(false)
    }
  }
  let externals = @biscuit.ExternalFunctions::{
    unary: Map([("edit", value => edit(value))]),
    binary: Map([
      (
        "edit_pair",
        (left, right) => {
          let left_edited = edit(left)
          let right_edited = edit(right)
          @biscuit.Boolean(
            left_edited == @biscuit.Boolean(true) &&
            right_edited == @biscuit.Boolean(true),
          )
        },
      ),
    ]),
  }
  let exercise = @biscuit.parse_policy(
    "allow if grant($g), $g.extern::edit(), $g.extern::edit_pair($g), $g == {\"files\": [\"logs\"]}",
  )
  let original = @biscuit.parse_policy(
    "allow if grant({\"files\": [\"logs\"]})",
  )
  for policy in [exercise, original] {
    assert_eq(
      prepared.authorize([], [], [], [policy], 30, 10, externals).policy_index,
      0,
    )
  }
}

///|
test "external callback argument nesting is bounded" {
  let mut nested : @biscuit.Value = @biscuit.Null
  for _ in 0..<64 {
    nested = @biscuit.ArrayValue([nested])
  }
  let fact = @biscuit.Fact::{ name: "input", values: [nested], }
  let externals = @biscuit.ExternalFunctions::{
    unary: Map([("accept", _ => @biscuit.Boolean(true))]),
    binary: Map([]),
  }
  let limited = try {
    ignore(
      @biscuit.evaluate_policy_set_with_externals(
        [fact],
        [],
        [@biscuit.parse_policy("allow if input($x), $x.extern::accept()")],
        externals,
      ),
    )
    false
  } catch {
    @biscuit.Expression(@biscuit.StepLimit) => true
    _ => false
  }
  assert_true(limited)
}
