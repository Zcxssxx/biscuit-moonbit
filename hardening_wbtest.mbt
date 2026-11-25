///|
test "third-party request rejects malformed and legacy inputs before signing" {
  let seed = Bytes::make(32, b'\x31')
  for request in [b"", b"\x1a\x00", b"\x1a\x01x", b"\x1a\x40short"] {
    let rejected = try {
      ignore(sign_third_party_request(request, b"", seed))
      false
    } catch {
      Malformed(_) => true
      _ => false
    }
    assert_true(rejected)
  }
  for tag in [b'\x0a', b'\x12'] {
    let request = encode_bytes_field(tag, b"") +
      encode_bytes_field(b'\x1a', Bytes::make(64, b'\x32'))
    let rejected = try {
      ignore(sign_third_party_request(request, b"", seed))
      false
    } catch {
      Unsupported(_) => true
      _ => false
    }
    assert_true(rejected)
  }
  let oversized = Bytes::make(MAX_TOKEN_SIZE + 1, b'\x00')
  let rejected = try {
    ignore(parse_third_party_block(oversized))
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(rejected)
  let rejected_block = try {
    ignore(
      sign_third_party_request(
        encode_bytes_field(b'\x1a', Bytes::make(64, b'\x32')),
        oversized,
        seed,
      ),
    )
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(rejected_block)
}

///|
test "predicate index preserves origin variants and join binding limits" {
  let facts = [
    FactOrigin::{ fact: parse_fact("member(1)"), origins: [0], },
    FactOrigin::{ fact: parse_fact("member(1)"), origins: [1], },
    FactOrigin::{ fact: parse_fact("member(2)"), origins: [0], },
    FactOrigin::{ fact: parse_fact("other(99)"), origins: [0], },
    FactOrigin::{ fact: parse_fact("member(1, 2)"), origins: [0], },
  ]
  let rule = parse_rule("pair($a, $b) <- member($a), member($b)")
  let index = ScopedFacts::from_facts(facts)
  assert_eq(scoped_bindings(rule.body, index, [0], 10).length(), 4)
  assert_eq(scoped_bindings(rule.body, index, [0, 1], 10).length(), 9)
  assert_eq(scoped_bindings(rule.body, index, [], 10).length(), 0)
  let limited = try {
    ignore(scoped_bindings(rule.body, index, [0, 1], 8))
    false
  } catch {
    FactLimit => true
    _ => false
  }
  assert_true(limited)
}

///|
test "derived facts enter the index with their original scopes and budgets" {
  let facts = [
    FactOrigin::{ fact: parse_fact("source(7)"), origins: [0], },
    FactOrigin::{ fact: parse_fact("source(7)"), origins: [1], },
  ]
  let rules = [
    ScopedRule::{
      rule: parse_rule("stage($x) <- source($x)"),
      origin: 2,
      visible_origins: [0, 1, 2],
    },
    ScopedRule::{
      rule: parse_rule("outcome($x) <- stage($x)"),
      origin: 2,
      visible_origins: [0, 2],
    },
  ]
  let externals = ExternalFunctions::{ unary: Map([]), binary: Map([]), }
  let derived = derive_scoped_facts(facts, rules, 5, 2, externals)
  let stage = parse_query_body("stage($x)")
  let outcome = parse_query_body("outcome(7)")
  assert_eq(derived.count, 5)
  assert_eq(scoped_bindings(stage.body, derived, [0, 1, 2], 2).length(), 2)
  assert_eq(scoped_bindings(stage.body, derived, [0, 2], 2).length(), 1)
  assert_true(scoped_query_matches(outcome, derived, [0, 2], externals))
  assert_false(scoped_query_matches(outcome, derived, [1, 2], externals))
  let fact_limited = try {
    ignore(derive_scoped_facts(facts, rules, 4, 2, externals))
    false
  } catch {
    FactLimit => true
    _ => false
  }
  assert_true(fact_limited)
  let iteration_limited = try {
    ignore(derive_scoped_facts(facts, rules, 5, 1, externals))
    false
  } catch {
    IterationLimit => true
    _ => false
  }
  assert_true(iteration_limited)
}
