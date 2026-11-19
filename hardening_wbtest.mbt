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
  assert_eq(scoped_rule_bindings(rule, facts, [0], 10).length(), 4)
  assert_eq(scoped_rule_bindings(rule, facts, [0, 1], 10).length(), 9)
  assert_eq(scoped_rule_bindings(rule, facts, [], 10).length(), 0)
  let limited = try {
    ignore(scoped_rule_bindings(rule, facts, [0, 1], 8))
    false
  } catch {
    FactLimit => true
    _ => false
  }
  assert_true(limited)
}
