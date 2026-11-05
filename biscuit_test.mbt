///|
test "v1 authority payload uses domain separation and little endian fields" {
  let payload = @biscuit.authority_payload_v1(b"abc", b"key")
  assert_eq(
    payload, b"\x00BLOCK\x00\x00VERSION\x00\x01\x00\x00\x00\x00PAYLOAD\x00abc\x00ALGORITHM\x00\x00\x00\x00\x00\x00NEXTKEY\x00key",
  )
}

///|
test "issue a raw block and verify its signature chain" {
  // RFC 8032 test seed and public key. Never use test keys in production.
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let next_seed = Bytes::make(32, b'\x42')
  let token = @biscuit.issue_raw(b"\x18\x03", root_seed, next_seed)
  @biscuit.verify_signatures(token, root_key)
}

///|
test "verified authority facts decode null and nested array terms" {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let block = b"\x18\x06\x22\x10\x0a\x0e\x08\x04\x12\x02\x42\x00\x12\x06\x4a\x04\x0a\x02\x10\x07"
  let token = @biscuit.issue_raw(block, root_seed, Bytes::make(32, b'\x43'))
  let facts = @biscuit.verify_authority_facts(token, root_key)
  assert_eq(facts.length(), 1)
  let query = @biscuit.parse_query("right(null, [7])")
  assert_eq(@biscuit.match_query(query, facts).length(), 1)
}

///|
test "verified authority facts decode map keys and values" {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let block = b"\x18\x06\x22\x12\x0a\x10\x08\x04\x12\x0c\x52\x0a\x0a\x08\x0a\x02\x10\x00\x12\x02\x10\x09"
  let token = @biscuit.issue_raw(block, root_seed, Bytes::make(32, b'\x44'))
  let facts = @biscuit.verify_authority_facts(token, root_key)
  assert_eq(facts.length(), 1)
  assert_eq(
    facts[0].values[0],
    @biscuit.MapValue([(@biscuit.StringKey("read"), @biscuit.Number(9L))]),
  )
}

///|
test "authorize simple tokens and checks while rejecting appended rights" {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let predicate = b"\x08\x04\x12\x03\x18\x80\x08\x12\x02\x18\x00"
  let fact = b"\x22\x0d\x0a\x0b" + predicate
  let query = b"\x0a\x11\x0a\x02\x08\x04\x12\x0b" + predicate
  let authority = b"\x0a\x05file1\x18\x06" + fact + b"\x32\x13" + query
  let token = @biscuit.issue_raw(authority, root_seed, Bytes::make(32, b'\x46'))
  let policy = @biscuit.Policy::{
    kind: @biscuit.Allow,
    queries: [@biscuit.parse_query_body("right(\"file1\", \"read\")")],
  }
  @biscuit.authorize_token(token, root_key, [], [], [policy], 100, 20)

  let attenuated = @biscuit.append_raw(
    token,
    root_key,
    b"\x18\x06\x32\x13" + query,
    Bytes::make(32, b'\x47'),
  )
  @biscuit.authorize_token(attenuated, root_key, [], [], [policy], 100, 20)

  let escalated = @biscuit.append_raw(
    token,
    root_key,
    b"\x18\x06" + fact,
    Bytes::make(32, b'\x48'),
  )
  let accepted = try {
    @biscuit.authorize_token(escalated, root_key, [], [], [policy], 100, 20)
    true
  } catch {
    @biscuit.UnsupportedTokenFeature(_) => false
    _ => abort("expected appended rights to be rejected")
  }
  assert_false(accepted)
}

///|
test "token authorization rejects explicit scope annotations" {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let token = @biscuit.issue_raw(
    b"\x18\x04\x3a\x02\x08\x00",
    root_seed,
    Bytes::make(32, b'\x49'),
  )
  let rejected = try {
    @biscuit.authorize_token(token, root_key, [], [], [], 100, 20)
    false
  } catch {
    @biscuit.UnsupportedTokenFeature(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "version 3 rejects null terms introduced in version 3.3" {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let block = b"\x18\x03\x22\x08\x0a\x06\x08\x04\x12\x02\x42\x00"
  let token = @biscuit.issue_raw(block, root_seed, Bytes::make(32, b'\x4a'))
  let accepted = try {
    ignore(@biscuit.verify_authority_facts(token, root_key))
    true
  } catch {
    @biscuit.Unsupported(_) => false
    _ => true
  }
  assert_false(accepted)
}

///|
test "serialized comparison expressions implement check one and check all" {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let prefix = b"\x0a\x05file1\x0a\x01r\x0a\x02op\x18\x06\x22\x0d\x0a\x0b\x08\x04\x12\x03\x18\x80\x08\x12\x02\x18\x00\x22\x0d\x0a\x0b\x08\x04\x12\x03\x18\x80\x08\x12\x02\x18\x01"
  let rule = b"\x0a\x02\x08\x04\x12\x0c\x08\x04\x12\x03\x08\x81\x08\x12\x03\x08\x82\x08\x1a\x13\x0a\x05\x0a\x03\x08\x82\x08\x0a\x04\x0a\x02\x18\x00\x0a\x04\x1a\x02\x08\x04"
  let check_prefix = b"\x32\x2b\x0a\x27" + rule
  let policy = @biscuit.Policy::{
    kind: @biscuit.Allow,
    queries: [@biscuit.parse_query_body("right(\"file1\", \"read\")")],
  }
  let one_token = @biscuit.issue_raw(
    prefix + check_prefix + b"\x10\x00",
    root_seed,
    Bytes::make(32, b'\x4b'),
  )
  assert_eq(
    @biscuit.verify_block_facts(one_token, root_key)[0].facts.length(),
    2,
  )
  @biscuit.authorize_token(one_token, root_key, [], [], [policy], 100, 20)

  let all_token = @biscuit.issue_raw(
    prefix + check_prefix + b"\x10\x01",
    root_seed,
    Bytes::make(32, b'\x4c'),
  )
  let all_accepted = try {
    @biscuit.authorize_token(all_token, root_key, [], [], [policy], 100, 20)
    true
  } catch {
    @biscuit.FailedCheck(0) => false
    _ => abort("expected check all to reject the write binding")
  }
  assert_false(all_accepted)
}

///|
test "issue rejects malformed or repeated seeds" {
  let seed = Bytes::make(32, b'\x42')
  for (root, next) in [(b"short", seed), (seed, seed)] {
    let rejected = try {
      ignore(@biscuit.issue_raw(b"\x18\x03", root, next))
      false
    } catch {
      @biscuit.Malformed(_) => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "structured block round trips v3.3 value types and unicode symbols" {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let fact = @biscuit.Fact::{
    name: "资源",
    values: [
      @biscuit.Text("document"),
      @biscuit.Number(-42),
      @biscuit.Date(1700000000),
      @biscuit.ByteString(b"\x00\xff"),
      @biscuit.Boolean(true),
      @biscuit.Null,
      @biscuit.ArrayValue([@biscuit.Number(1), @biscuit.Text("值")]),
      @biscuit.SetValue([@biscuit.Text("a"), @biscuit.Text("b")]),
      @biscuit.MapValue([
        (@biscuit.StringKey("标签"), @biscuit.Boolean(false)),
        (@biscuit.IntegerKey(9), @biscuit.Null),
      ]),
    ],
  }
  let token = @biscuit.issue(
    [fact],
    [],
    [],
    6,
    root_seed,
    Bytes::make(32, b'\x52'),
  )
  @biscuit.verify_signatures(token, root_key)
  let blocks = @biscuit.verify_block_facts(token, root_key)
  assert_eq(blocks.length(), 1)
  assert_eq(blocks[0].facts.length(), 1)
  assert_true(blocks[0].facts[0] == fact)
}

///|
test "structured issue and check-only attenuation authorize end to end" {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let read_fact = @biscuit.parse_fact("right(\"file1\", \"read\")")
  let read_query = @biscuit.parse_query_body("right(\"file1\", \"read\")")
  let read_check = @biscuit.Check::{
    mode: @biscuit.Any,
    queries: [read_query],
  }
  let token = @biscuit.issue(
    [read_fact],
    [],
    [read_check],
    6,
    root_seed,
    Bytes::make(32, b'\x53'),
  )
  let programs = @biscuit.verify_block_programs(token, root_key)
  assert_eq(programs.length(), 1)
  assert_eq(programs[0].checks.length(), 1)
  let policy = @biscuit.Policy::{ kind: @biscuit.Allow, queries: [read_query], }
  @biscuit.authorize_token(token, root_key, [], [], [policy], 100, 20)
  let attenuated = @biscuit.attenuate(
    token,
    root_key,
    [read_check],
    6,
    Bytes::make(32, b'\x54'),
  )
  @biscuit.verify_signatures(attenuated, root_key)
  @biscuit.authorize_token(attenuated, root_key, [], [], [policy], 100, 20)
  assert_eq(@biscuit.verify_block_facts(attenuated, root_key).length(), 2)
}

///|
test "structured encoder rejects unsafe rules and unsupported versions" {
  let unsafe_rule = @biscuit.Rule::{
    head: @biscuit.Predicate::{
      name: "derived",
      terms: [@biscuit.Variable("unbound")],
    },
    body: [],
    conditions: [],
  }
  let unsafe_rejected = try {
    ignore(@biscuit.encode_block([], [unsafe_rule], [], 6))
    false
  } catch {
    @biscuit.Malformed(_) => true
    _ => false
  }
  assert_true(unsafe_rejected)
  let version_rejected = try {
    ignore(@biscuit.encode_block([], [], [], 7))
    false
  } catch {
    @biscuit.Unsupported(_) => true
    _ => false
  }
  assert_true(version_rejected)
}

///|
test "conditional rule parsing, encoding and authorization agree" {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let rule = @biscuit.parse_rule(
    "eligible($n) <- item($n), caption($n, \"value, <-\"), $n >= 10",
  )
  assert_eq(rule.body.length(), 2)
  assert_eq(rule.conditions.length(), 1)
  let check = @biscuit.parse_check_body("eligible($n), $n >= 10", @biscuit.Any)
  let policy = @biscuit.parse_policy_body("eligible($n)", @biscuit.Allow)
  let facts = [
    @biscuit.parse_fact("item(12)"),
    @biscuit.parse_fact("caption(12, \"value, <-\")"),
  ]
  let token = @biscuit.issue(
    facts,
    [rule],
    [check],
    6,
    root_seed,
    Bytes::make(32, b'\x55'),
  )
  let programs = @biscuit.verify_block_programs(token, root_key)
  assert_eq(programs[0].rules.length(), 1)
  assert_false(programs[0].has_unsupported_expressions)
  assert_eq(programs[0].rules[0].conditions.length(), 1)
  @biscuit.authorize_token(token, root_key, [], [], [policy], 100, 20)

  let too_small = @biscuit.issue(
    [
      @biscuit.parse_fact("item(9)"),
      @biscuit.parse_fact("caption(9, \"value, <-\")"),
    ],
    [rule],
    [check],
    6,
    root_seed,
    Bytes::make(32, b'\x56'),
  )
  let allowed = try {
    @biscuit.authorize_token(too_small, root_key, [], [], [policy], 100, 20)
    true
  } catch {
    @biscuit.FailedCheck(0) => false
    _ => abort("expected conditional rule check to fail")
  }
  assert_false(allowed)
}

///|
test "canonical base64url transport round trips and rejects aliases" {
  assert_eq(@biscuit.token_to_base64url(b"\xfb\xff\x00"), "-_8A")
  for length = 1; length <= 96; length = length + 1 {
    let bytes = Bytes::makei(length, fn(index) { index.to_byte() })
    let encoded = @biscuit.token_to_base64url(bytes)
    assert_true(@biscuit.token_from_base64url(encoded) == bytes)
  }
  for malformed in ["", "A", "+/8", "AA==", "ab=c", "AA\n"] {
    let accepted = try {
      ignore(@biscuit.token_from_base64url(malformed))
      true
    } catch {
      @biscuit.Malformed(_) => false
      _ => false
    }
    assert_false(accepted)
  }
  let noncanonical = try {
    ignore(@biscuit.token_from_base64url("AR"))
    true
  } catch {
    @biscuit.Malformed(_) => false
    _ => false
  }
  assert_false(noncanonical)
}

///|
test "structured encoder rejects duplicate map keys and old-version collections" {
  let duplicate = @biscuit.Fact::{
    name: "config",
    values: [
      @biscuit.MapValue([
        (@biscuit.StringKey("mode"), @biscuit.Text("read")),
        (@biscuit.StringKey("mode"), @biscuit.Text("write")),
      ]),
    ],
  }
  let duplicate_rejected = try {
    ignore(@biscuit.encode_block([duplicate], [], [], 6))
    false
  } catch {
    @biscuit.Malformed(_) => true
    _ => false
  }
  assert_true(duplicate_rejected)
  let collection = @biscuit.Fact::{
    name: "tags",
    values: [@biscuit.ArrayValue([@biscuit.Text("reader")])],
  }
  let version_rejected = try {
    ignore(@biscuit.encode_block([collection], [], [], 5))
    false
  } catch {
    @biscuit.Unsupported(_) => true
    _ => false
  }
  assert_true(version_rejected)
}

///|
test "check-only attenuation rejects empty restrictions" {
  let root_seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let token = @biscuit.issue([], [], [], 6, root_seed, Bytes::make(32, b'\x57'))
  let rejected = try {
    ignore(@biscuit.attenuate(token, root_key, [], 6, Bytes::make(32, b'\x58')))
    false
  } catch {
    @biscuit.Malformed(_) => true
    _ => false
  }
  assert_true(rejected)
}
