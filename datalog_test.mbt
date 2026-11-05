///|
test "parse common authorization fact values" {
  let fact = @biscuit.parse_fact("permit(\"文档/一\", -12, true, null)")
  assert_eq(fact.name, "permit")
  assert_eq(fact.values.length(), 4)
  assert_eq(fact.values[0], @biscuit.Text("文档/一"))
  assert_eq(fact.values[1], @biscuit.Number(-12L))
  assert_eq(fact.values[2], @biscuit.Boolean(true))
  assert_eq(fact.values[3], @biscuit.Null)
}

///|
test "parse byte string facts as hexadecimal" {
  let fact = @biscuit.parse_fact("digest(hex:00a1FF)")
  assert_eq(fact.values[0], @biscuit.ByteString(b"\x00\xa1\xff"))
  let invalid = try {
    ignore(@biscuit.parse_fact("digest(hex:xyz)"))
    false
  } catch {
    _ => true
  }
  assert_true(invalid)
}

///|
test "parse nested array fact terms" {
  let fact = @biscuit.parse_fact(
    "payload([1, \"text, with comma\", [false, null]])",
  )
  assert_eq(
    fact.values[0],
    @biscuit.ArrayValue([
      @biscuit.Number(1L),
      @biscuit.Text("text, with comma"),
      @biscuit.ArrayValue([@biscuit.Boolean(false), @biscuit.Null]),
    ]),
  )
}

///|
test "parse typed deduplicated set values" {
  let first = @biscuit.parse_fact("roles({\"reader\", \"admin\", \"reader\"})")
  let second = @biscuit.parse_fact("roles({\"admin\", \"reader\"})")
  assert_eq(first.values[0], second.values[0])
  assert_eq(
    first.values[0],
    @biscuit.SetValue([@biscuit.Text("reader"), @biscuit.Text("admin")]),
  )
  let empty = @biscuit.parse_fact("roles({,})")
  assert_eq(empty.values[0], @biscuit.SetValue([]))
  let mixed = @biscuit.parse_fact("values({1, true, \"x\"})")
  assert_eq(
    mixed.values[0],
    @biscuit.SetValue([
      @biscuit.Number(1L),
      @biscuit.Boolean(true),
      @biscuit.Text("x"),
    ]),
  )
}

///|
test "reject nested sets and ambiguous empty maps" {
  for source in ["x({{1}})", "x({})"] {
    let accepted = try {
      ignore(@biscuit.parse_fact(source))
      true
    } catch {
      _ => false
    }
    assert_false(accepted)
  }
}

///|
test "evaluate comparisons against query bindings" {
  let facts = [
    @biscuit.parse_fact("rank(\"alice\", 5)"),
    @biscuit.parse_fact("rank(\"bob\", 2)"),
  ]
  let allow = @biscuit.Policy::{
    kind: @biscuit.Allow,
    queries: [
      @biscuit.parse_query_body(
        "rank($user, $level), $level >= 3, $user == \"alice\"",
      ),
    ],
  }
  @biscuit.evaluate_policy_set(facts, [], [allow])
  let reject_bob = try {
    @biscuit.evaluate_policy_set(facts, [], [
      @biscuit.Policy::{
        kind: @biscuit.Allow,
        queries: [
          @biscuit.parse_query_body("rank(\"bob\", $level), $level > 3"),
        ],
      },
    ])
    false
  } catch {
    @biscuit.NoMatchingPolicy => true
    _ => false
  }
  assert_true(reject_bob)
}

///|
test "match facts and enforce repeated variable equality" {
  let facts = [
    @biscuit.parse_fact("edge(\"a\", \"b\")"),
    @biscuit.parse_fact("edge(\"b\", \"c\")"),
    @biscuit.parse_fact("loop(\"a\", \"a\")"),
  ]
  let query = @biscuit.parse_query("edge($from, $to)")
  let matches = @biscuit.match_query(query, facts)
  assert_eq(matches.length(), 2)
  let same = @biscuit.match_query(@biscuit.parse_query("loop($x, $x)"), facts)
  assert_eq(same.length(), 1)
}

///|
test "constant and name matching are exact" {
  let facts = [
    @biscuit.parse_fact("right(\"/docs\", \"read\")"),
    @biscuit.parse_fact("right(\"/docs\", \"write\")"),
  ]
  let query = @biscuit.parse_query("right($path, \"read\")")
  let matches = @biscuit.match_query(query, facts)
  assert_eq(matches.length(), 1)
  assert_eq(matches[0].get("path"), Some(@biscuit.Text("/docs")))
}

///|
test "malformed Datalog predicates fail closed" {
  for
    source in [
      "", "x", "x(,)", "x($v)", "x(1) trailing", "x(\"open)", "x(999999999999999999999)",
    ] {
    let accepted = try {
      ignore(@biscuit.parse_fact(source))
      true
    } catch {
      _ => false
    }
    assert_false(accepted)
  }
  let too_large = String::from_array(Array::make(65537, 'x'))
  let accepted = try {
    ignore(@biscuit.parse_fact(too_large))
    true
  } catch {
    _ => false
  }
  assert_false(accepted)
}

///|
test "all checks pass before first matching policy is applied" {
  let facts = [
    @biscuit.parse_fact("user(\"alice\")"),
    @biscuit.parse_fact("resource(\"report\")"),
    @biscuit.parse_fact("operation(\"read\")"),
  ]
  let checks = [
    @biscuit.Check::{
      mode: @biscuit.All,
      queries: [
        @biscuit.parse_query_body("user(\"alice\")"),
        @biscuit.parse_query_body("resource(\"report\")"),
      ],
    },
  ]
  let policies = [
    @biscuit.Policy::{
      kind: @biscuit.Deny,
      queries: [@biscuit.parse_query_body("operation(\"write\")")],
    },
    @biscuit.Policy::{
      kind: @biscuit.Allow,
      queries: [@biscuit.parse_query_body("operation(\"read\")")],
    },
  ]
  @biscuit.evaluate_policy_set(facts, checks, policies)
}

///|
test "a missing check or unmatched policy denies by default" {
  let facts = [@biscuit.parse_fact("user(\"alice\")")]
  let check = @biscuit.Check::{
    mode: @biscuit.Any,
    queries: [@biscuit.parse_query_body("resource(\"report\")")],
  }
  let policy = @biscuit.Policy::{
    kind: @biscuit.Allow,
    queries: [@biscuit.parse_query_body("user(\"bob\")")],
  }
  let check_passed = try {
    @biscuit.evaluate_policy_set(facts, [check], [policy])
    true
  } catch {
    @biscuit.FailedCheck(0) => false
    _ => true
  }
  assert_false(check_passed)
  let no_policy = try {
    @biscuit.evaluate_policy_set(facts, [], [policy])
    true
  } catch {
    @biscuit.NoMatchingPolicy => false
    _ => true
  }
  assert_false(no_policy)
  let deny_first = try {
    @biscuit.evaluate_policy_set([@biscuit.parse_fact("role(\"admin\")")], [], [
      @biscuit.Policy::{
        kind: @biscuit.Deny,
        queries: [@biscuit.parse_query_body("role(\"admin\")")],
      },
      @biscuit.Policy::{
        kind: @biscuit.Allow,
        queries: [@biscuit.parse_query_body("role(\"admin\")")],
      },
    ])
    true
  } catch {
    @biscuit.Denied(0) => false
    _ => true
  }
  assert_false(deny_first)
}

///|
test "recursive positive rules derive transitive facts" {
  let facts = [
    @biscuit.parse_fact("parent(\"a\", \"b\")"),
    @biscuit.parse_fact("parent(\"b\", \"c\")"),
    @biscuit.parse_fact("parent(\"c\", \"d\")"),
  ]
  let rules = [
    @biscuit.parse_rule("ancestor($x, $y) <- parent($x, $y)"),
    @biscuit.parse_rule("ancestor($x, $z) <- ancestor($x, $y), parent($y, $z)"),
  ]
  let result = @biscuit.derive_facts(facts, rules, 100, 10)
  let query = @biscuit.parse_query("ancestor(\"a\", $descendant)")
  let descendants = @biscuit.match_query(query, result)
  assert_eq(descendants.length(), 3)
}

///|
test "unsafe rules and evaluation exhaustion fail" {
  let unsafe_rule = try {
    ignore(@biscuit.parse_rule("grant($user) <- login(\"ok\")"))
    false
  } catch {
    _ => true
  }
  assert_true(unsafe_rule)
  let facts = [@biscuit.parse_fact("edge(\"a\", \"b\")")]
  let rule = @biscuit.parse_rule("reach($x, $y) <- edge($x, $y)")
  let fact_limited = try {
    ignore(@biscuit.derive_facts(facts, [rule], 1, 10))
    false
  } catch {
    @biscuit.FactLimit => true
    _ => false
  }
  assert_true(fact_limited)
  let iteration_limited = try {
    ignore(@biscuit.derive_facts(facts, [rule], 10, 1))
    false
  } catch {
    @biscuit.IterationLimit => true
    _ => false
  }
  assert_true(iteration_limited)
}

///|
test "check and policy query predicates join through shared variables" {
  let facts = [
    @biscuit.parse_fact("user(\"alice\")"),
    @biscuit.parse_fact("role(\"alice\", \"reader\")"),
    @biscuit.parse_fact("role(\"bob\", \"admin\")"),
  ]
  let query = @biscuit.parse_query_body("user($u), role($u, \"reader\")")
  let check = @biscuit.Check::{ mode: @biscuit.Any, queries: [query], }
  let allow = @biscuit.Policy::{
    kind: @biscuit.Allow,
    queries: [@biscuit.parse_query_body("user($u), role($u, \"reader\")")],
  }
  @biscuit.evaluate_policy_set(facts, [check], [allow])
  let impossible = @biscuit.parse_query_body("user($u), role($u, \"admin\")")
  assert_eq(
    @biscuit.match_query(@biscuit.parse_query("user($u)"), facts).length(),
    1,
  )
  assert_false(
    try {
      @biscuit.evaluate_policy_set(
        facts,
        [@biscuit.Check::{ mode: @biscuit.Any, queries: [impossible], }],
        [allow],
      )
      true
    } catch {
      @biscuit.FailedCheck(0) => false
      _ => true
    },
  )
}
