///|
fn expression_query_matches(
  source : String,
  facts : Array[@biscuit.Fact],
) -> Bool {
  try {
    @biscuit.evaluate_policy_set(facts, [], [
      @biscuit.Policy::{
        kind: @biscuit.Allow,
        queries: [@biscuit.parse_query_body(source)],
      },
    ])
    true
  } catch {
    @biscuit.NoMatchingPolicy => false
    _ => false
  }
}

///|
test "Datalog expressions implement arithmetic precedence and errors" {
  let facts = [@biscuit.parse_fact("number(2)")]
  assert_true(expression_query_matches("number($n), $n + 3 * 4 == 14", facts))
  assert_true(expression_query_matches("number($n), ($n + 3) * 4 == 20", facts))
  assert_true(expression_query_matches("number($n), $n * 3 / 2 == 3", facts))
  assert_true(expression_query_matches("number($n), $n - 1 == 1", facts))
  assert_true(expression_query_matches("1 | 2 ^ 3 === 0", []))

  let overflow = try {
    @biscuit.evaluate_policy_set(
      [@biscuit.parse_fact("number(9223372036854775807)")],
      [],
      [
        @biscuit.Policy::{
          kind: @biscuit.Allow,
          queries: [@biscuit.parse_query_body("number($n), $n + 1 == 0")],
        },
      ],
    )
    false
  } catch {
    @biscuit.Expression(@biscuit.IntegerOverflow) => true
    _ => false
  }
  assert_true(overflow)

  let divide_by_zero = try {
    @biscuit.evaluate_policy_set(facts, [], [
      @biscuit.Policy::{
        kind: @biscuit.Allow,
        queries: [@biscuit.parse_query_body("number($n), $n / 0 == 0")],
      },
    ])
    false
  } catch {
    @biscuit.Expression(@biscuit.DivisionByZero) => true
    _ => false
  }
  assert_true(divide_by_zero)
}

///|
test "Datalog expressions implement values strings sets arrays and maps" {
  let facts = [
    @biscuit.parse_fact("word(\"biscuit\")"),
    @biscuit.parse_fact("roles({\"read\", \"write\"})"),
    @biscuit.parse_fact("items([1, 2, 3])"),
    @biscuit.parse_fact("config({\"mode\": \"read\", 1: true})"),
    @biscuit.parse_fact("payload(hex:00a1ff)"),
  ]
  assert_true(
    expression_query_matches(
      "word($s), $s.starts_with(\"bi\"), $s.ends_with(\"it\"), $s.contains(\"scu\"), $s.matches(\"^b.*t$\"), $s.length() == 7, $s.type() == \"string\"",
      facts,
    ),
  )
  assert_true(
    expression_query_matches(
      "roles($r), $r.intersection({\"read\", \"admin\"}) == {\"read\"}, $r.union({\"admin\"}) == {\"read\", \"write\", \"admin\"}, $r.contains(\"write\")",
      facts,
    ),
  )
  assert_true(expression_query_matches("items($a), $a.get(0) == 1", facts))
  assert_true(expression_query_matches("items($a), $a.contains(3)", facts))
  assert_true(
    expression_query_matches("items($a), $a.starts_with([1, 2])", facts),
  )
  assert_true(expression_query_matches("items($a), $a.ends_with([3])", facts))
  assert_true(expression_query_matches("items($a), $a.length() == 3", facts))
  assert_true(
    expression_query_matches("items($a), $a.type() == \"array\"", facts),
  )
  assert_true(
    expression_query_matches(
      "config($m), $m.get(\"mode\") == \"read\", $m.get(9) === null, $m.contains(1), $m.length() == 2, $m.type() == \"map\"",
      facts,
    ),
  )
  assert_true(
    expression_query_matches(
      "payload($b), $b.length() == 3, $b.type() == \"bytes\"", facts,
    ),
  )
}

///|
test "Datalog expressions implement closures short circuit and try_or" {
  let facts = [
    @biscuit.parse_fact("items([1, 2, 3])"),
    @biscuit.parse_fact("config({\"mode\": \"read\", 1: true})"),
  ]
  assert_true(
    expression_query_matches(
      "items($a), $a.any($x -> $x == 2), $a.all($x -> $x > 0)", facts,
    ),
  )
  assert_true(
    expression_query_matches(
      "config($m), $m.any($entry -> $entry.get(0) == \"mode\" && $entry.get(1) == \"read\")",
      facts,
    ),
  )
  assert_true(expression_query_matches("true || (1 / 0 == 0)", []))
  assert_false(expression_query_matches("false && (1 / 0 == 0)", []))
  assert_true(expression_query_matches("(1 / 0).try_or(42) == 42", []))
  assert_false(expression_query_matches("1 == \"one\"", []))

  let strict_mismatch = try {
    @biscuit.evaluate_policy_set([], [], [
      @biscuit.Policy::{
        kind: @biscuit.Allow,
        queries: [@biscuit.parse_query_body("1 === \"one\"")],
      },
    ])
    false
  } catch {
    @biscuit.Expression(@biscuit.TypeMismatch(_)) => true
    _ => false
  }
  assert_true(strict_mismatch)

  let bad_regex = try {
    @biscuit.evaluate_policy_set([], [], [
      @biscuit.Policy::{
        kind: @biscuit.Allow,
        queries: [@biscuit.parse_query_body("\"text\".matches(\"[\")")],
      },
    ])
    false
  } catch {
    @biscuit.Expression(@biscuit.InvalidRegex(_)) => true
    _ => false
  }
  assert_true(bad_regex)
}

///|
test "Datalog date offsets denote the same UTC instant" {
  assert_true(
    expression_query_matches("clock($time), $time === 2025-01-01T00:00:00Z", [
      @biscuit.parse_fact("clock(2025-01-01T08:00:00+08:00)"),
    ]),
  )
}

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
test "parse deduplicated set values" {
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
test "parse maps with integer and string keys independent of order" {
  let first = @biscuit.parse_fact(
    "config({\"mode\": \"read\", 1: [true], \"nested\": {\"x\": 2}})",
  )
  let reordered = @biscuit.parse_fact(
    "config({\"nested\": {\"x\": 2}, \"mode\": \"read\", 1: [true]})",
  )
  assert_true(first == reordered)
  assert_eq(
    first.values[0],
    @biscuit.MapValue([
      (@biscuit.StringKey("mode"), @biscuit.Text("read")),
      (@biscuit.IntegerKey(1L), @biscuit.ArrayValue([@biscuit.Boolean(true)])),
      (
        @biscuit.StringKey("nested"),
        @biscuit.MapValue([(@biscuit.StringKey("x"), @biscuit.Number(2L))]),
      ),
    ]),
  )
  assert_eq(@biscuit.parse_fact("x({})").values[0], @biscuit.MapValue([]))
}

///|
test "reject invalid map keys, duplicate keys and nested sets" {
  for source in ["x({{1}})", "x({true: 1})", "x({\"dup\": 1, \"dup\": 2})"] {
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
test "comparison operators cover inclusive boundaries and type mismatches" {
  let facts = [@biscuit.parse_fact("score(5)")]
  for
    (source, expected) in [
      ("score($n), $n < 6", true),
      ("score($n), $n > 4", true),
      ("score($n), $n <= 5", true),
      ("score($n), $n >= 5", true),
      ("score($n), $n == 5", true),
      ("score($n), $n != 4", true),
      ("score($n), $n < 5", false),
      ("score($n), $n > 5", false),
      ("score($n), $n <= 4", false),
      ("score($n), $n >= 6", false),
      ("score($n), $n == 4", false),
      ("score($n), $n != 5", false),
    ] {
    let matched = try {
      @biscuit.evaluate_policy_set(facts, [], [
        @biscuit.Policy::{
          kind: @biscuit.Allow,
          queries: [@biscuit.parse_query_body(source)],
        },
      ])
      true
    } catch {
      @biscuit.NoMatchingPolicy => false
      _ => abort("unexpected comparison evaluation error")
    }
    assert_eq(matched, expected)
  }
  let type_error = try {
    @biscuit.evaluate_policy_set(facts, [], [
      @biscuit.Policy::{
        kind: @biscuit.Allow,
        queries: [@biscuit.parse_query_body("score($n), $n >= \"5\"")],
      },
    ])
    false
  } catch {
    @biscuit.Expression(@biscuit.TypeMismatch(_)) => true
    _ => false
  }
  assert_true(type_error)
}

///|
test "date ordering is supported while mixed type ordering fails closed" {
  let facts = [@biscuit.Fact::{ name: "clock", values: [@biscuit.Date(100)], }]
  let date_query = @biscuit.Query::{
    body: [
      @biscuit.Predicate::{ name: "clock", terms: [@biscuit.Variable("when")], },
    ],
    conditions: [
      @biscuit.Condition::{
        operations: [
          @biscuit.Value(@biscuit.Reference("when")),
          @biscuit.Value(@biscuit.Literal(@biscuit.Date(101))),
          @biscuit.Binary(@biscuit.LessThan),
        ],
      },
    ],
    scopes: [],
  }
  @biscuit.evaluate_policy_set(facts, [], [
    @biscuit.Policy::{ kind: @biscuit.Allow, queries: [date_query], },
  ])
  let mixed_query = @biscuit.Query::{
    body: date_query.body,
    conditions: [
      @biscuit.Condition::{
        operations: [
          @biscuit.Value(@biscuit.Reference("when")),
          @biscuit.Value(@biscuit.Literal(@biscuit.Number(101))),
          @biscuit.Binary(@biscuit.LessThan),
        ],
      },
    ],
    scopes: [],
  }
  let type_error = try {
    @biscuit.evaluate_policy_set(facts, [], [
      @biscuit.Policy::{ kind: @biscuit.Allow, queries: [mixed_query], },
    ])
    false
  } catch {
    @biscuit.Expression(@biscuit.TypeMismatch(_)) => true
    _ => false
  }
  assert_true(type_error)
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
test "all checks validate every matching binding and reject checks invert a match" {
  let facts = [
    @biscuit.parse_fact("right(\"file1\", \"read\")"),
    @biscuit.parse_fact("right(\"file2\", \"write\")"),
  ]
  let all_query = @biscuit.parse_query_body(
    "right($resource, $operation), $operation == \"read\"",
  )
  let all_passed = try {
    @biscuit.evaluate_policy_set(
      facts,
      [@biscuit.Check::{ mode: @biscuit.All, queries: [all_query], }],
      [],
    )
    true
  } catch {
    @biscuit.FailedCheck(0) => false
    _ => true
  }
  assert_false(all_passed)

  let reject_query = @biscuit.parse_query_body("right(\"file1\", \"read\")")
  let rejected_match = try {
    @biscuit.evaluate_policy_set(
      facts,
      [@biscuit.Check::{ mode: @biscuit.Reject, queries: [reject_query], }],
      [],
    )
    true
  } catch {
    @biscuit.FailedCheck(0) => false
    _ => true
  }
  assert_false(rejected_match)

  let rejected_nonmatch = try {
    @biscuit.evaluate_policy_set(
      facts,
      [
        @biscuit.Check::{
          mode: @biscuit.Reject,
          queries: [@biscuit.parse_query_body("right(\"file3\", \"read\")")],
        },
      ],
      [],
    )
    false
  } catch {
    @biscuit.NoMatchingPolicy => true
    _ => false
  }
  assert_true(rejected_nonmatch)
}

///|
test "reject if fails when any alternative query matches" {
  let facts = [@biscuit.parse_fact("present(\"yes\")")]
  let mixed_queries = [
    @biscuit.parse_query_body("present(\"yes\")"),
    @biscuit.parse_query_body("absent(\"no\")"),
  ]
  let rejected = try {
    @biscuit.evaluate_policy_set(
      facts,
      [@biscuit.Check::{ mode: @biscuit.Reject, queries: mixed_queries, }],
      [],
    )
    false
  } catch {
    @biscuit.FailedCheck(0) => true
    _ => false
  }
  assert_true(rejected)

  let all_unmatched = try {
    @biscuit.evaluate_policy_set(
      facts,
      [
        @biscuit.Check::{
          mode: @biscuit.Reject,
          queries: [
            @biscuit.parse_query_body("absent(\"one\")"),
            @biscuit.parse_query_body("absent(\"two\")"),
          ],
        },
      ],
      [],
    )
    false
  } catch {
    // Reaching policy evaluation proves the reject check passed.
    @biscuit.NoMatchingPolicy => true
    _ => false
  }
  assert_true(all_unmatched)
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

///|
test "registered external functions run in expressions policies and rules" {
  let externals = @biscuit.ExternalFunctions::{
    unary: Map([
      (
        "positive",
        fn(value) {
          match value {
            @biscuit.Number(number) => @biscuit.Boolean(number > 0L)
            _ => @biscuit.Boolean(false)
          }
        },
      ),
      (
        "even",
        fn(value) {
          match value {
            @biscuit.Number(number) => @biscuit.Boolean(number % 2L == 0L)
            _ => @biscuit.Boolean(false)
          }
        },
      ),
    ]),
    binary: Map([
      (
        "at_least",
        fn(left, right) {
          match (left, right) {
            (@biscuit.Number(a), @biscuit.Number(b)) => @biscuit.Boolean(a >= b)
            _ => @biscuit.Boolean(false)
          }
        },
      ),
    ]),
  }
  let facts = [@biscuit.parse_fact("score(8)")]
  let positive = @biscuit.Policy::{
    kind: @biscuit.Allow,
    queries: [@biscuit.parse_query_body("score($n), $n.extern::positive()")],
  }
  @biscuit.evaluate_policy_set_with_externals(facts, [], [positive], externals)

  let at_least_six = @biscuit.Policy::{
    kind: @biscuit.Allow,
    queries: [@biscuit.parse_query_body("score($n), $n.extern::at_least(6)")],
  }
  @biscuit.evaluate_policy_set_with_externals(
    facts,
    [],
    [at_least_six],
    externals,
  )

  let rule = @biscuit.parse_rule(
    "even_score($n) <- score($n), $n.extern::even()",
  )
  let derived = @biscuit.derive_facts_with_externals(
    facts,
    [rule],
    100,
    10,
    externals,
  )
  assert_eq(
    @biscuit.match_query(@biscuit.parse_query("even_score(8)"), derived).length(),
    1,
  )

  let missing = try {
    @biscuit.evaluate_policy_set(facts, [], [positive])
    false
  } catch {
    @biscuit.Expression(@biscuit.MissingExternal("positive")) => true
    _ => false
  }
  assert_true(missing)
}

///|
test "Datalog expressions print and parse with operator identity preserved" {
  let expressions = [
    "1 + 2 * 3", "7 - 2 / 2", "(1 + 2) * 3", "!true || false", "true &&! false",
    "false ||! true", "1 < 2 && 2 <= 3", "3 > 2 || 2 >= 2", "1 === 1", "1 !== 2",
    "1 == \"1\"", "1 != \"1\"", "\"abc\".contains(\"b\")", "\"abc\".starts_with(\"a\")",
    "\"abc\".ends_with(\"c\")", "\"abc\".matches(\"^a.*c$\")", "{1, 2}.intersection({2, 3})",
    "{1, 2}.union({2, 3})", "9 & 3 | 2 ^ 1", "[1, 2].get(0)", "[1, 2].any($n -> $n > 1)",
    "[1, 2].all($n -> $n > 0)", "[1].length() == 1", "true.type() == \"bool\"", "null.try_or(\"fallback\") == \"fallback\"",
    "1.extern::identity() == 1", "1.extern::add(2) == 3",
  ]
  for source in expressions {
    let parsed = @biscuit.parse_expression(source)
    let printed = @biscuit.print_expression(parsed)
    let reparsed = @biscuit.parse_expression(printed)
    assert_true(reparsed == parsed)
  }
}

///|
test "Datalog values dates and scoped rules round trip through text" {
  let fact = @biscuit.parse_fact(
    "settings({\"line\\nbreak\": [true, null, hex:deadbeef], 7: {,}})",
  )
  assert_true(@biscuit.parse_fact(@biscuit.print_fact(fact)) == fact)
  let redundant_set = @biscuit.Fact::{
    name: "tags",
    values: [@biscuit.SetValue([@biscuit.Number(1L), @biscuit.Number(1L)])],
  }
  let canonical_set = @biscuit.Fact::{
    name: "tags",
    values: [@biscuit.SetValue([@biscuit.Number(1L)])],
  }
  assert_true(
    @biscuit.parse_fact(@biscuit.print_fact(redundant_set)) == canonical_set,
  )
  assert_eq(@biscuit.print_value(@biscuit.Date(-1L)), "1969-12-31T23:59:59Z")
  let parsed_date = @biscuit.parse_fact("time(2026-11-15T12:34:56+08:00)")
  let date_seconds = match parsed_date.values[0] {
    @biscuit.Date(seconds) => seconds
    _ => abort("expected date fact")
  }
  assert_eq(
    @biscuit.print_value(@biscuit.Date(date_seconds)),
    "2026-11-15T04:34:56Z",
  )

  let rule = @biscuit.parse_rule(
    "eligible($user) <- member($user), active($user), $user != \"blocked\" trusting authority, previous",
  )
  assert_true(@biscuit.parse_rule(@biscuit.print_rule(rule)) == rule)
}

///|
test "Datalog check and policy directives preserve alternatives and scopes" {
  let check = @biscuit.parse_check(
    "check all role(\"a or b\") trusting authority or role(\"admin\") trusting previous;",
  )
  assert_true(@biscuit.parse_check(@biscuit.print_check(check)) == check)
  let reject = @biscuit.parse_check("reject if banned($user), $user == 3")
  assert_true(@biscuit.parse_check(@biscuit.print_check(reject)) == reject)

  let policy = @biscuit.parse_policy(
    "allow if role(\"a or b\") trusting authority or role(\"admin\") trusting previous;",
  )
  assert_true(@biscuit.parse_policy(@biscuit.print_policy(policy)) == policy)
  let deny = @biscuit.parse_policy("deny if banned($user)")
  assert_true(@biscuit.parse_policy(@biscuit.print_policy(deny)) == deny)
}
