///|
fn benchmark_scoped_index(
  bench : @bench.T,
  background_count : Int32,
  check_count : Int32,
) -> Unit raise {
  let root = @biscuit.SigningKey::{
    algorithm: @biscuit.Ed25519,
    secret: Bytes::make(32, b'\x71'),
  }
  let token = @biscuit.issue_with_keys(
    [@biscuit.parse_fact("right(\"logs\", \"read\")")],
    [],
    [],
    [],
    6,
    root,
    { algorithm: @biscuit.Ed25519, secret: Bytes::make(32, b'\x72'), },
  )
  let prepared = @biscuit.prepare_with_key(
    token,
    @biscuit.verification_key(root),
  )
  let facts = [@biscuit.parse_fact("request(\"logs\")")]
  for i in 0..<background_count {
    facts.push({ name: "reading", values: [@biscuit.Number(i.to_int64())], })
  }
  let rules = [
    @biscuit.parse_rule("permitted($r) <- request($r), right($r, \"read\")"),
    @biscuit.parse_rule("ready($r) <- permitted($r)"),
  ]
  let check = @biscuit.parse_check("check if permitted(\"logs\")")
  let checks = Array::make(check_count, check)
  let policies = [@biscuit.parse_policy("allow if ready(\"logs\")")]
  let externals = @biscuit.ExternalFunctions::{
    unary: Map([]),
    binary: Map([]),
  }
  let max_facts = background_count + 16
  assert_eq(
    prepared.authorize(facts, rules, checks, policies, max_facts, 10, externals).policy_index,
    0,
  )
  bench.bench(fn() {
    let result = prepared.authorize(
      facts, rules, checks, policies, max_facts, 10, externals,
    ) catch {
      _ => abort("scoped benchmark should authorize")
    }
    bench.keep(result)
  })
}

///|
test "scoped facts 0 background 1 check" (bench : @bench.T) {
  benchmark_scoped_index(bench, 0, 1)
}

///|
test "scoped facts 128 background 8 checks" (bench : @bench.T) {
  benchmark_scoped_index(bench, 128, 8)
}

///|
test "scoped facts 2048 background 1 check" (bench : @bench.T) {
  benchmark_scoped_index(bench, 2048, 1)
}

///|
test "scoped facts 2048 background 24 checks" (bench : @bench.T) {
  benchmark_scoped_index(bench, 2048, 24)
}
