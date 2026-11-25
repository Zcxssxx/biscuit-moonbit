///|
fn benchmark_fixture(
  algorithm : @biscuit.SignatureAlgorithm,
  count : Int32,
  mixed : Bool,
) -> (Bytes, @biscuit.VerificationKey) raise {
  let root = @biscuit.SigningKey::{
    algorithm,
    secret: Bytes::make(32, b'\x01'),
  }
  let trusted = @biscuit.verification_key(root)
  let mut token = @biscuit.issue_with_keys(
    [@biscuit.parse_fact("right(\"logs\", \"read\")")],
    [],
    [],
    [],
    6,
    root,
    { algorithm, secret: Bytes::make(32, b'\x02'), },
  )
  let check = @biscuit.parse_check("check if operation(\"read\")")
  for index = 1; index < count; index = index + 1 {
    let next_algorithm = if mixed && index % 2 == 1 {
      @biscuit.Secp256r1
    } else {
      algorithm
    }
    token = @biscuit.attenuate_with_key(
      token,
      trusted,
      [],
      [],
      [check],
      [],
      6,
      {
        algorithm: next_algorithm,
        secret: Bytes::make(32, (index + 2).to_byte()),
      },
    )
  }
  (token, trusted)
}

///|
fn benchmark_authorization(
  bench : @bench.T,
  algorithm : @biscuit.SignatureAlgorithm,
  count : Int32,
  mixed : Bool,
  reuse : Bool,
) -> Unit raise {
  let (token, trusted) = benchmark_fixture(algorithm, count, mixed)
  let prepared = @biscuit.prepare_with_key(token, trusted)
  let facts = [@biscuit.parse_fact("operation(\"read\")")]
  let policies = [@biscuit.parse_policy("allow if right(\"logs\", \"read\")")]
  let externals = @biscuit.ExternalFunctions::{
    unary: Map([]),
    binary: Map([]),
  }
  assert_eq(
    prepared.authorize(facts, [], [], policies, 100, 10, externals).policy_index,
    0,
  )
  if reuse {
    bench.bench(fn() {
      let decision = prepared.authorize(
        facts,
        [],
        [],
        policies,
        100,
        10,
        externals,
      ) catch {
        _ => abort("prepared benchmark should authorize")
      }
      bench.keep(decision)
    })
  } else {
    bench.bench(fn() {
      let decision = @biscuit.authorize_with_key(
        token,
        trusted,
        facts,
        [],
        [],
        policies,
        100,
        10,
        externals,
      ) catch {
        _ => abort("one-shot benchmark should authorize")
      }
      bench.keep(decision)
    })
  }
}

///|
test "Ed25519 1 block full" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Ed25519, 1, false, false)
}

///|
test "Ed25519 1 block prepared" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Ed25519, 1, false, true)
}

///|
test "Ed25519 4 blocks full" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Ed25519, 4, false, false)
}

///|
test "Ed25519 4 blocks prepared" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Ed25519, 4, false, true)
}

///|
test "Ed25519 16 blocks full" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Ed25519, 16, false, false)
}

///|
test "Ed25519 16 blocks prepared" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Ed25519, 16, false, true)
}

///|
test "P-256 1 block full" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Secp256r1, 1, false, false)
}

///|
test "P-256 1 block prepared" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Secp256r1, 1, false, true)
}

///|
test "P-256 4 blocks full" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Secp256r1, 4, false, false)
}

///|
test "P-256 4 blocks prepared" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Secp256r1, 4, false, true)
}

///|
test "mixed 4 blocks full" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Ed25519, 4, true, false)
}

///|
test "mixed 4 blocks prepared" (b : @bench.T) {
  benchmark_authorization(b, @biscuit.Ed25519, 4, true, true)
}
