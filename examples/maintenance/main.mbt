// All seeds and request context below are public, deterministic demo fixtures.

///|
fn expect_request(
  token : @biscuit.PreparedToken,
  label : String,
  site : String,
  job : String,
  path : String,
  operation : String,
  time : String,
  expected : Bool,
) -> Unit raise {
  // A real gateway supplies these values from its authenticated request and clock.
  let facts = [
    @biscuit.parse_fact("site(\"" + site + "\")"),
    @biscuit.parse_fact("job(\"" + job + "\")"),
    @biscuit.parse_fact("resource(\"" + path + "\")"),
    @biscuit.parse_fact("operation(\"" + operation + "\")"),
    @biscuit.parse_fact("time(" + time + ")"),
  ]
  let policy = @biscuit.parse_policy(
    "allow if site($s), operation($op), right($s, $op) trusting authority",
  )
  let allowed = try {
    let decision = token.authorize(facts, [], [], [policy], 1000, 100, @biscuit.ExternalFunctions::{
      unary: Map([]),
      binary: Map([]),
    })
    decision.decision is @biscuit.Allow
  } catch {
    @biscuit.FailedCheck(_) | @biscuit.NoMatchingPolicy | @biscuit.Denied(_) =>
      false
    @biscuit.InvalidToken(message)
    | @biscuit.UnsupportedTokenFeature(message) => abort(message)
    @biscuit.Expression(_) => abort("表达式求值错误：" + label)
    _ => abort("业务案例发生非预期协议或求值错误：" + label)
  }
  assert_eq(allowed, expected)
  println(label + "：" + (if allowed { "允许" } else { "拒绝" }))
}

///|
fn main {
  try {
    let root_seed = Bytes::make(32, b'\x61')
    let approval_seed = Bytes::make(32, b'\x62')
    let root = @ed25519.derive_public_key(root_seed)
    let approval_key = @ed25519.derive_public_key(approval_seed)
    let base = @biscuit.issue(
      [@biscuit.parse_fact("right(\"plant-a\", \"read\")")],
      [],
      [
        @biscuit.parse_check(
          "check if site($s), job($j), approval($s, $j) trusting ed25519/" +
          @hex.encode(approval_key),
        ),
      ],
      6,
      root_seed,
      Bytes::make(32, b'\x63'),
    )
    // Contractor delegates a narrowed capability to the work-order tool.
    let delegated = @biscuit.attenuate(
      base,
      root,
      [
        @biscuit.parse_check("check if job(\"WO-2026-041\")"),
        @biscuit.parse_check(
          "check if resource($p), $p.starts_with(\"/plant-a/pump-7/logs/\")",
        ),
        @biscuit.parse_check("check if time($t), $t < 2026-11-20T12:00:00Z"),
      ],
      6,
      Bytes::make(32, b'\x64'),
    )
    let request = @biscuit.create_third_party_request(delegated, root)
    let approval_data = @biscuit.encode_block(
      [@biscuit.parse_fact("approval(\"plant-a\", \"WO-2026-041\")")],
      [],
      [],
      6,
    )
    let contents = @biscuit.build_third_party_block(
      request, approval_data, approval_seed,
    )
    let ready = @biscuit.append_serialized_third_party_block(
      delegated,
      root,
      @biscuit.serialize_third_party_block(contents),
      Bytes::make(32, b'\x65'),
    )
    let ready_for_requests = @biscuit.prepare_token(ready, root)
    let path = "/plant-a/pump-7/logs/error.log"
    let now = "2026-11-20T10:00:00Z"
    expect_request(
      @biscuit.prepare_token(delegated, root),
      "未取得工厂审批",
      "plant-a",
      "WO-2026-041",
      path,
      "read",
      now,
      false,
    )
    expect_request(
      ready_for_requests, "审批后读取指定设备日志", "plant-a", "WO-2026-041",
      path, "read", now, true,
    )
    expect_request(
      ready_for_requests, "尝试写入日志", "plant-a", "WO-2026-041", path, "write",
      now, false,
    )
    expect_request(
      ready_for_requests, "尝试读取其他设备", "plant-a", "WO-2026-041", "/plant-a/pump-8/logs/error.log",
      "read", now, false,
    )
    expect_request(
      ready_for_requests, "尝试跨工厂读取", "plant-b", "WO-2026-041", path,
      "read", now, false,
    )
    expect_request(
      ready_for_requests, "尝试换用其他工单", "plant-a", "WO-2026-042", path,
      "read", now, false,
    )
    expect_request(
      ready_for_requests, "到期边界拒绝", "plant-a", "WO-2026-041", path, "read",
      "2026-11-20T12:00:00Z", false,
    )
    // A holder's own fact must not impersonate the trusted approval signer.
    let forged = @biscuit.attenuate_block(
      delegated,
      root,
      [@biscuit.parse_fact("approval(\"plant-a\", \"WO-2026-041\")")],
      [],
      [],
      [],
      6,
      Bytes::make(32, b'\x66'),
    )
    expect_request(
      @biscuit.prepare_token(forged, root),
      "持有者自填审批事实",
      "plant-a",
      "WO-2026-041",
      path,
      "read",
      now,
      false,
    )
    let impostor = @biscuit.build_third_party_block(
      request,
      approval_data,
      Bytes::make(32, b'\x67'),
    )
    let wrong_signer = @biscuit.append_serialized_third_party_block(
      delegated,
      root,
      @biscuit.serialize_third_party_block(impostor),
      Bytes::make(32, b'\x68'),
    )
    expect_request(
      @biscuit.prepare_token(wrong_signer, root),
      "非受信方签署审批",
      "plant-a",
      "WO-2026-041",
      path,
      "read",
      now,
      false,
    )
    // Later rights facts cannot override authority trust or earlier checks.
    let escalated = @biscuit.attenuate_block(
      ready,
      root,
      [@biscuit.parse_fact("right(\"plant-a\", \"write\")")],
      [],
      [],
      [],
      6,
      Bytes::make(32, b'\x69'),
    )
    expect_request(
      @biscuit.prepare_token(escalated, root),
      "追加写权限事实尝试越权",
      "plant-a",
      "WO-2026-041",
      path,
      "write",
      now,
      false,
    )
    println("业务验收：10/10 场景符合预期")
  } catch {
    _ => abort("运维委托案例验收失败")
  }
}
