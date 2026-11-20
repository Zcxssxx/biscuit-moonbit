# 一致性与互操作记录

当前结果见文末 2026-11-20 P-256 实现验收；此前章节为历史运行记录，Ed25519-only 与 unsupported 统计不再代表当前范围。本文只记录实际命令与 CI 结果。

## 固定基线

- 规范、`schema.proto` 与 `samples/current`：`eclipse-biscuit/biscuit`，commit `b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639`。
- 对照实现：`eclipse-biscuit/biscuit-rust`，commit `2273077e2fcabeb8c03474125b4d96d57df6b4f7`（`biscuit-auth 7.0.0-alpha.3`）。
- MoonBit：`moon 0.1.20261023`、`moonc v0.10.17+d971670cd`。
- 兼容范围：当前 protobuf v3、Datalog 3.0–3.3、Ed25519。P-256/secp256r1 按兼容声明排除。

## 官方样例

实际运行命令：

```text
moon test -f 'official*'
```

实测输出：`Total tests: 51, passed: 51, failed: 0.`

统计口径：规范目录包含 38 个样例 ID；MoonBit 测试覆盖其中 50 个授权结果场景，另有一项独立测试验证官方 test024 的第三方块签名。共 51 项断言。test036 和 test037 使用 P-256/secp256r1，在本项目明确的 Ed25519 配置外，测试按预期返回 `unsupported_token`，不计入支持范围通过数。因此支持范围内为 49 项（48 个授权场景和 1 项第三方签名验证），范围外为 2 项，断言失败数为 0。

| 样例 | 授权场景结果（按测试顺序） | 说明 |
| --- | --- | --- |
| test001 | denied | 默认授权策略拒绝 |
| test002 | bad_signature | 根公钥不匹配 |
| test003 | invalid_token | 签名格式无效 |
| test004 | bad_signature | 随机区块签名无效 |
| test005 | bad_signature | 签名被篡改 |
| test006 | bad_signature | 区块顺序被更改 |
| test007 | denied | 规则来源作用域 |
| test008 | denied | 检查来源作用域 |
| test009 | denied | 过期令牌 |
| test010 | denied | Authorizer 作用域 |
| test011 | denied | authority caveat |
| test012 | ok；denied | 两个不同资源查询 |
| test013 | ok；denied | 衰减区块规则 |
| test014 | denied；ok | 正则约束，两个资源输入 |
| test015 | ok | 多个查询分支 |
| test016 | denied | caveat 头部名称 |
| test017 | ok | 表达式运算 |
| test018 | invalid_token | 规则中未绑定变量 |
| test019 | denied | 从变量生成 ambient 值 |
| test020 | ok | 已封存令牌 |
| test021 | ok | 令牌解析 |
| test022 | ok | 默认符号表 |
| test023 | denied | 执行作用域 |
| test024 | ok | 官方第三方块授权；另有签名验证测试 |
| test025 | ok；denied；denied | `check all` 的成功、非法项和无匹配项 |
| test026 | ok | 公钥 intern |
| test027 | overflow | 整数溢出错误 |
| test028 | ok | v4 表达式 |
| test029 | ok；denied | `reject if` 未触发与触发 |
| test030 | ok；denied；denied；denied | null 值和三种拒绝条件 |
| test031 | ok；denied | 异构相等和 false 求值 |
| test032 | ok；shadowed_variable | 闭包惰性和变量遮蔽错误 |
| test033 | ok | `typeof` |
| test034 | ok | 数组和映射 |
| test035 | ok | FFI |
| test036 | unsupported_token | P-256，明确超出 Ed25519 范围 |
| test037 | unsupported_token | 第三方 P-256，明确超出 Ed25519 范围 |
| test038 | ok；expression_error | `try_or` 成功与右侧错误 |

附加断言 `official sample 024 third-party block signatures verify` 对官方第三方块签名执行验证，结果通过。样例及期望状态对应仓库内 `official_samples*_test.mbt` 与 `interop_test.mbt`；公开令牌 fixture 来源与许可证见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

## Rust 双向互操作

实际执行由 GitHub Actions 固定 Rust revision 运行：

- 提交：`3ec8c723c8ef154b2a5ad8ab8a9b8d922991c0db`
- Workflow：[`CI run 43793900704`](https://github.com/Zcxssxx/biscuit-moonbit/actions/runs/43793900704)
- 状态：成功。MoonBit 格式检查、`moon check`、构建、115 项测试、验证示例、Rust `cargo fmt --check`、Rust `cargo test` 和 `python tools/interop.py` 均完成。
- 互操作脚本的 12 组授权结果对照和一项 Datalog 文本解析检查均由成功的 `python tools/interop.py` 步骤覆盖。

| 方向与能力 | 对照结果 |
| --- | --- |
| MoonBit 签发/衰减令牌 → Rust 验证和授权 | 允许结果一致；MoonBit 策略拒绝用例两边均拒绝 |
| Rust authority 令牌 → MoonBit 验证和授权 | 允许结果一致 |
| Rust 衰减令牌 → MoonBit 验证和授权 | 允许结果一致 |
| Rust sealed 令牌 → MoonBit 验证和授权 | 允许结果一致 |
| MoonBit sealed 令牌 → Rust 验证和授权 | 允许结果一致 |
| Rust 令牌 → MoonBit 再衰减 → 两边授权 | 允许结果一致 |
| MoonBit 第三方块请求和签名 → Rust 追加、验证和授权 | 基础令牌拒绝，追加后允许；结果一致 |
| Rust 第三方签名块 → MoonBit 验证和授权 | 基础令牌拒绝，追加后允许；结果一致 |
| Rust 追加 MoonBit 签名的第三方块 | 追加后的令牌验证和授权结果一致 |
| MoonBit 打印的 Datalog block、check 和 policy 文本 → Rust | Rust 分别用 `BlockBuilder` 和 `AuthorizerBuilder` 解析成功 |

本套件是基于固定 Rust revision 的确定性用例，不是随机 differential testing，也不覆盖任意策略组合或双方所有错误定位索引。

## 本机其他验证

以下命令在 2026-11-16 的当前实现工作树实际运行并通过：

| 命令 | 结果 |
| --- | --- |
| `moon fmt --check` | 退出码 0 |
| `moon check` | 退出码 0 |
| `moon test` | 115 项通过，0 项失败 |
| `moon test -f 'official*'` | 51 项通过，0 项失败 |
| `moon build` | 成功，示例构建完成 |
| `python -m py_compile tools/interop.py` | 退出码 0 |

本机没有 Rust `cargo`，所以 Rust helper 的格式、测试与互通结果只引用上述 Actions 运行，不记作本地通过。

## 2026-11-19 业务案例与符号表回归

本轮修复第三方块符号表应独立、后续普通块应忽略第三方符号的行为，规范依据为固定 SHA 的 SPECIFICATIONS.md 的 “third party blocks (with an external signature)” 节。新增一项白盒回归测试，验证同名业务值与后续常规块索引隔离。

本机工具链已变为 `moon 0.1.20261104` / `moonc v0.10.20+65efd5b93`；CI 仍按 `.moonbit-toolchain` 固定原版本。本机新工具链报告旧 derive 语法弃用警告，未改动库的公开接口。执行 `moon info` 和 `moon fmt` 后，保留与旧 CI 兼容的既有 derive 语法。

本地实际命令与结果：

- `moon test -f '*symbols are isolated*'`：1 项通过。
- `moon test`：116 项通过、0 项失败。
- `moon test -f 'official*'`：51 项通过、0 项失败，统计边界同上。
- `moon build`：成功，含新 maintenance 示例。
- `moon run examples/maintenance`：10/10 场景符合预期（一个允许、九个拒绝）。

业务案例是模拟集成原型。具体接入职责、工单流程、方案取舍和结果表见 [maintenance-case.md](maintenance-case.md)。代码提交 `fe10e680854301cf6a18bf16e5a75a483e317937` 的 [CI run 44439951220](https://github.com/Zcxssxx/biscuit-moonbit/actions/runs/44439951220) 已成功：固定工具链格式检查、检查/构建/116 项测试、新业务案例、Rust helper 及原有双向互通全部通过。

## 2026-11-19 第二轮优化验证

代码提交 `e3296a0` 的 [CI run 44444274522](https://github.com/Zcxssxx/biscuit-moonbit/actions/runs/44444274522) 成功。实际日志：

```text
Total tests: 118, passed: 118, failed: 0.
业务验收：10/10 场景符合预期
Seeded decision differential: 32/32 passed (seed 20261119)
All bidirectional Biscuit interoperability checks passed.
```

原有 12 组双向授权对照及 Datalog parser 检查继续通过。新增差分使用固定 Rust 令牌和 32 组小型随机事实/规则/策略，独立 Python 预期值同时约束两侧结果：ALLOW:index、DENY:index、NO_MATCH、CHECK_FAILED。失败检查暂按类别归一化，不比较具体检查索引；不是任意表达式的模糊测试。JSON 输入与结果在 Actions artifact `interop-decisions` 中保存 14 天。

本机实际运行 `moon check`、`moon test`（118/118）、`moon test -f 'official*'`（51/51）、`moon build`，以及 maintenance（10/10）、authorize、inspect 示例均成功。decision 适配器的 allow/deny/no-match/failed-check 四类本地烟雾检查通过；完整跨实现结果来自 CI。本机仍无 Cargo。Python 脚本 AST 解析检查通过，互通子进程明确以 UTF-8 处理输出。

CI 使用固定 MoonBit 工具链通过 `moon fmt --check`；本机较新工具链保留弃用语法兼容说明。新增输入加固和来源索引的两个回归测试通过，公开 MoonBit API 未变动。

首次 CI run 44444072510 在新增 Rust helper 的格式检查处失败；按其具体诊断修正后完成上述成功运行。没有将失败运行记作通过。

## 2026-11-20 完整算法目标与参照矩阵

最终兼容目标现已包含 P-256 和混合算法，不再把 Ed25519 配置作为最终范围。实现拆分、逐块密钥流程、后端资格验证和最终门槛见 [full-compatibility-plan.md](full-compatibility-plan.md)。

提交 `38a7541` 的 [CI run 44705898333](https://github.com/Zcxssxx/biscuit-moonbit/actions/runs/44705898333) 成功，实际执行固定工具链的格式、检查、构建、118 项测试、业务案例、原互通/32 组差分，以及新增命令：

```text
cargo run --quiet --manifest-path tools/biscuit-rust-interop/Cargo.toml -- algorithm-matrix
```

新增步骤成功退出，覆盖 root E/P × authority.nextKey E/P × external E/P 共 8 个组合，其中 000/111 分别保持纯 E/P，其他组合切换后续 key 算法；每组检查缺失审批拒绝、审批后 read 允许、write 拒绝，以及重新解码验证和 seal 验证。公开测试令牌与结论保存在 Actions artifact 的 `algorithm-reference.txt` 中，保留 14 天。

这是 **biscuit-rust 自身的算法参照矩阵**，不是 MoonBit P-256 测试。MoonBit 当前仍拒绝 test036/test037，对应两项不支持断言没有变成标准兼容通过；最终验收必须让其真实授权结果与官方一致，并完成 MoonBit↔Rust 的 P-256/混合链双向测试。本机没有 Cargo，未声称本地运行该 Rust 矩阵。

首个 run 44705746005 因新增 helper 的 Rust 格式检查失败；修正后上述 run 成功。未以配置存在或失败运行代替通过证据。

## 2026-11-20 P-256 / 混合算法实现验收（当前）

MoonBit 实现已支持 Ed25519、P-256、混合链、两算法第三方块、typed key、DER/SEC1、proof 与封存。API 和测试流程见 [algorithm-api.md](algorithm-api.md)。

本地实际执行：`moon check`、`moon info`、`moon fmt`、`moon build` 成功；`moon test` 120/120；`moon test -f 'official*'` 52/52。52 项包括 38 个官方 ID 的 50 个授权场景和 test024/test036 两项签名验证；test036/test037 现在按授权成功断言，不再有范围外 P-256 项。

实现提交 `14f7b9e` 的 [CI run 44708002028](https://github.com/Zcxssxx/biscuit-moonbit/actions/runs/44708002028) 全流程通过，实际日志包括：

```text
Total tests: 119, passed: 119, failed: 0.
Seeded decision differential: 32/32 passed (seed 20261119)
MoonBit / Rust algorithm matrix 000: PASS
MoonBit / Rust algorithm matrix 001: PASS
MoonBit / Rust algorithm matrix 010: PASS
MoonBit / Rust algorithm matrix 011: PASS
MoonBit / Rust algorithm matrix 100: PASS
MoonBit / Rust algorithm matrix 101: PASS
MoonBit / Rust algorithm matrix 110: PASS
MoonBit / Rust algorithm matrix 111: PASS
Bidirectional algorithm matrix: 8/8 passed
```

119 是该提交的实测数；之后新增的一项 P-256 签名跨令牌绑定/算法混淆/作用域往返回归，使本地总数为 120，不混写两个版本的结果。该测试与 contents 编解码往返将随后续提交在 CI 再验收。

每组算法矩阵验证：MoonBit 签发和封存→Rust 验证授权；Rust 追加 MoonBit token→MoonBit 继续追加→Rust 再验证；Rust 签发→MoonBit 衰减→Rust 验证；Rust sealed token→MoonBit 验证且拒绝追加。各 token 都携带外部签名块，read 允许、write 拒绝。000 为纯 E，111 为纯 P，其余跨算法切换；对应 JSON artifact 为 `algorithm-interop.json`。

密码后端单测覆盖签名/DER 往返、消息篡改、非法 DER、零标量和非法曲线点。另有 P-256 外部签名跨令牌重放拒绝、错算法根公钥拒绝、scope 文本往返。仍非完整密码审计或任意输入穷举；P-256 签名算法为 SHA-256/RFC6979，不能据此宣称常量时间。本机没有 Cargo，双向互通结论来自上述 CI，不记作本地 Rust 通过。

后续提交 `9d79030` 的 [CI run 44708900216](https://github.com/Zcxssxx/biscuit-moonbit/actions/runs/44708900216) 再次全流程通过，实测 120 项测试，包含跨令牌签名绑定负向测试、第三方 contents 编解码以及 8/8 双向算法矩阵。

最后补充跨算法 secret 复用拒绝：即使 root/next 或 current/next 采用不同算法，相同 secret 字节也不可作为新 proof 复用，以避免转交 proof 时暴露上游签名 secret。新增回归测试本地通过；完整本地总数为 121/121，官方筛选维持 52/52。签发 API 只检查可直接比较的 secret；宿主仍必须为每次签发/追加提供独立新鲜密钥。
