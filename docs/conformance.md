# 一致性与互操作记录

最后核对：2026-11-16。本文只记录已实际执行的本地命令和 GitHub Actions 结果。

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
