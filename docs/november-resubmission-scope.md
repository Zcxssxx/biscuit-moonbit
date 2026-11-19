# 11 月复审补充说明

更新日期：2026-11-16
用途：按初审意见逐项说明当前实现、实际验证和未覆盖边界。此文提供可复核证据，不承诺组委会一定通过。

## 项目定位

**Biscuit 当前 protobuf v3、Datalog 3.0–3.3、Ed25519 配置的 MoonBit 实现。**兼容声明以固定规范 commit `b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639` 为基准，不将范围外算法或旧外层令牌格式标作支持。

## 对初审意见的补充

| 初审指出的缺口 | 当前实现与验证 |
| --- | --- |
| 完整 Datalog 表达式 | 支持 3.0–3.3 的值、运算、短路、集合/数组/映射、闭包、`try_or`、溢出与类型错误；对应单元测试及 official test017、027–038。 |
| 显式 Scopes | 支持 `authority`、`previous`、Ed25519 trusting 公钥，以及 block、rule、query/check 级来源作用域；覆盖 official test007、008、010、011、023。 |
| 衰减块 facts/rules | 结构化衰减 API 接受 facts、rules、checks 和 block scope；派生事实保留来源并按 scope 过滤；覆盖 official test012–015、019、023、025。 |
| 第三方签名 | Ed25519 请求、contents 签署、验证、追加和 trusting 公钥授权；官方 test024 与固定 Rust revision 的双向互操作通过。 |
| Authorizer | 支持 token 与 ambient facts/rules/checks、check if/check all/reject if、allow/deny、首个匹配策略、结构化授权结果、失败检查与求值错误。 |
| 序列化和 sealed token | 当前 protobuf v3、Base64URL、Ed25519 proof 与 sealed/unsealed 验证；`seal_token` 可封存已验证令牌，封存后不可继续追加。 |
| 文本解析与打印 | 提供 fact/predicate/value/expression/rule/check/policy 的解析与打印 API，AST round-trip 测试通过；Rust CI 对照接受打印的 block、check 和 policy。 |
| 一致性与双向互通 | 官方 38 个样例 ID 的 50 个授权场景及一项第三方签名断言全部按期望通过；固定 Rust 实现 CI 中 12 组授权结果对照和 Datalog parser 检查通过。 |

样例逐项结果、命令、固定 SHA 和 Actions run 见 [docs/conformance.md](conformance.md)。版本和能力边界见 [docs/compatibility.md](compatibility.md)，逐项审计表见 [docs/gap-analysis.md](gap-analysis.md)。

## 已知限制

- 仅支持 Ed25519；官方 test036/test037 的 P-256/secp256r1 场景返回 `unsupported_token`，明确不计入支持范围。
- 仅支持当前 protobuf v3 外层格式；旧外层 token v0/v1/v2 不在范围。未知 protobuf 字段按严格策略拒绝。
- 资源控制使用 facts、迭代、表达式步数和查询绑定的确定性上限；没有 wall-clock timeout API。
- issue/attenuate/third-party/seal API 要求调用方提供安全生成的独立 seed；本库不内置 CSPRNG。
- `hustcer/ed25519` 上游注明其实现未审计且不是 constant-time；本项目没有独立密码审计。
- 跨实现用例固定在一个 Rust revision，新增 32 组 seeded differential testing，比较匹配 policy 索引；尚未系统性比较所有失败 check 索引和任意策略组合。
- 解析错误提供类别与消息，尚无源码行列定位。

## 复审材料建议表述

申报时可说明：项目已实现 Biscuit 当前格式下 Ed25519 配置的 Datalog 3.0–3.3 核心授权语义，并提交官方样例逐项结果及固定 Rust revision 的双向互操作证据。应同时声明 P-256、旧外层格式和随机差分测试的限制；最终兼容范围以该仓库文档及可复现 CI 记录为准。
