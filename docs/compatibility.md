# 兼容性范围

更新：2026-11-20。以下为当前实现状态；此前 Ed25519 里程碑记录保留在 conformance.md 的历史章节。

## 基准与最终目标

规范、schema.proto、samples/current 固定为 `eclipse-biscuit/biscuit@b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639`；Rust 对照固定为 `eclipse-biscuit/biscuit-rust@2273077e2fcabeb8c03474125b4d96d57df6b4f7`（7.0.0-alpha.3）。最终目标为该修订的完整当前标准兼容，已实现的 P-256 与混合链证据见 [conformance.md](conformance.md)。不将单次测试集合通过视为所有输入的兼容证明。

## 当前支持矩阵

| 层次 | 已实现 | 证据与边界 |
| --- | --- | --- |
| 外层格式 | 当前 protobuf v3，已知 schema 字段 | 未知字段严格拒绝；旧外层 v0/v1/v2 不支持 |
| Datalog 3.0–3.3 | block version 3–6，值、表达式、规则、checks、scopes、Authorizer | 38 个官方 ID 的 50 个授权场景全部按期望通过 |
| Ed25519 | v0/v1 payload 验证、v1 签发/追加、第三方块、sealed/unsealed proof | 保留原有字节 API；签名 64 bytes |
| P-256/secp256r1 | SHA-256、压缩 SEC1 公钥、DER 签名、大端私有标量；同样的令牌操作 | 固定 mooncrypt 0.3.1 后端；官方 test036/test037 通过 |
| 混合签名链 | root、各 nextKey、外部签名可分别选择 E/P；proof 使用最后 nextKey 的算法 | 8 组 MoonBit↔Rust 矩阵，纯 P、E→P、P→E、交替追加和封存验证 |
| 第三方块 | 两算法请求/签名/contents 解析与序列化、追加、来源隔离 | P-256 scope 文本往返；跨令牌复用签名拒绝；两算法签名标签不可互换 |
| 传输 | canonical Base64URL，支持正确 padding 与无 padding 输入 | 表示解码不等于签名验证或授权 |

签名 payload v0 是当前格式中的兼容项，不代表支持旧外层格式。新第三方签名使用 v1，不接受废弃的 external signature payload v0。

## API 与资源边界

新 API 使用 `SigningKey` / `VerificationKey` 显式携带算法；`issue_with_keys`、`attenuate_with_key`、`authorize_with_key` 等见 [algorithm-api.md](algorithm-api.md)。原有 Ed25519 API 的默认行为保留。

输入 token 最大 1 MiB、最多 128 个追加块；协议值嵌套深度 16，文本深度 32，集合/数组/映射最多 1024 项。facts/iterations 由调用方设限；每条表达式最多 10,000 步、查询最多 10,000 绑定，无 wall-clock timeout。日期文本打印限四位年份；错误提供类别和消息，尚无源码行列定位。

FFI handler、可信根选择、真实 ambient facts、安全随机数、密钥管理、身份绑定与即时撤销由宿主实现。Ed25519 seed 和 P-256 scalar 均须独立、安全生成；P-256 scalar 要在有效范围内，不能把任意口令直接作为密钥。

两套密码后端均未由本项目接受独立密码或侧信道审计。Rust 对照固定 Biscuit revision、Rust 1.100.0 和 [Cargo.lock](../tools/biscuit-rust-interop/Cargo.lock)。这些 Rust 依赖仅用于对照测试。

## 测试状态

本地 121 项测试通过；官方筛选 52 项通过（50 个授权场景 + test024/test036 两项签名验证），不再有“预期不支持 P-256”计数。已执行的 CI 和双向结果详见 [conformance.md](conformance.md)。固定 seed 的 32 组小型授权差分比较匹配策略索引及错误类别，不覆盖全部失败检查索引或任意表达式。
