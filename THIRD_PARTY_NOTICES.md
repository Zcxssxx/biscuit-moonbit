# 第三方来源与许可证说明

本项目自身使用 Apache-2.0，完整条款见 [LICENSE](LICENSE)。下表记录协议来源、测试向量和第三方依赖；更新依赖或基准版本时应重新核验许可证与安全状态。

## 规范、样例与测试向量

| 来源 | 固定版本 | 用途 | 许可证/说明 |
| --- | --- | --- | --- |
| Biscuit 规范 | `b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639` | `SPECIFICATIONS.md`、`schema.proto` 用于协议实现；`samples/current` 的令牌、授权策略和预期结果改编为根包的 `official_samples*_test.mbt` 及 [互通测试](interop_test.mbt) | [Apache-2.0](https://github.com/eclipse-biscuit/biscuit/blob/b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639/LICENSE) |
| Biscuit Rust 样例 | `21e650f31a8521af575f968925acbb56486172f9` | 公开测试令牌和公钥，来源标注见 [互通测试](interop_test.mbt) | [biscuit-auth 的 Apache-2.0](https://github.com/eclipse-biscuit/biscuit-rust/blob/21e650f31a8521af575f968925acbb56486172f9/biscuit-auth/LICENSE) |
| Biscuit Rust 对照 | `2273077e2fcabeb8c03474125b4d96d57df6b4f7` | [CI 对照工具的外部依赖](tools/biscuit-rust-interop/Cargo.toml) | [biscuit-auth 的 Apache-2.0](https://github.com/eclipse-biscuit/biscuit-rust/blob/2273077e2fcabeb8c03474125b4d96d57df6b4f7/biscuit-auth/LICENSE) |

令牌编码、签名链逻辑和 Datalog 求值的 MoonBit 实现位于根包。规范与 Rust 对照用于协议参考和交叉验证。各包的 `pkg.generated.mbti` 由 `moon info` 从本仓库源码生成，保留在版本控制中用于审阅公开接口变更。

## MoonBit 运行时依赖

| 依赖 | 版本 | 关系 | 许可证 | 安全说明 |
| --- | --- | --- | --- | --- |
| [hustcer/ed25519](https://github.com/hustcer/mbt-ed25519) | 0.6.1 | 直接依赖 | Apache-2.0 | 上游说明实现未审计且不是 constant-time；本项目未做密码学审计 |
| [moonbitlang/x](https://github.com/moonbitlang/x) | 0.5.5 | 经 `hustcer/ed25519` 引入 | Apache-2.0 | 版本见 MoonBit 依赖元数据 |
| [moonbitlang/core](https://github.com/moonbitlang/core) | 工具链自带 | 标准库 | Apache-2.0 | 用于集合、字符串、编码与测试 |

## P-256 密码后端（2026-11-20 新增）

- [moonbitstack/mooncrypt](https://github.com/moonbitstack/mooncrypt) 0.3.1，Apache-2.0：直接依赖 `sign/ecdsa`，提供 P256/SHA-256、RFC6979、SEC1 点处理；本项目实现协议 DER 适配及算法分派。未由本项目独立审计，不宣称常量时间。
- 模块声明的传递依赖 [moonbitstack/moonbase](https://github.com/moonbitstack/moonbase) 0.4.0 与 [moonbitstack/moondate](https://github.com/moonbitstack/moondate) 0.1.0，均按安装包 moon.mod / LICENSE 确认为 Apache-2.0。
- 新增适配代码独立按规范编写，没有复制密码后端曲线算法源码；后端通过 Mooncakes 固定版本导入。

## Rust 测试辅助工具依赖

仅 CI 互操作 helper 使用以下 Rust crate，不作为 MoonBit 库的运行时依赖：

| crate | 固定/声明版本 | 许可证 | 用途 |
| --- | --- | --- | --- |
| [biscuit-auth](https://github.com/eclipse-biscuit/biscuit-rust) | Git revision `2273077e2fcabeb8c03474125b4d96d57df6b4f7` | Apache-2.0 | 官方对照实现 |
| [base64](https://github.com/marshallpierce/rust-base64) | 0.22.1 | MIT OR Apache-2.0 | URL-safe 第三方 block contents 编码 |
| [hex](https://github.com/KokaKiwi/rust-hex) | 0.4.3 | MIT OR Apache-2.0 | 测试密钥十六进制转换 |

`Cargo.toml` 固定了 helper 的直接 crate 版本和 Biscuit Git revision，但仓库不含 `Cargo.lock`；Rust 间接依赖的最终解析版本可能随时间变化。CI 每次解析时运行 `cargo test`，这不等价于完整锁定传递依赖。

## 安全与再分发边界

- 仓库中的 seed、public key、令牌和签名数据均为上游公开 fixture 或测试示例，不得作为生产密钥使用。
- MoonBit 签发与追加 API 由调用方提供新鲜随机种子；应用必须通过操作系统安全熵源生成，不得复用示例值。
- 上述许可证信息按当前固定来源和依赖元数据整理。升级版本、复制新的样例或增加依赖时，需更新本文件并复核各自 LICENSE/NOTICE。
