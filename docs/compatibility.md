# 兼容性范围

审计基线：2026-11-15。本文记录当前已实现并测试的支持配置，不把未支持算法或未来目标写成已支持能力。

## 对标版本

- Biscuit 规范、schema.proto 与 samples/current：eclipse-biscuit/biscuit，修订 b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639。
- 跨实现基准：eclipse-biscuit/biscuit-rust，修订 2273077e2fcabeb8c03474125b4d96d57df6b4f7，biscuit-auth 7.0.0-alpha.3。
- 该修订的 official samples/current 清单有 38 个样例 ID。测试覆盖 50 个授权结果场景，并额外验证 test024 的官方第三方块签名，共 51 项。
- 本项目工具链：moon 0.1.20261023，moonc 0.10.17+d971670cd；CI 从 .moonbit-toolchain 安装相同编译器版本。

## 版本与算法矩阵

| 协议层 | 支持声明 | 实测/限制 |
| --- | --- | --- |
| 外层 token protobuf | 当前 Biscuit v3 格式 | 解析并验证已知字段；输入上限 1 MiB、最多 128 个追加块。未知字段与未知变体拒绝，不承诺前向兼容。 |
| Datalog 3.0 | block version 3 | 基础事实、规则、作用域、表达式和授权语义；纳入官方 current 样例。 |
| Datalog 3.1 | block version 4 | 版本门控表达式与检查语义；纳入官方 current 样例。 |
| Datalog 3.2 | block version 5 | 显式作用域、trusting 公钥和第三方 Ed25519 block；第三方 block 最低版本要求为 3.2。 |
| Datalog 3.3 | block version 6 | null、array、map、type、try_or 及相应表达式语义；纳入官方 current 样例。 |
| 区块签名 payload | Ed25519 v0/v1 | 验证两种 payload；本项目新签发与追加使用 v1。payload 版本不等于外层 token 版本。 |
| Proof | Ed25519 unsealed/sealed | 两种 proof 均验证；seal_token 将已验证 token 封存。sealed token 不能再追加衰减块。 |
| 第三方签名 | Ed25519 | 支持请求、contents、外部签名验证、追加、trusting 公钥与授权；不支持第三方 P-256。 |
| P-256/secp256r1 | 不支持 | 官方 test036、test037 返回 unsupported_token，按范围外单独记录，不计兼容通过。 |
| 旧外层 token v0/v1/v2 | 不支持 | 即使某区块签名 payload v0 可验证，也不代表支持旧外层令牌格式。 |

Datalog block version 的映射为 3→3.0、4→3.1、5→3.2、6→3.3。超出此范围的版本明确报错。

## 核心功能边界

- 值类型：整数、字符串、秒精度日期、字节、布尔、null、数组、集合、映射；映射键支持字符串和整数。协议解析最大嵌套深度 16；文本解析最大深度 32，集合/数组/映射各最多 1024 项。
- 表达式：比较、严格/宽松相等、整数算术与溢出、逻辑短路/急切布尔、位运算、字符串前后缀/包含/正则、集合交并、数组/映射访问、长度/类型、外部函数、any/all 闭包和 try_or。类型错误、除零、溢出、非法正则、未绑定变量、闭包遮蔽与步骤耗尽有结构化错误。
- 文本 API：fact、predicate、Datalog 值、表达式、规则、check if/check all/reject if、allow/deny policy 的解析与打印；已覆盖 parse-print-parse 结构往返。表达式打印器拒绝无法用当前文本语法表示的非法 AST。
- 作用域：authority、previous、Ed25519 公钥；支持 block、rule 与 query/check scope。默认及显式作用域用于决定事实来源可见性。
- 衰减块：可带事实、规则、检查和 block scope；派生事实携带来源，检查和策略依据可见来源集查询。
- Authorizer：执行 token 与调用方事实/规则/check，按顺序使用首个匹配 allow/deny policy；check 失败、拒绝策略、无匹配策略、无效令牌、表达式错误和资源耗尽均有结构化变体。authorize_token_detailed 返回匹配策略类别和索引。
- 执行限制：调用方设置最大事实数和迭代数；每条表达式固定最多 10,000 个求值步骤，每个查询最多 10,000 个绑定。无 wall-clock 超时 API。
- Base64URL：输出为带正确 padding 的 URL 安全编码；解码接受规范的有 padding/无 padding形式，并校验字符、大小和规范性。解码本身不验证签名。
- Root key ID 只保留为提示；验证 API 始终要求调用方明确传入可信 root public key。
- unknown protobuf fields 按严格策略拒绝；解析诊断返回类别与消息，没有行列位置。

## 测试状态

本地命令及真实结果见 [conformance.md](conformance.md)。截至本次文档整理：

- moon test：115 项通过，0 项失败。
- moon test -f 'official*'：51 项通过、0 项失败；其中 48 个 Ed25519 范围内授权场景及 1 项官方第三方签名验证符合预期。test036/test037 为预期 unsupported_token，范围外。
- 固定 biscuit-rust 修订的 CI 双向互通通过 12 组授权结果对照，并成功解析 MoonBit 打印的 Datalog 文本。完整结果见 [conformance.md](conformance.md) 与 Actions run 43793900704。

## 安全与版本声明

issue、attenuate、third-party 与 seal API 要求调用方提供独立、新鲜的 32-byte seeds；本项目不替代系统 CSPRNG。公开示例密钥只能用于测试。Ed25519 依赖 hustcer/ed25519 0.6.1 未在本项目接受密码审计，且维护者说明实现不是 constant-time。

本兼容性声明仅覆盖上述固定规范与 Rust 修订下的 Ed25519 配置，不代表 P-256、旧 token 格式、未知 protobuf 扩展或其他实现版本兼容。
