# 规范差距与复审点核对

审计日期：2026-11-15
规范基线：eclipse-biscuit/biscuit b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639
对照实现：eclipse-biscuit/biscuit-rust 2273077e2fcabeb8c03474125b4d96d57df6b4f7（biscuit-auth 7.0.0-alpha.3）
测试工具链：moon 0.1.20261023 / moonc 0.10.17+d971670cd

本表按驳回意见逐项记录“biscuit-rust 是否支持、当前实现、对应证据和剩余边界”。“计划/剩余项”只列真实未完成事项。

| 规范条目 | biscuit-rust 是否支持 | 我们现状 | 计划/剩余项 | 对应测试 |
| --- | --- | --- | --- | --- |
| Biscuit 当前 protobuf v3 与 schema.proto | 支持 | 已实现有界 protobuf 读写、v3 block 解析和签名链；输入最多 1 MiB、追加块最多 128。未知字段/变体严格拒绝 | 若后续规范增字段，需逐项更新 schema 和双向 fixture；当前不承诺未知字段前向兼容 | official test001–006、020、026；biscuit_test.mbt |
| Datalog 3.0–3.3 版本门控 | 支持 | block version 3–6 对应 3.0–3.3，按版本校验值、操作码和特性 | 测试未来新版本时更新兼容矩阵；当前拒绝范围外版本 | official test017、025、028–038；official_samples*_test.mbt |
| 值类型与嵌套集合 | 支持 | Integer/String/Date/Bytes/Bool/Null/Array/Set/Map；Map 键为整数或字符串；集合语义去重；有深度和数量上限 | 日期文本输出限制为 RFC3339 四位年份；协议值若超出可打印年份会返回 Unsupported | official test030、033、034；datalog_test.mbt |
| 一元/二元 Datalog 表达式 | 支持 | 比较、严格/宽松相等、算术、溢出/除零、逻辑短路与急切布尔、位运算、字符串操作、regex、集合交并、get、length/type、FFI、any/all、try_or 均有求值分支 | 继续扩大边界/类型错误用例和跨实现差分；已有 32 组 seeded 小型授权差分，尚未生成任意表达式组合 | official test017、027–038；datalog_test.mbt；datalog_eval.mbt |
| Datalog 文本解析与打印 | 支持常用 Biscuit 语法 | fact、predicate、规则、表达式、scope、check if/all、reject if、allow/deny 有解析/打印 API；新增 AST 相等往返测试 | 解析错误没有行列位置；Rust 对打印输出的 CI 校验覆盖代表性 block，而非每个 AST 组合 | datalog_test.mbt；examples/print_datalog；tools/interop.py 的 parse-datalog |
| 显式 trusted-origin scope | 支持 | authority、previous、Ed25519 public key；block/rule/query(Check) scope；默认作用域按来源规则处理 | P-256 public-key scope 不支持；需持续增加来源混淆和差分用例 | official test007、008、010、011、023；biscuit_test.mbt |
| 衰减块中的事实、规则、检查 | 支持 | attenuate_block 可附加 facts/rules/checks；推导事实保留来源；规则、check、policy 查询根据 scope 过滤 | 低层 append_raw 保留为不校验语义的原始接口，使用者必须自行保证内容；建议应用用结构化 API | official test012–015、019、023、025；biscuit_test.mbt |
| 第三方签名块 | 支持 Ed25519 | request/contents 生成、签名、序列化/解析、第三方签名验证、追加和 trusting Ed25519 key；block 需 Datalog 3.2+ | 不支持 P-256 第三方签名；持续扩大 Rust 侧对签名错误与 trust-key 边界的覆盖 | official test024；examples/third_party；interop_test.mbt；tools/interop.py |
| sealed proof | 支持 Ed25519 | 验证 sealed/unsealed proof；新增 seal_token，封存后 append_raw/attenuate 拒绝；增加两端生成/验证互测 | P-256 seal 不支持 | official test020；interop_test.mbt；examples/seal；tools/interop.py |
| Authorizer checks 与 allow/deny | 支持 | token 与调用方 facts/rules/checks；check if/all/reject if；首个匹配策略；缺省拒绝；详细 API 返回决策和策略索引，错误类型保留失败 check 索引等 | CI 互通用例目前比较 curated allow/deny；尚未全面比较双方所有 failed-check/policy index 与随机策略集 | official test009–019、025、029–035、038；biscuit_test.mbt |
| 资源限制 | 支持确定性上限 | 调用方可设 max_facts/max_iterations；每条表达式最多 10,000 steps；每个 query 最多 10,000 bindings | 无 wall-clock timeout，也无请求级共享表达式预算参数；需避免把固定预算描述成超时保证 | datalog_test.mbt 的预算用例；biscuit_test.mbt |
| Ed25519/P-256 算法范围 | Rust 支持多种算法；本项目限定 Ed25519 | Ed25519 v0/v1 签名 payload 验证，v1 签发；P-256/secp256r1 明确返回 unsupported_token | P-256 为已声明排除，不列为通过；目前不引入未经审计的第二套密码库 | official test036/037 预期 unsupported_token；互通 suite |
| 官方 samples/current | 支持样例全集 | 38 个官方样例 ID 覆盖 50 个授权结果场景，另有 test024 第三方签名断言；总计 51 项测试。48 个 Ed25519 范围内授权场景与期望一致，test024 签名验证通过；2 个 P-256 场景如期报告 unsupported_token | deprecated 旧格式 samples 不在本轮范围；升级规范基线时需重跑并更新 docs/conformance.md | moon test -f 'official*'；docs/conformance.md |
| 跨实现双向互通 | 支持固定修订下的 curated 用例 | 固定 Rust 修订 CI 已通过 12 组授权结果对照，覆盖双向 token、衰减、第三方块与封存；Rust 解析 MoonBit 输出的 Datalog 文本也通过 | 新增 32 组 seeded 小型授权差分及匹配 policy 索引对照；未系统比较全部失败 check 索引，测试集合不是任意输入的穷举 | tools/interop.py；tools/biscuit-rust-interop；docs/conformance.md；Actions run 43793900704 |
| 传输格式与 RNG | Rust 支持规范 Base64URL；密钥策略依使用方 | token Base64URL encode/decode、有 padding 和无 padding规范化；issue/append API 要求调用方传 32-byte seeds | API 不内置 CSPRNG；不把公开示例固定 seed 用于真实签发 | biscuit_test.mbt；examples/issue、examples/seal |
| 外部 protobuf 扩展 | 支持未知字段处理取决于 Rust serde/protobuf 层 | 项目采用 fail-closed 的未知字段策略 | 若需前向兼容，先定义保留原始签名字节与忽略无关字段的安全规则，再加官方 fixture | malformed/unknown-field 单测；docs/compatibility.md |

## 结论

初审点名的四类核心语义已进入实现：完整 Datalog 表达式与文本往返、显式 scope、可带 facts/rules/checks 的衰减块、Ed25519 第三方块和来源感知 Authorizer。sealed token 创建和详细策略决策也已补齐。

仍需在复审材料中明示的限制是：P-256 与旧 token 外层格式不支持；未知 protobuf 字段严格拒绝；没有 wall-clock timeout；密码依赖未经本项目审计；跨实现验证是固定 Rust 修订上的 curated suite，已有小型 seeded differential，但未覆盖任意输入和全部错误索引。最终通过数与新增跨实现结果以 [conformance.md](conformance.md) 中的运行命令和 Actions 记录为准。

2026-11-19 追加验证：具体接入对象、委托流程和 ACL/JWT 比较见 [maintenance-case.md](maintenance-case.md)。真实业务值重名场景发现第三方符号表隔离缺陷，本轮已修复并增加回归测试；此前的通过记录仅表示当时用例集合通过，不能代替所有规范输入的兼容证明。
