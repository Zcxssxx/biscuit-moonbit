# 最终标准兼容目标与 P-256 实施验收记录

更新：2026-11-20。G1–G7 的 P-256 与混合链实现已落地；官方样例和实际 MoonBit↔Rust 8 组矩阵通过。下文保留实施拆分与最终目标，进度以本段及 conformance.md 的最新结果为准。

## 最终目标及固定基准

最终交付目标是固定规范修订下的**完整当前标准兼容**，覆盖当前 Biscuit protobuf v3 外层格式、Datalog 3.0–3.3（block version 3–6）、Ed25519 与 ECDSA P-256/secp256r1，以及两者混合的签名链。包括签发、验证、衰减、第三方块、算法对应的 trusting 公钥、Base64URL、unsealed/sealed proof 和相同授权语义。

基准不变：规范、schema.proto、samples/current 固定到 `eclipse-biscuit/biscuit@b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639`；Rust 对照固定到 `eclipse-biscuit/biscuit-rust@2273077e2fcabeb8c03474125b4d96d57df6b4f7`。最终验收不能再把 test036/test037 当成算法范围外，也不能仅通过 Rust 参照测试就宣称 MoonBit 兼容。

“完整”限于上述修订的当前标准，不等于支持所有历史外层格式、废弃的 external signature payload v0 或未知未来扩展。普通区块签名 payload v0/v1 按基准规范及官方样例校验；新签发使用 v1，第三方签名使用 v1。资源限制可以拒绝超限输入，但必须明确报错、公开限制，不得把规范内缺失能力静默忽略。

**当前状态：** MoonBit 已集成 Ed25519 与 P-256，包括压缩 SEC1 公钥、严格 DER 编解码、带算法密钥类型、混合链、proof、两算法公钥作用域。官方 test036/test037 已取消 unsupported 预期并按真实授权成功通过。新增 typed API 和双向用例见 [algorithm-api.md](algorithm-api.md)。

## 算法实现约束

规范算法编号为 Ed25519=0、SECP256R1=1。P-256 使用 SHA-256、33-byte 压缩 SEC1 公钥（02/03 前缀）、大端私有标量及 ASN.1 DER 编码的 `(r,s)` 签名。不能将 P-256 签名按 Ed25519 的固定 64 字节处理，也不能把原始 `r||s` 直接放入协议。

已建立独立密码适配层，固定 `moonbitstack/mooncrypt 0.3.1/sign/ecdsa`，已在本机及固定 CI 工具链编译；依赖许可证和版本见 THIRD_PARTY_NOTICES.md。密码运算使用该库，协议编解码、DER 适配、签名 payload、来源隔离和 Datalog/Authorizer 由 MoonBit 实现。Rust helper 仅作对照。后端通过签名互验和非法输入测试不代表独立安全审计。

后端验收包含已知签名向量、Rust 双向签名验证、非法点/前缀/长度、零值或越界标量、DER 非法长度/整数和签名篡改。不以自行拼装未经验证的曲线运算赶进度。

## 实施修改范围

| 工作包 | 具体修改 | 完成门槛 |
| --- | --- | --- |
| G1 密码后端 | 验证 P-256 derive/sign/verify、SEC1、DER、SHA-256，固定版本与许可 | 后端向量和双向签名对照实际通过；不只验证签名成功用例 |
| G2 类型与 wire | 引入带 algorithm 的公钥/私钥类型；解码保留算法；按算法验证长度与编码；签名 payload 写入 nextKey 的真实算法编号 | 不丢弃算法标签、不以公钥长度猜测签名者算法；保持 Ed25519 包装 API 可用 |
| G3 签发与衰减 | 新 API 分别接收 root key 与 next key；追加时以当前 proof 对应算法签署，调用方选择下一把 key 的算法 | 纯 P-256、Ed→P、P→Ed、多次交替链签发/追加双向互通；错误算法标签和篡改失败 |
| G4 proof/seal | nextSecret 按最后 nextKey 算法恢复；sealed proof 按最后 key 验证，payload 携带真实算法；sealed 后追加拒绝 | 混合链两种结尾算法分别测试 unsealed、seal、再验证及禁止追加 |
| G5 第三方与作用域 | ExternalSignature 保留独立算法；trust scope 身份为 `(algorithm,key)`；解析/打印 `secp256r1/…`；复用来源隔离 | E/P 外部签名与 E/P 链任意组合；错公钥/错算法/伪造事实均不能满足 check |
| G6 完整 conformance | 取消 test036/test037 的 unsupported 预期；运行全部 current 样例，并扩展双向对照与差分 | 38 个 ID 的 50 个授权场景均与期望一致，另有签名断言；不得留两项“预期不支持”充数 |
| G7 交付证据 | 更新 README、compatibility、gap-analysis、来源说明、示例与申报书 | 每一项支持声明有命令、结果、SHA、CI 与失败原因；保留已知实现差异 |

## P-256 与混合算法流程示例

下面 E=Ed25519，P=P-256。`root → next1 → next2` 表示签名密钥演进，不能按“全令牌只有一种算法”处理。

1. **纯 P-256：P root→P next1→P next2。** P root 签发 authority，写入 P next1；持有者用 P next1 对追加限制块签名并写入 P next2。proof 采用 P next2 私有标量，seal 用 P next2 签名。授权流程与 Ed25519 相同，先全部验签，再检查数据来源和限制。
2. **混合 E→P→E。** E root 签 authority，authority.nextKey 为 P。追加块签名由 P key 完成，nextKey 改为 E；该块的 payload 中 algorithm 是下一把 E key 的编号 0，签名验证仍使用前一把 P key。最后 proof 用 E key。反向 P→E→P 也必须通过。
3. **第三方 P 审批 + E/P 混合链。** 工厂改用 P-256 审批 key，外部块附 `approval(plant,job)`，`trusting secp256r1/<compressed-key>` 只信任这一来源。外部签名算法和持有者追加块签名算法分别验证；二者不要求相同。签名链通过仍不足以允许操作，必须执行工单、路径、期限及 read 策略。

现有工厂日志案例将扩展以上三种签发/委托方式，要求同一请求在 E-only、P-only 和混合链下产生相同允许/拒绝结果。

## 验收矩阵与参照程序

新增 Rust helper 模式 `algorithm-matrix`，先建立可运行参照：root 算法 E/P × authority.nextKey E/P × 第三方签名 E/P，共 8 组；000/111 保持纯 E/P，其余组合在普通衰减时切换 nextKey 算法，第三方块后再次设置 nextKey。每组验证审批前拒绝、审批后 read 允许、write 拒绝，并重新解码验签和封存验签。它输出公开测试令牌供后续 MoonBit 测试复用，**属于 Rust-only 参照，不是 MoonBit P-256 互通结果**。

```text
cargo run --manifest-path tools/biscuit-rust-interop/Cargo.toml -- algorithm-matrix
```

MoonBit 后续必须执行矩阵同样流程的双向版本：Rust 生成→MoonBit 验证/追加/授权；MoonBit 生成→Rust 验证/追加/授权；并比较 allow/deny、命中策略和失败 check。覆盖错根 key、算法标签篡改、DER 篡改、错误第三方 key、跨令牌复用 contents、seal 后追加、proof 标量与算法不符。32 组现有小型差分保留，但不能替代混合链矩阵。

## 截止前安排与失败处理

计划按 G1→G2/G3→G4/G5→G6/G7 推进：11 月 20–22 日完成后端资格验证；23–25 日完成算法类型、签发与普通衰减；26–27 日完成 proof、第三方与混合链；28–29 日执行全部样例、双向验收和材料核对，30 日前提交结果。日期是待验证工作安排，不能代替通过证据。

若密码后端不能在固定工具链可靠编译或验证失败，应记录具体阻塞并调整后端方案；若到期仍未通过完整门槛，应如实报告未完成，不再把 Ed25519 子集称为最终标准兼容，也不承诺组委会一定通过。

规范依据：[固定 SHA SPECIFICATIONS.md](https://github.com/eclipse-biscuit/biscuit/blob/b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639/SPECIFICATIONS.md) 的 Algorithms、Signed payload generation、Proof、Symbol/Public key tables；候选后端资料：[ECDSA API](https://mooncakes.io/docs/moonbitstack/mooncrypt/sign/ecdsa)。

参照矩阵已在 [CI run 44705898333](https://github.com/Zcxssxx/biscuit-moonbit/actions/runs/44705898333) 实际执行并成功，详见 [conformance.md](conformance.md)。该次是实施前的参照结果；当前 MoonBit 实现状态和双向结果见下一节。

## 实现验收结果

代码提交 `14f7b9e` 的 [CI run 44708002028](https://github.com/Zcxssxx/biscuit-moonbit/actions/runs/44708002028) 成功，新增 `python tools/algorithm_interop.py` 的 000–111 八组均 PASS。这次是 MoonBit 与 Rust 相互签发/验证、交替衰减、两算法第三方块和 seal 验证，不再只是 Rust-only 参照。本地后续新增签名绑定和算法混淆负向测试，最新通过数与 CI 见 [conformance.md](conformance.md)。

原日期安排为实施前计划，现由实际实现结果取代；密码审计、完整错误索引差分和生产接入仍是已知边界。
