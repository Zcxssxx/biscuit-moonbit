# P-256 和混合算法接入

## 数据与信任边界

`SignatureAlgorithm` 包含 `Ed25519` 与 `Secp256r1`。`SigningKey` 携带 algorithm 和 secret；`VerificationKey` 携带 algorithm 和标准公钥 key。P-256 secret 是有效范围内的 32-byte 大端标量，不是任意长度口令；公钥是 33-byte 压缩 SEC1 点。不得仅凭 token 的根 key ID 自动选择信任根。

P-256 后端固定为 `moonbitstack/mooncrypt 0.3.1/sign/ecdsa`，使用默认 P256/SHA-256 和 RFC6979 签名。项目将后端的 `r||s` 转为协议 DER，验签前严格验证 DER 正整数、长度和最短编码，再转换回后端格式；非法点和标量明确拒绝。密码库及本适配层没有独立安全审计。

## 结构化流程

以下变量的随机种子/标量由宿主安全生成，示例展示调用关系：

```moonbit
let root = @biscuit.SigningKey::{ algorithm: @biscuit.Ed25519, secret: root_secret }
let next = @biscuit.SigningKey::{ algorithm: @biscuit.Secp256r1, secret: next_scalar }
let trusted_root = @biscuit.verification_key(root)
let token = @biscuit.issue_with_keys(facts, rules, checks, [], 6, root, next)
let delegated = @biscuit.attenuate_with_key(
  token, trusted_root, [], [], restrictions, [], 6,
  @biscuit.SigningKey::{ algorithm: @biscuit.Ed25519, secret: fresh_secret },
)
```

authority 签名使用 root 的 Ed25519，authority.nextKey 写入 P-256。衰减块使用 proof 对应的 P-256 签名，nextKey 改为 Ed25519，末尾 proof 随之使用 Ed25519。普通签名 payload 的算法编号属于 nextKey；验证该块使用前一把 key 的算法。

第三方流程使用 `third_party_request_with_key` 生成请求，以 `sign_third_party_with_key(request,payload,external_key)` 签名，形成 `ThirdPartyBlockContents`；该结构支持 serialize/parse，然后通过 `append_third_party_with_key` 追加并选择 next key。外部签名算法与令牌链签名算法相互独立。`trust_verification_key` 构造相应的 trusting 公钥，文本语法支持 `secp256r1/<compressed-key-hex>`。

`authorize_with_key` 接收与现有 Authorizer 相同的事实、规则、checks、策略和资源限制，返回决策与策略索引。`seal_with_key` 用最后 proof key 对末块封存，封存后再次追加返回 Unsupported。

## 可复制运行的验收

在 PowerShell 中运行一组纯 P-256 的公开测试 fixture：

```powershell
$env:MATRIX_MODE = 'mint'
$env:ROOT_ALGORITHM = '1'
$env:NEXT_ALGORITHM = '1'
$env:EXTERNAL_ALGORITHM = '1'
moon run --target native examples/algorithms
```

0 代表 Ed25519，1 代表 P-256。该例程使用公开固定测试 secret，输出 ROOT_KEY、TOKEN、SEALED；不可用于生产。完整验收执行：

```text
python tools/algorithm_interop.py
```

8 组输入为 root × authority.nextKey × external 的 E/P 组合，000 和 111 分别保持纯算法，其余在后续追加中切换算法。每组检查 MoonBit 签发的未封存/封存令牌被 Rust 接受、Rust 和 MoonBit 交替追加、Rust 令牌由 MoonBit 继续衰减、Rust 封存令牌由 MoonBit 验证并拒绝追加，以及 read 允许/write 拒绝。原有工单业务例程另覆盖工单、资源、期限和伪造审批的拒绝场景。

`_build/algorithm-interop.json` 保存矩阵结果，CI 上传到 artifact。完整命令和实际结果见 [conformance.md](conformance.md)。通过这些测试不代表已经穷举所有算法组合与异常输入。
