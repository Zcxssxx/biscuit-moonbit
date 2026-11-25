# Biscuit MoonBit

Biscuit 授权令牌与 Datalog 的 MoonBit 实现，目标配置为 Biscuit 当前 protobuf v3、Datalog 3.0–3.3 和 Ed25519 / P-256。项目包含令牌签发、验证、衰减、封存、第三方块签署与追加，以及来源感知的 Authorizer。

项目仍为实验性实现，尚未进行独立密码审计。发布前请阅读“安全边界”；示例中的固定密钥是公开测试数据，不能用于保护真实资源。

## 快速开始

### 安装已发布版

在已有的 MoonBit 项目中添加依赖。 [Mooncakes 包页面](https://mooncakes.io/docs/Zcxssxx/biscuit)

```sh
moon add Zcxssxx/biscuit@0.1.0
```

在调用方的 `moon.pkg` 中导入库。

```moonbit
import {
  "Zcxssxx/biscuit" @biscuit,
}
```

Mooncakes `0.1.0` 对应 [发布源码提交 `630ae9b`](https://github.com/Zcxssxx/biscuit-moonbit/tree/630ae9b34647f5111569906046a1e4395ac4234f)。后续优化和测试记录随 GitHub 默认分支更新。

### 从源码运行完整场景

```sh
git clone https://github.com/Zcxssxx/biscuit-moonbit.git
cd biscuit-moonbit
moon version --all
moon update
moon run examples/maintenance
```

工厂日志示例应输出 `业务验收：10/10 场景符合预期`，覆盖签发、衰减、第三方签署与授权。单项示例包括 [签发与衰减](examples/issue)、[第三方块](examples/third_party) 和 [封存](examples/seal)。

## 最终兼容目标与当前进度

当前已实现固定规范下的 Ed25519、P-256/secp256r1 及混合算法签名链，覆盖签发、验证、衰减、第三方块、封存与授权。MoonBit 使用 mooncrypt 的 P-256 密码运算，协议、DER/SEC1 适配、签名链与授权求值由本项目实现。

官方 test036/test037 已按授权成功断言通过；MoonBit↔固定版本 biscuit-rust 的 8 组算法组合实际互通通过。实现和验收过程见 [完整兼容计划与结果](docs/full-compatibility-plan.md)，命令与 CI 证据见 [一致性记录](docs/conformance.md)。这不是独立密码安全审计或所有输入的兼容性证明。

## 支持范围

具体应用案例：[工厂日志的外包排障委托](docs/maintenance-case.md)。平台授予读取权，承包商把交给工单工具的子令牌缩到单台设备、单个工单和期限；工厂审批方独立签署放行事实。网关离线验证原授权、追加限制和受信第三方背书。运行 `moon run examples/maintenance` 可验收一个允许场景和九个拒绝场景。案例为模拟集成原型，接入边界与 ACL/JWT 的取舍详见案例文档。

| 能力 | 支持范围 |
| --- | --- |
| Biscuit 外层格式 | 当前 protobuf v3；Datalog block version 3、4、5、6 分别对应 Datalog 3.0、3.1、3.2、3.3 |
| Datalog 值 | 整数、字符串、日期、字节、布尔、null、数组、集合、字符串或整数键映射 |
| Datalog 求值 | 规范表达式、严格与宽松比较、算术与溢出检查、字符串/集合/数组/映射运算、正则、短路、any/all 闭包、try_or 和 FFI |
| 作用域与衰减 | authority、previous、Ed25519 / P-256 trusting 公钥；块、规则、查询/检查级作用域；衰减块可含事实、规则和检查 |
| 签名与令牌操作 | Ed25519 / P-256 签名 payload v0/v1 验证；v1 签发与追加；unsealed/sealed proof 验证；seal_token 创建 sealed token |
| 第三方块 | Ed25519 / P-256 request、签名、contents 编解码、追加、验证和 trusting 公钥授权 |
| Authorizer | token 与调用方事实/规则/check、check if/check all/reject if、首个匹配 allow/deny 策略、详细策略决策和结构化错误 |
| 文本与传输 | Datalog fact/rule/check/policy/表达式和值解析和打印；Base64URL token 文本 |

Biscuit 外层旧格式 v0/v1/v2 不在当前标准版本范围。未知 protobuf 字段按严格策略拒绝；兼容性边界详见 [docs/compatibility.md](docs/compatibility.md)。

## API 流程

签发结构化 authority block：

    let token = @biscuit.issue(
      facts, rules, checks, 6, root_seed, next_seed,
    )

追加可含 facts、rules、checks 与作用域的衰减块：

    let attenuated = @biscuit.attenuate_block(
      token, root_public_key, facts, rules, checks, block_scopes, 6, fresh_next_seed,
    )

生成并提交第三方 Ed25519 block：

    let request = @biscuit.create_third_party_request(token, root_public_key)
    let contents = @biscuit.build_third_party_block(request, block_data, external_seed)
    let extended = @biscuit.append_serialized_third_party_block(
      token, root_public_key, @biscuit.serialize_third_party_block(contents), fresh_next_seed,
    )

封存后令牌不能继续衰减：

    let sealed = @biscuit.seal_token(attenuated, root_public_key)

获取可检查的策略结果；令牌错误、失败的 check、表达式错误和资源上限仍以 AuthorizationError 变体返回：

    let result = @biscuit.authorize_token_detailed(
      token, root_public_key, ambient_facts, ambient_rules, ambient_checks,
      policies, max_facts, max_iterations, externals,
    )
    match result.decision {
      @biscuit.Allow => println("允许")
      @biscuit.Deny => println("拒绝")
    }
    println(result.policy_index.to_string())

可运行示例位于 examples/。底层 issue_raw/append_raw 接收预序列化数据，不校验其 Datalog 语义；一般使用应优先选择结构化 API。

## P-256 与混合算法 API

`SigningKey` / `VerificationKey` 显式携带 `Ed25519` 或 `Secp256r1`。前者 secret 为 32 字节 Ed25519 seed 或 32 字节大端 P-256 标量（须在有效范围内）；后者 key 为标准 32 字节 Ed25519 公钥或 33 字节压缩 SEC1 P-256 公钥。

- `verification_key`：从私钥导出带算法的公钥。
- `issue_with_keys`：结构化签发，root 和 next 可以使用不同算法。
- `attenuate_with_key`：追加 facts/rules/checks/scopes，并选择下一把 proof key 的算法。
- `verify_with_key` / `authorize_with_key` / `seal_with_key`：带算法根公钥的验签、授权与封存。
- `third_party_request_with_key` / `sign_third_party_with_key` / `append_third_party_with_key`：任意两种算法组合的第三方请求、签署与追加。
- `trust_verification_key`、`external_verification_key`：构造公钥作用域、读取第三方签名者的标准公钥。

旧 API 继续接受 Ed25519 字节，默认生成下一把 Ed25519 key。内部为兼容旧字节字段使用私有带标签表示；调用方应通过上述类型 API 传递标准公钥，不手工拼装内部表示。

运行全部算法的可复现双向验收：`python tools/algorithm_interop.py`（需要 Cargo 和 native 编译环境）。详细用法见 [算法接入说明](docs/algorithm-api.md)。

## 同一令牌的重复授权

使用 `prepare_with_key(token, trusted_root)` 验签并解码一次。结果为不可从库外构造的 `PreparedToken`。对每个请求调用 `prepared.authorize(facts, rules, checks, policies, max_facts, max_iterations, externals)`，提供该次请求的可信事实与当前策略。

```moonbit
let prepared = @biscuit.prepare_with_key(token, trusted_root)
let result = prepared.authorize(
  request_facts, [], [], policies, 1000, 100,
  @biscuit.ExternalFunctions::{ unary: Map([]), binary: Map([]), },
)
```

服务端按可信根和令牌内容划分缓存，在信任配置改变时使缓存失效。调用方继续在每次请求提供当前时钟、权限条件和撤销决策。工厂日志示例使用同一已验签令牌处理多次独立请求。可复现实测与三轮数据见 [授权基准](docs/benchmarks.md)。

## 验证与互操作

CI 编译器版本固定在 [`.moonbit-toolchain`](.moonbit-toolchain)。本地复现可运行以下命令。

```sh
moon check
moon build
moon test
moon test --target native
moon test -f "official*"
```

- 默认后端和 native 各通过 127 项测试。官方样例筛选通过 52 项，包含 38 个样例 ID 中的 50 个授权场景和 2 项独立签名验证。
- 固定 biscuit-rust 修订的 CI 通过双向互通、8 组签名算法组合与 32 组授权结果差分。格式检查使用 CI 固定工具链。场景明细见 [一致性记录](docs/conformance.md)，运行结果见 [GitHub Actions](https://github.com/Zcxssxx/biscuit-moonbit/actions/workflows/ci.yml)。

## 仓库结构

| 路径 | 内容 |
| --- | --- |
| 根包 [`moon.mod`](moon.mod)、[`moon.pkg`](moon.pkg) | 库的入口与依赖。令牌验证和授权在 [`token.mbt`](token.mbt)，Datalog 解析和求值在 [`datalog.mbt`](datalog.mbt)、[`datalog_eval.mbt`](datalog_eval.mbt)。 |
| 根包 `*_test.mbt`、`*_wbtest.mbt` | 公共 API 测试、内部不变量、官方样例和性能基准。 |
| [`examples/`](examples) | 按用途组织的独立示例包。 |
| [`tools/`](tools) | Python 互通脚本及 Rust 对照工具，供本地复现和 CI 使用。 |
| [`docs/`](docs) | 兼容范围、应用接入、验收证据和开发记录。 |

## 安全边界

- 调用方必须独立选择可信根公钥。token 中的 root key ID 不会替调用方选择信任根。
- issue/attenuate/third-party/seal 相关 API 接收调用方提供的 32 字节种子，不内置随机数生成器。必须从操作系统安全熵源取得彼此独立且新鲜的种子；复用或硬编码种子会破坏安全性。
- 项目使用的 hustcer/ed25519 0.6.1 依赖未经过本项目密码审计，其维护者标注实现未经审计且不是 constant-time。
- Authorizer 为派生事实数量、迭代次数提供调用方可配置上限；表达式步骤和查询绑定有固定确定性上限。当前没有 wall-clock 超时参数。
- 外部 Datalog 回调接收独立的集合副本，以隔离宿主修改。回调参数超过嵌套上限时返回表达式预算错误。
- token 输入最大 1 MiB、最多 128 个追加块；Datalog 值深度和集合大小也有限制。解析错误目前提供错误类别与消息，不提供源码行列位置。
- 上游双向测试固定到一个 biscuit-rust revision。另有 seed=20261119 的 32 组小型授权输入差分，覆盖允许/拒绝的匹配策略索引、无匹配策略和失败 check 类别；未覆盖任意表达式组合、全部错误或失败 check 索引。不能据此推断兼容所有 Biscuit 实现或未来版本。
- P-256 使用 moonbitstack/mooncrypt 0.3.1；未经过本项目独立密码/侧信道审计，不宣称常量时间实现。

## 来源与许可证

本项目采用 Apache-2.0，见 [LICENSE](LICENSE)。规范基线、官方样例和 Rust 对照实现的修订、直接与传递依赖许可证、测试向量来源见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。审核基准、支持版本边界及逐项差距见 [docs/compatibility.md](docs/compatibility.md)、[docs/gap-analysis.md](docs/gap-analysis.md) 和 [docs/conformance.md](docs/conformance.md)。

开发与复现流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题反馈见 [SECURITY.md](SECURITY.md)。项目文档按用途收录在 [文档索引](docs/README.md)。
