# 规范差距与当前实现核对

更新：2026-11-20。基准为 Biscuit `b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639` / Rust `2273077e2fcabeb8c03474125b4d96d57df6b4f7`。此前 Ed25519-only 里程碑已由两算法实现取代。

| 规范条目 | biscuit-rust 是否支持 | 我们现状 | 剩余边界 | 对应测试 |
| --- | --- | --- | --- | --- |
| Datalog 3.0–3.3 | 支持 | 值、表达式、短路、闭包、类型错误、溢出、文本解析打印已实现 | 非任意组合穷举，解析无行列定位 | datalog_test、official samples |
| 显式 scopes / 来源 | 支持 | authority、previous、两算法公钥，块/规则/check 作用域 | 继续扩展来源混淆测试 | biscuit_test、crypto_wbtest、test007/008/023/037 |
| 衰减块 facts/rules/checks | 支持 | 保留来源，限制不可通过普通后续块提权 | raw 接口由调用者保证 Datalog 编码 | test012–015/019/025、maintenance |
| Ed25519 / P-256 | 支持 | 带算法密钥、SEC1/DER、签发验证、proof | 未独立密码审计 | crypto_wbtest、test036/037 |
| 混合链 / seal | 支持 | E/P root、nextKey 切换和最后 proof 算法正确分派 | 固定 8 组非任意长度穷举 | tools/algorithm_interop.py、seal 拒绝追加 |
| 第三方块 | 支持 | 两算法请求、签名、contents、追加、来源隔离 | 无生产审批系统 | test024/037、crypto_wbtest、双向矩阵 |
| Authorizer | 支持 | facts/rules/checks、allow/deny、首个匹配策略、结构化错误 | 不比较全部失败 check 索引 | 32 组 seeded differential、biscuit_test |
| 官方 current 样例 | 支持 | 38 IDs、50 授权场景及两项签名验证；52 项全通过 | deprecated 旧格式不在当前版本目标 | moon test -f 'official*' |
| 资源限制 | 支持 | 大小、深度、facts/iterations、表达式步数、绑定数上限 | 无 wall-clock timeout/请求共享预算 | hardening_wbtest、datalog_test |
| 序列化和前向兼容 | 支持当前 schema | protobuf、Base64URL、版本门控、算法标签 | 未知字段严格拒绝 | malformed 与官方 fixture |
| 实际业务接入 | 可由库实现 | 工厂日志模拟委托，10 个场景断言 | 无真实工厂部署/HTTP 网关 | examples/maintenance |

当前核心评审缺口 P-256 和混合链已进入 MoonBit 实现，并以官方样例和 Rust 双向矩阵验证；不以计划或 Rust-only 参照代替实现。最新命令和 CI 证据见 [conformance.md](conformance.md)，API 见 [algorithm-api.md](algorithm-api.md)。
