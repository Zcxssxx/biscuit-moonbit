# 开发与验证

## 环境

CI 按 `.moonbit-toolchain` 固定 MoonBit 编译器；先用 `moon version --all` 记录本机版本。较新工具链会将旧 `derive(...)` 自动格式化为新语法，提交前检查差异，避免意外破坏固定版本兼容性。

```text
moon update
moon check
moon test
moon build
moon run examples/maintenance
```

根包的 `*_test.mbt` 测试公开 API，`*_wbtest.mbt` 测试内部不变量。涉及协议语义时，应补正常输入、拒绝/错误输入和可复现 fixture；纯文档修改可检查链接和差异，无需添加对应测试。

按 AGENTS.md 在完成时运行 `moon info` 和 `moon fmt`，检查生成接口差异是否符合预期。固定版本工具链下 `moon fmt --check` 必须通过。

可选的 Git 提交前检查在 [`.githooks/`](.githooks)，启用后会在本地提交前执行 `moon check`。

## 官方样例与差分

```text
moon test -f 'official*'
cargo fmt --manifest-path tools/biscuit-rust-interop/Cargo.toml -- --check
cargo test --manifest-path tools/biscuit-rust-interop/Cargo.toml
python tools/interop.py
```

互通脚本需要本机 Cargo 和 MoonBit native 编译环境；也可使用 GitHub Actions。脚本固定 upstream Rust revision，保留双向令牌、衰减、第三方、封存检查，并生成 32 组 seed=20261119 的小型授权输入，比较决策和匹配策略索引。失败 check 暂按类别比较，没有映射全部检查索引。

`_build/interop-decisions.json` 记录随机种子、输入事实、策略、期望和两侧结果；CI 保存为 `interop-decisions` artifact 14 天。发生差异时先保存该 fixture，再缩减复现并修复；不得把异常统一记为权限拒绝来让对照通过。上游解析错误或意外求值错误应使差分进程失败。

## 修改与来源

提交应说明具体行为变化并附实际验证结果。复制上游 fixture 或引入依赖时更新 `THIRD_PARTY_NOTICES.md`。更改支持范围或测试统计时，同步 README、compatibility 和 conformance；保留历史运行记录并追加当前结果。

当前仓库只接受所有者 Zcxssxx 的提交身份，不添加 Co-authored-by。提交前检查仓库级 git user.name/user.email 和远程地址，账号认证仅核验目标账号，不枚举本机其他账号。
