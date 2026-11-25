# Git 提交前检查

在本仓库启用 Git 钩子后，`git commit` 会运行 `moon check`。命令失败时 Git 会中止本次提交。

```sh
git config --local core.hooksPath .githooks
```

完整验证流程见 [CONTRIBUTING.md](../CONTRIBUTING.md)。
