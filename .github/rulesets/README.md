# 仓库保护规则

这些 JSON 是可审计的 GitHub Ruleset 导入模板，提交文件不会自动启用远端保护。

- `protect-main.json` 保护默认分支，要求 review、线性历史及四个稳定检查。
- `protect-release-tags.json` 禁止删除或移动 `v*` 标签。

先在 GitHub 上观察到 `Required Checks`、`Coverage Matrix`、`Prek`、`Docs Build`
四个检查，再由维护者在 Settings → Rules → Rulesets 导入。默认分支现为 `main`；
更改分支名时同步修改 workflow 的 push 和 workflow-run 过滤器。单人维护仓库应先评估一人 review
及最后一次推送审批要求是否符合实际协作流程，再启用模板。

PyPI/TestPyPI/Pages 环境、自动标签和发布恢复方式见[发布文档](../../docs/development/release.md)。
修改汇总 job 名称必须同步修改这里的检查 context 和已启用的远端规则。
