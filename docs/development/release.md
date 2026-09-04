# 发布与 GitHub Actions

项目使用 Semantic Versioning、Towncrier、uv 和 hatchling。分发名保持
`nonebot-plugin-1password`，正式发布只接受与项目版本完全一致的 `vX.Y.Z` 标签。

## 检查拓扑

| Workflow | 职责 | 稳定检查名称 |
| --- | --- | --- |
| `ci.yml` | Ruff、BasedPyright、verifytypes、ty、release metadata、构建和分发安全检查 | Required Checks |
| `coverage.yml` | Python 3.10–3.13 全量测试；3.13 执行总体及关键文件分支覆盖率门禁 | Coverage Matrix |
| `prek.yml` | 普通 hooks、actionlint、zizmor、完整 Git 历史 Gitleaks 扫描 | Prek |
| `docs.yml` | Zensical strict build，保留可下载的静态预览产物 | Docs Build |

检查完成后，`auto-tag.yml` 为版本提升的可信 commit 创建标签并显式触发发布；
`pages.yml` 使用默认分支的 Docs artifact 部署 GitHub Pages。两者不属于 PR 的
必需检查，不接收 fork/PR 的发布请求。

四个 workflow 在 `main` push、PR 和手动触发时运行，也接受发布流程传入的确定
commit SHA。发布检查禁用依赖缓存，不继承 secrets。汇总检查使用 `always()`，
上游失败、取消或异常跳过都不会被当成成功。PR 更新取消旧检查；默认分支上的
每个 push 保留自己的检查，便于审计。

共享 action `.github/actions/setup-project/action.yml` 固定 uv 版本并执行
`make sync`。所有外部 action 固定到 commit SHA，Dependabot 每周提交 Actions
更新。Python 依赖及 uv 二进制版本仍需通过包管理器和正常 review 更新。

## 本地入口

```bash
make check
make hooks
make workflow-lint
make workflow-test
make secret-scan
```

`make check` 先构建分发，再运行全量覆盖率测试，避免旧 `dist/` 干扰结构检查。
`make workflow-test` 使用 Node.js 22+ 内置测试器直接验证 workflow 中的脚本，
不需要 npm 依赖。CI 使用固定 github-script action 自带的 Node 运行同一测试。
`make workflow-lint` 使用 manual hook stage，扫描全部 workflow 及本地 action，
不维护容易遗漏新增文件的命令行名单。`make secret-scan` 扫描 Git 历史，
不是干净 checkout 中的空暂存区；它需要真实 Git 仓库。CI 使用完整历史 checkout。
Gitleaks 仅对测试中的明确合成标识符和 canary 使用窄范围 allowlist。

覆盖率报告、JUnit 报告及 wheel/sdist 保留 14 天；文档预览保留 7 天。
`make coverage-report` 只生成覆盖率证据；`make coverage` 在此基础上执行门禁。
`site/`、`dist/` 和报告文件都是忽略的构建产物，不提交回源码分支。
日志和 artifact 不应包含真实凭据；workflow 不转储进程环境。

## 正式发布

1. 审查公共 API、三份 NoneBot TOML schema、Broker 配置与协议，以及迁移说明。
2. 确认 Secret 隔离、mTLS、reconciliation 和重启测试通过。
3. 使用 `uv version X.Y.Z` 更新版本并同步 PluginMetadata。
4. 预览并生成 Towncrier 发布记录，同步文档 changelog：

   ```bash
   uv run --frozen towncrier build --draft --version X.Y.Z
   make changelog VERSION=X.Y.Z
   make check
   ```

5. 将版本变更通过 PR 合入默认分支，等待四个必需检查通过。
6. `Auto Tag` 检查同一 SHA 的四个最新 push 检查均成功，比较第一父提交的项目版本，
   再创建 `vX.Y.Z` 并触发 `Publish`。没有版本提升时不发布；首个提交不自动打标签。

自动标签只支持 canonical `X.Y.Z` 版本，不接受降级、预发行或本地版本段。
已有标签必须指向同一 commit，workflow 从不移动标签。多个完成事件按 SHA 串行，
已有 Publish run 时不重复触发。由 `GITHUB_TOKEN` 创建的标签不会触发普通 push
workflow，因此自动流程通过 API 显式 dispatch，不依赖 token 绕过或长期 PAT。

若尚未创建标签或标签创建后 dispatch 中断，从默认分支手动运行 Auto Tag，传入
当前默认分支完整 `source_sha`。这仍要求四个真实 push 检查通过；缺少证据时先
补齐对应 push run 或重跑失败检查。已经开始 Publish 的版本使用其恢复入口。
仅在首次引入项目、没有可比较父提交等场景，由维护者手工创建合规标签。

`publish.yml` 先验证标签格式、版本与默认分支祖先关系，再把解析得到的同一个
SHA 传给全部可复用检查。CI 构建出的不可变 artifact 是唯一发布输入；
有 OIDC 权限的发布 job 不 checkout、不运行项目代码、不重新构建包。
PyPI 发布成功后创建 GitHub Release，并附上同一份 wheel/sdist；已有资产不会被覆盖。

失败恢复优先使用 GitHub 的 **Re-run failed jobs**，保留成功门禁及原始产物。
若尚未成功上传任何文件，也可从默认分支或匹配标签手动运行 Publish，
传入已有 `release_tag`。已上传版本不得用重新构建的文件冒充原产物；
若出现部分上传、artifact 过期或 GitHub Release 已存在，先核对远端状态与摘要，
再决定恢复措施。workflow 不设置 `skip-existing`，避免把不同内容静默视为成功。

## TestPyPI 演练

从默认分支手动运行 `Publish (TestPyPI)`。它在隔离 runner 中先执行
`make check workflow-lint secret-scan`，再通过 `uv version --no-sync` 生成带
run ID 和 attempt 的唯一 `.dev` 版本，同步锁文件与环境后重新构建和检查产物。
这些版本变更不会 commit 或推回仓库，也不会发布到正式 PyPI。

## 远端启用清单

仓库内配置不会自动修改 GitHub 或 PyPI 设置，维护者需完成：

1. 确认默认分支为 `main`；若使用其他名称，同步四个检查 workflow 的 push 过滤器，
   以及 Auto Tag、GitHub Pages 的 workflow-run 分支过滤器。
2. 在四个稳定检查至少运行一次后，审阅并导入
   `.github/rulesets/` 中的默认分支及标签 Ruleset。
   模板要求另一人 review 和最后推送审批，单人维护仓库需先调整协作政策。
3. 创建 GitHub Environments `pypi`、`testpypi`、`github-pages`，配置审批人及允许的部署 ref。
   `pypi` 允许正式标签；若需从默认分支手动恢复，也需允许该分支。
   `testpypi` 只允许默认分支。
   `github-pages` 也只允许默认分支；审批后会重新核对源 SHA，防止发布过时文档。
4. 分别在 PyPI 和 TestPyPI 创建 Trusted Publisher，填写实际 owner/repository、
   workflow 文件名 `publish.yml` / `publish-test.yml`，以及对应 environment 名称。
5. 保持默认 token 最小权限；发布 job 单独请求 `id-token: write`，
   GitHub Release job 单独请求 `contents: write`。Auto Tag 的写入 job 请求
   `contents: write` 和 `actions: write`；确认组织 Actions policy 允许这些权限。
   不配置长期 PyPI API token，也无需自动标签 PAT。
6. 在 Settings → Pages 将 Source 设为 **GitHub Actions**，不要选 gh-pages 分支。
   确认 `zensical.toml` 的 `site_url` 匹配实际 owner/repository 或自定义域名。
   首次配置后，从默认分支手动运行 Docs 即可生成并自动部署文档。

GitHub Pages 发布默认分支的最新文档，不维护版本目录。PR 仅提供 artifact 预览，
不会将不受信任的页面发布到正式站点。恢复部署时可从默认分支手动运行 GitHub Pages，
传入成功 Docs run 的 `docs_run_id`；产物必须未过期且 SHA 仍是默认分支当前 HEAD。
否则重新运行 Docs，不复用旧站点文件。

OIDC 和同仓库复用语义分别遵循
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
与 [GitHub reusable workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)。
自动触发限制见 [GitHub workflow triggers](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/trigger-a-workflow)，
Pages 部署权限见 [actions/deploy-pages](https://github.com/actions/deploy-pages)。

## 分发与事故处理

wheel 只允许包 Python 源码、`py.typed` 和固定 metadata；sdist 只允许明确列出的
项目文件、文档、workflow、开发脚本、typing stubs、合法 Towncrier fragment
及包源码。新增基础设施时同步 `tests/security/test_distribution.py` 的精确白名单，
不能通过放开整个目录来绕过检查。内容检查额外阻止凭据、私钥等敏感内容进入产物。

普通回归回滚前先评估 ORM 与 Broker store 兼容性。若 Secret 或签名材料泄露，
撤回包不能替代 token、证书吊销和事故响应。
