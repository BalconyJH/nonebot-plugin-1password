# Documentation Development

The documentation uses Zensical. Content lives in `docs/`, and configuration lives in `zensical.toml`.

```bash
uv run zensical serve
uv run zensical build --strict
```

## Content Rules

- 新增或修改的说明正文使用简体中文；代码、类型、配置标识符和注释使用 English。
- The distribution and repository name is fixed as `nonebot-plugin-1password`; the import name is fixed as `nonebot_plugin_1password`.
- Commands, schemas, defaults, error codes, and runtime capabilities must come from the current code and tests. Remove obsolete compatibility interfaces and planning-stage language.
- Clearly distinguish the NoneBot public Catalog from the Broker private Catalog.
- Examples must not contain real tokens, certificates, fingerprints, Secret references, or production URLs. Private Catalog examples use obviously fictitious values only.
- Public API documentation recommends only `nonebot_plugin_1password.api`. The Broker runtime is an operational embedding surface, not the Provider compatibility API.

After making changes, search for obsolete names and interfaces, run the strict build, and manually review the Secret boundary. A successful build proves only link and syntax validity; it does not prove that security claims are correct.

## GitHub Actions 预览

`Docs` workflow 对 PR 和默认分支执行 `make docs`，并保留 `docs-site-<run_id>`
artifact 7 天。下载并解压后可用静态 HTTP server 检查页面；构建成功不等于页面
内容已经完成人工审阅。PR 只提供 artifact，不获得仓库写入或发布权限。
`site/` 已被忽略，它的存在不意味着应提交生成结果。

## GitHub Pages

默认分支成功的 Docs push 或手动运行会触发 `GitHub Pages`。部署流程重新读取 run、
workflow、分支、commit SHA 和 artifact ID，只接收当前默认分支的成功构建，
拒绝 fork/PR、过期和超限产物。静态文件经过类型与大小检查后才交给 Pages；
部署 job 不 checkout、不安装依赖、不执行站点或项目代码。

站点使用默认分支的最新文档，不维护版本化目录。审批等待期间如果分支已前进，
旧部署会跳过。GitHub Pages 的 Source、environment 与恢复步骤见[发布文档](release.md)。
