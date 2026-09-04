## 背景与方案

<!-- 描述问题、实现边界及关键取舍。关联 issue 时使用 Closes #123。 -->

## 兼容性与安全影响

<!-- 说明 API、配置、迁移、Broker 协议或 Secret 边界变化；无则写“无”。 -->

## 验证

- [ ] `make check`
- [ ] `make hooks`
- [ ] workflow 变更已运行 `make workflow-lint`，或本项不适用
- [ ] workflow 变更已运行 `make workflow-test`，或本项不适用
- [ ] 已补充必要的回归测试、文档及 Towncrier fragment
- [ ] 已检查文档构建产物，示例不包含真实凭据或生产配置

<!-- 列出实际执行结果及未验证项，不要只写“测试通过”。 -->

## 合并前

- [ ] PR 标题符合 `type(scope): subject`
- [ ] 所有必需检查通过，阻塞 review 已解决
