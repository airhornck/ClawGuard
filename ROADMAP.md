## ClawGuard Roadmap / 路线图

### 0.x Series (Current) / 当前阶段

- **CN**
  - 稳定现有 CLI 接口与核心能力：
    - `audit config`：配置与凭证审计。
    - `audit skills`：基于 AST + 规则库的 Skills 静态扫描。
    - `fix:auto`：自动修复网关暴露与明文密钥迁移辅助。
  - 收集社区反馈，迭代规则与误报控制策略。

- **EN**
  - Stabilize the current CLI surface and core features:
    - `audit config`: configuration and credential audit.
    - `audit skills`: AST + signature-based static analysis for Skills.
    - `fix:auto`: gateway hardening and secret migration assistance.
  - Collect community feedback and tune rules / false-positive behavior.

---

### Planned Enhancements / 计划增强

- **Rules & Engine / 规则与引擎**
  - CN：
    - 引入“Review Needed”等中间等级，用于减少高误报率规则的干扰。
    - 支持按项目自定义和覆盖签名库（例如 `.clawguard-rules.json`）。
    - 更多针对网络、文件系统、进程控制的规则。
  - EN:
    - Introduce intermediate severities such as "Review Needed" for noisy rules.
    - Support per-project rule overrides (e.g. `.clawguard-rules.json`).
    - Add more rules for network, filesystem, and process control patterns.

- **Config & Env / 配置与环境**
  - CN：
    - 更智能地区分开发 / 测试 / 生产环境配置风险。
    - 集成简单的依赖安全检查（模拟 CVE 黑名单或调用外部服务）。
  - EN:
    - Better environment awareness (dev / test / prod) for config findings.
    - Integrate lightweight dependency security checks (CVE blacklists or external services).

- **Reporting / 报告**
  - CN：
    - 支持导出 JSON / Markdown 报告，方便集成到 CI 或工单系统。
    - 为 IDE / CI 提供机器可读的结果格式。
  - EN:
    - Export JSON / Markdown reports for CI and ticketing integration.
    - Provide machine-readable formats suitable for IDE and CI plugins.

---

### Longer Term / 长期规划

- CN：
  - 与 OpenClaw 官方生态更紧密结合（例如：官方配置模式、推荐实践）。
  - 提供简单的“安全基线”模板，让新项目一键应用安全默认值。
  - 探索将静态分析结果与动态运行数据（如审计日志）结合的可能性。

- EN:
  - Tighter integration with the OpenClaw ecosystem (official config schemas, best practices).
  - Provide security baseline templates for new projects.
  - Explore combining static analysis results with runtime signals (e.g. audit logs).

