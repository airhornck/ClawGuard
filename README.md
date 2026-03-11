## ClawGuard - OpenClaw Security Audit CLI

### 简介 (Chinese)

ClawGuard 是一个面向 OpenClaw 生态的轻量级安全审计与加固 CLI 工具，目标是帮助用户快速发现并缓解以下风险：

- **配置风险**：网关对公网暴露、明文密钥、调试模式等。
- **供应链风险**：恶意或脆弱的 Skills 代码（RCE、数据外传、混淆代码等）。
- **权限风险**：以 root / 管理员身份运行导致的高危影响面。

当前版本聚焦本地静态分析（SAST），通过 AST 和规则库对 OpenClaw Skills 进行深度扫描，同时提供基础的自动修复能力。

### Features (English)

- **Config audit** (`audit config`)
  - Detects gateway bindings to `0.0.0.0` (potential public exposure).
  - Detects plaintext credentials and hardcoded API keys (e.g. `sk-...`, `AKIA...`, `password: "..."`).
  - Warns when running as root/admin (or when privilege cannot be safely detected).

- **Skills static analysis** (`audit skills`)
  - AST-based scanning of all `.js` / `.ts` files under `~/.openclaw/skills/`.
  - Rule-driven detection of:
    - `child_process.exec / execSync / spawn` (RCE risk).
    - `eval` / `Function` constructor (dynamic code execution).
    - Dangerous file deletion (`fs.rm`, `fs.unlink` with wildcard/root-like paths).
    - Potential data exfiltration via `axios.post` / `fetch` to non-whitelisted domains.
    - High-entropy long strings (possible obfuscation or embedded payloads).

- **Auto-fix for common issues** (`fix:auto`)
  - Generates a `.env.example` template for suspected plaintext secrets.
  - Interactively replaces `host: "0.0.0.0"` with `127.0.0.1` in config files, with timestamped `.bak` backups.

---

## 安装与使用 (Installation & Usage)

### 1. 从源码安装 (From Source)

```bash
git clone <your-repo-url> clawguard
cd clawguard
npm install
npm run build

# Optionally link as a global CLI
npm link
clawguard audit config
clawguard audit skills
clawguard fix:auto
```

### 2. 直接使用打包二进制 (Prebuilt Binary, no Node required)

> 注意：二进制支持情况取决于 Release 中提供的构建产物。

1. 从项目的 Releases 页面下载对应平台的可执行文件（例如 `clawguard-win-x64.exe`）。
2. 将其放到任意目录（建议加入到 `PATH`）。
3. 在终端中运行：

```bash
clawguard audit config
clawguard audit skills
clawguard fix:auto
```

若使用 Windows，可直接在 PowerShell 中执行：

```powershell
.\clawguard-win-x64.exe audit skills
```

---

## 命令说明 (Commands)

- `clawguard audit config`
  - CN：审计 `~/.openclaw/config.json` 和当前目录下的 `claw.config.json`，检测网关暴露、明文密钥和高权限运行等风险。
  - EN：Audits OpenClaw config and credentials for common misconfigurations and plaintext secrets.

- `clawguard audit skills`
  - CN：扫描 `~/.openclaw/skills/` 下的所有 `.js` / `.ts` 文件，使用 AST + 规则库识别 RCE / 动态执行 / 数据外传 / 混淆代码等模式。
  - EN：Performs AST-based static analysis on all Skills under `~/.openclaw/skills/`, matching against a configurable signature library.

- `clawguard fix:auto`
  - CN：自动生成 `.env.example`，并在用户确认后修复 `host: "0.0.0.0"` 为 `127.0.0.1`（先创建带时间戳的 `.bak` 备份）。
  - EN: Generates `.env.example` from detected secrets and interactively fixes `host: "0.0.0.0"` to `127.0.0.1` with safe backups.

---

## 规则引擎 (Rule Engine)

ClawGuard 使用一个 JSON 规则文件来描述恶意特征：

- 文件：`src/rules/signatures.json`
- 字段：
  - `id`: Unique rule ID (e.g. `RCE-001`).
  - `severity`: `"CRITICAL" | "HIGH" | "MEDIUM"`.
  - `type`: `"function_call" | "entropy"`（未来可扩展 `"pattern"`）。
  - `pattern`: Pattern definition interpreted by the AST scanner.
  - `description`: Human-readable explanation.
  - `remediation`: Suggested remediation steps.

你可以通过提交 PR 增加或调整规则，以覆盖更多的危险模式或减少误报。

You are welcome to extend the signature library via PRs to cover more dangerous patterns or reduce false positives.

---

## 安全声明 (Security Disclaimer)

- CN：ClawGuard 是一个安全辅助工具，不能保证发现所有漏洞或风险。扫描结果需要结合上下文进行人工审查和验证。  
- EN: ClawGuard is a security assistance tool. It **cannot guarantee** to find all vulnerabilities or risks. Findings should be reviewed and validated in context.

如你在 ClawGuard 自身发现安全问题，请参见 `SECURITY.md` 中的“报告安全漏洞”部分。

If you discover a vulnerability in ClawGuard itself, please follow the disclosure process described in `SECURITY.md`.

---

## 贡献指南 (Contributing)

- CN：
  - 欢迎提交 Issue / PR，尤其是：
    - 新的 AST 规则和特征库扩展。
    - 对现有规则的误报优化。
    - 新的审计维度（网络暴露面、依赖 CVE 等）。
- EN:
  - Contributions are welcome, especially:
    - New AST rules and signature extensions.
    - False-positive tuning for existing rules.
    - New audit dimensions (network exposure, dependency CVEs, etc.).

在提交前请确保：

- 通过 `npm run build`。
- 尽量为新的规则或检测逻辑增加简单的测试样例（可以放在 `test-data/`）。

---

## 路线图 (Roadmap)

高层规划请参见 `ROADMAP.md`。

For the high-level roadmap, see `ROADMAP.md`.

