## ClawGuard - OpenClaw Security Audit CLI

### Overview

ClawGuard is a lightweight security audit and hardening CLI for the OpenClaw ecosystem.  
It helps users quickly identify and mitigate:

- **Configuration risks**: public gateway exposure, plaintext secrets, debug mode in production, etc.
- **Supply-chain risks**: malicious or vulnerable Skill code (RCE, data exfiltration, obfuscation, etc.).
- **Privilege risks**: running as root/admin and amplifying the blast radius of any exploit.

The current version focuses on local static analysis (SAST), using AST + a signature library to scan OpenClaw Skills, and provides basic auto-fix capabilities.

### Features

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

## Installation & Usage

### 1. From Source

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

### 2. Prebuilt Binary (no Node required)

> Note: Binary availability depends on which artifacts are published in Releases.

1. Download the executable for your platform from the Releases page (e.g. `clawguard-win-x64.exe`).
2. Place it in any directory (ideally one included in `PATH`).
3. Run it from your terminal:

```bash
clawguard audit config
clawguard audit skills
clawguard fix:auto
```

On Windows, you can run it directly in PowerShell:

```powershell
.\clawguard-win-x64.exe audit skills
```

---

## Commands

- `clawguard audit config`
  - Audits `~/.openclaw/config.json` and `./claw.config.json` to detect gateway exposure, plaintext secrets, and privilege-related risks.

- `clawguard audit skills`
  - Scans all `.js` / `.ts` files under `~/.openclaw/skills/` using AST + a rule library to detect RCE / dynamic code execution / data exfiltration / obfuscation patterns.

- `clawguard fix:auto`
  - Generates a `.env.example` file from detected secrets, and (after user confirmation) changes `host: "0.0.0.0"` to `127.0.0.1` with timestamped `.bak` backups.

---

## Rule Engine

ClawGuard uses a JSON-based signature file to describe suspicious and malicious patterns:

- File: `src/rules/signatures.json`
- Fields:
  - `id`: Unique rule ID (e.g. `RCE-001`).
  - `severity`: `"CRITICAL" | "HIGH" | "MEDIUM"`.
  - `type`: `"function_call" | "entropy"` (future: `"pattern"`).
  - `pattern`: Pattern definition interpreted by the AST scanner.
  - `description`: Human-readable explanation.
  - `remediation`: Suggested remediation steps.

You are welcome to extend the signature library via PRs to cover more dangerous patterns or reduce false positives.

---

## Security Disclaimer

ClawGuard is a security assistance tool. It **cannot guarantee** to find all vulnerabilities or risks.  
Findings should always be reviewed and validated in context before taking action.

If you discover a vulnerability in ClawGuard itself, please follow the disclosure process described in `SECURITY.md`.

---

## Contributing

Contributions are welcome, especially:

- New AST rules and signature extensions.
- False-positive tuning for existing rules.
- New audit dimensions (network exposure, dependency CVEs, etc.).

Before submitting a PR, please:

- Run `npm run build`.
- Add or update simple test samples under `test-data/` when you introduce new rules or detection logic.

---

## Roadmap

For the high-level roadmap and planned features, see `ROADMAP.md`.


