import fs from "fs/promises";
import path from "path";
import os from "os";
import JSON5 from "json5";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface ConfigFinding {
  level: RiskLevel;
  title: string;
  detail?: string;
  recommendation?: string;
  source: string;
}

export interface ConfigAuditResult {
  findings: ConfigFinding[];
  scannedFiles: string[];
}

const SECRET_VALUE_PATTERNS: RegExp[] = [
  /sk-[A-Za-z0-9]{16,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
];

const SECRET_KEY_PATTERNS: RegExp[] = [
  /password/i,
  /secret/i,
  /token/i,
  /api[-_]?key/i,
];

function getCandidateConfigPaths(): string[] {
  const homeDir = os.homedir();
  const paths: string[] = [];

  if (homeDir) {
    paths.push(path.join(homeDir, ".openclaw", "config.json"));
  }

  paths.push(path.join(process.cwd(), "claw.config.json"));

  return paths;
}

async function readFileIfExists(filePath: string): Promise<string | null> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return content;
  } catch (error: any) {
    if (error && (error.code === "ENOENT" || error.code === "ENOTDIR")) {
      return null;
    }
    throw error;
  }
}

function parseJson5Safe(raw: string, source: string): any | null {
  try {
    return JSON5.parse(raw);
  } catch {
    return null;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function walkConfig(
  value: unknown,
  visitor: (context: { keyPath: string; key?: string; value: unknown }) => void,
  parentPath = ""
): void {
  visitor({ keyPath: parentPath, value, key: undefined });

  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      walkConfig(
        item,
        visitor,
        parentPath ? `${parentPath}[${index}]` : `[${index}]`
      )
    );
    return;
  }

  if (isPlainObject(value)) {
    Object.entries(value).forEach(([key, child]) => {
      const nextPath = parentPath ? `${parentPath}.${key}` : key;
      visitor({ keyPath: nextPath, key, value: child });
      walkConfig(child, visitor, nextPath);
    });
  }
}

function detectGatewayExposure(
  config: any,
  source: string
): ConfigFinding[] {
  const findings: ConfigFinding[] = [];

  walkConfig(config, ({ keyPath, key, value }) => {
    if (typeof value !== "string") {
      return;
    }

    if (value.trim() === "0.0.0.0") {
      const keyHint = key ?? keyPath;
      const probableGateway =
        /gateway|server|bind|host|listen/i.test(keyHint ?? "") || false;

      findings.push({
        level: "CRITICAL",
        title: "可能的 Gateway 绑定在 0.0.0.0（公网暴露风险）",
        detail: `字段路径：${keyPath}，值：${value}`,
        recommendation: probableGateway
          ? "将 Gateway / Server 绑定地址修改为 127.0.0.1 或内网 IP，并通过反向代理等方式进行受控暴露。"
          : "配置中存在绑定 0.0.0.0 的字段，请确认该字段是否为 Gateway / Server 监听地址，如是请限制为 127.0.0.1 或内网 IP。",
        source,
      });
    }
  });

  return findings;
}

function detectPlaintextSecretsInRaw(
  raw: string,
  source: string
): ConfigFinding[] {
  const findings: ConfigFinding[] = [];

  SECRET_VALUE_PATTERNS.forEach((pattern) => {
    const matches = raw.match(pattern);
    if (matches) {
      findings.push({
        level: "HIGH",
        title: "疑似硬编码的 API Key / 密钥值",
        detail: `在原始配置文本中匹配到模式：${pattern.toString()}`,
        recommendation:
          "避免在配置文件中硬编码密钥，建议迁移到环境变量，并在配置中引用环境变量。",
        source,
      });
    }
  });

  const passwordPattern = /password\s*[:=]\s*["']([^"']+)["']/gi;
  if (passwordPattern.test(raw)) {
    findings.push({
      level: "HIGH",
      title: "疑似硬编码的密码字段",
      detail:
        "在原始配置文本中检测到 password 字段携带明文密码。",
      recommendation:
        "将密码从配置文件中移除，改为使用环境变量或安全凭证管理服务。",
      source,
    });
  }

  return findings;
}

function detectPlaintextSecretsInParsed(
  config: any,
  source: string
): ConfigFinding[] {
  const findings: ConfigFinding[] = [];

  walkConfig(config, ({ keyPath, key, value }) => {
    if (typeof value !== "string" || !key) {
      return;
    }

    if (!SECRET_KEY_PATTERNS.some((re) => re.test(key))) {
      return;
    }

    if (!value.trim()) {
      return;
    }

    findings.push({
      level: "HIGH",
      title: "疑似明文存储的敏感凭证",
      detail: `字段路径：${keyPath}，键名：${key}`,
      recommendation:
        "避免在配置中直接存储敏感凭证，建议改为从环境变量读取或使用安全凭证存储服务。",
      source,
    });
  });

  return findings;
}

function detectProcessPrivilege(): ConfigFinding | null {
  try {
    if (typeof (process as any).getuid === "function") {
      const uid = (process as any).getuid();
      if (uid === 0) {
        return {
          level: "MEDIUM",
          title: "当前以 root 用户运行 OpenClaw 相关进程",
          detail:
            "以 root 身份运行会放大任何 RCE / 逃逸漏洞的危害范围。",
          recommendation:
            "建议为 OpenClaw 创建专用的非特权系统用户，并使用该用户运行网关与相关服务。",
          source: "process",
        };
      }
    } else if (process.platform === "win32") {
      return {
        level: "LOW",
        title: "Windows 平台无法自动判断是否以管理员身份运行",
        detail:
          "在 Windows 上缺乏可靠的无权限自检手段来确认当前进程是否以管理员运行。",
        recommendation:
          "请确保不要以管理员身份运行 OpenClaw 网关进程，以降低被利用时对系统的影响范围。",
        source: "process",
      };
    }
  } catch {
    // ignore detection errors
  }
  return null;
}

export async function runConfigAudit(): Promise<ConfigAuditResult> {
  const findings: ConfigFinding[] = [];
  const scannedFiles: string[] = [];

  const candidatePaths = getCandidateConfigPaths();

  for (const configPath of candidatePaths) {
    const raw = await readFileIfExists(configPath);
    if (raw == null) {
      continue;
    }

    scannedFiles.push(configPath);
    const sourceLabel = configPath;

    findings.push(...detectPlaintextSecretsInRaw(raw, sourceLabel));

    const parsed = parseJson5Safe(raw, sourceLabel);
    if (!parsed) {
      continue;
    }

    findings.push(...detectGatewayExposure(parsed, sourceLabel));
    findings.push(...detectPlaintextSecretsInParsed(parsed, sourceLabel));
  }

  const privilegeFinding = detectProcessPrivilege();
  if (privilegeFinding) {
    findings.push(privilegeFinding);
  }

  return { findings, scannedFiles };
}

