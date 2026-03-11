import fs from "fs/promises";
import path from "path";
import os from "os";
import JSON5 from "json5";
import readline from "readline";

interface HostFixCandidate {
  filePath: string;
  raw: string;
  parsed: any;
}

function getConfigPaths(): string[] {
  const homeDir = os.homedir();
  const paths: string[] = [];

  if (homeDir) {
    paths.push(path.join(homeDir, ".openclaw", "config.json"));
  }

  paths.push(path.join(process.cwd(), "claw.config.json"));

  return paths;
}

async function loadHostFixCandidates(): Promise<HostFixCandidate[]> {
  const candidates: HostFixCandidate[] = [];

  for (const filePath of getConfigPaths()) {
    let raw: string;
    try {
      raw = await fs.readFile(filePath, "utf8");
    } catch (error: any) {
      if (error && (error.code === "ENOENT" || error.code === "ENOTDIR")) {
        continue;
      }
      throw error;
    }

    let parsed: any;
    try {
      parsed = JSON5.parse(raw);
    } catch {
      continue;
    }

    let hasHostZero = false;

    const visit = (value: any): void => {
      if (Array.isArray(value)) {
        value.forEach(visit);
        return;
      }
      if (value && typeof value === "object") {
        for (const [key, v] of Object.entries(value)) {
          if (key === "host" && v === "0.0.0.0") {
            hasHostZero = true;
          }
          visit(v);
        }
      }
    };

    visit(parsed);

    if (hasHostZero) {
      candidates.push({ filePath, raw, parsed });
    }
  }

  return candidates;
}

async function applyHostFix(candidate: HostFixCandidate): Promise<string> {
  const backupSuffix = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = `${candidate.filePath}.${backupSuffix}.bak`;

  await fs.copyFile(candidate.filePath, backupPath);

  const updateHosts = (value: any): void => {
    if (Array.isArray(value)) {
      value.forEach(updateHosts);
      return;
    }
    if (value && typeof value === "object") {
      for (const [key, v] of Object.entries(value)) {
        if (key === "host" && v === "0.0.0.0") {
          (value as any)[key] = "127.0.0.1";
        } else {
          updateHosts(v);
        }
      }
    }
  };

  updateHosts(candidate.parsed);

  const newContent = `${JSON.stringify(candidate.parsed, null, 2)}\n`;
  await fs.writeFile(candidate.filePath, newContent, "utf8");

  return backupPath;
}

const SECRET_KEY_PATTERNS: RegExp[] = [
  /password/i,
  /secret/i,
  /token/i,
  /api[-_]?key/i,
];

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

async function generateEnvExampleFromConfigs(): Promise<void> {
  const envKeys = new Set<string>();

  for (const filePath of getConfigPaths()) {
    let raw: string;
    try {
      raw = await fs.readFile(filePath, "utf8");
    } catch (error: any) {
      if (error && (error.code === "ENOENT" || error.code === "ENOTDIR")) {
        continue;
      }
      throw error;
    }

    let parsed: any;
    try {
      parsed = JSON5.parse(raw);
    } catch {
      continue;
    }

    walkConfig(parsed, ({ keyPath, key, value }) => {
      if (typeof value !== "string" || !key) {
        return;
      }
      if (!SECRET_KEY_PATTERNS.some((re) => re.test(key))) {
        return;
      }
      if (!value.trim()) {
        return;
      }

      const pathSegments = keyPath.split(/[.\[\]]/).filter(Boolean);
      const envKey =
        "OPENCLAW_" +
        pathSegments
          .map((segment) => segment.replace(/[^A-Za-z0-9]+/g, "_"))
          .join("_")
          .toUpperCase();

      envKeys.add(envKey);
    });
  }

  if (envKeys.size === 0) {
    return;
  }

  const envExamplePath = path.join(process.cwd(), ".env.example");

  let exists = false;
  try {
    await fs.access(envExamplePath);
    exists = true;
  } catch {
    exists = false;
  }

  if (exists) {
    console.log(
      `.env.example 已存在，检测到疑似明文密钥，但不会覆盖现有文件。请手动将以下环境变量加入到 .env.example 中：`
    );
    for (const key of envKeys) {
      console.log(`- ${key}=<REPLACE_ME>`);
    }
    return;
  }

  const lines: string[] = [];
  lines.push("# 由 ClawGuard 自动生成的 .env.example 模板");
  lines.push(
    "# 请将以下占位值替换为真实密钥，并在配置中改为从环境变量读取（例如 process.env.MY_KEY）。"
  );
  lines.push("");

  for (const key of envKeys) {
    lines.push(`${key}=<REPLACE_ME>`);
  }
  lines.push("");

  await fs.writeFile(envExamplePath, lines.join("\n"), "utf8");

  console.log(`已生成 .env.example 模板：${envExamplePath}`);
}

async function askYesNo(question: string, defaultYes = true): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const suffix = defaultYes ? " [Y/n] " : " [y/N] ";

  const answer: string = await new Promise((resolve) => {
    rl.question(question + suffix, (input) => resolve(input));
  });

  rl.close();

  const normalized = answer.trim().toLowerCase();
  if (!normalized) {
    return defaultYes;
  }
  return normalized === "y" || normalized === "yes";
}

export async function runConfigFixInteractive(): Promise<void> {
  await generateEnvExampleFromConfigs();

  const candidates = await loadHostFixCandidates();

  if (candidates.length === 0) {
    console.log("未在配置文件中找到 host: \"0.0.0.0\"，无需修复。");
    return;
  }

  console.log("检测到以下配置文件包含 host: \"0.0.0.0\"：");
  for (const c of candidates) {
    console.log(`- ${c.filePath}`);
  }

  const confirmed = await askYesNo(
    "是否将上述配置文件中的 host: \"0.0.0.0\" 自动修改为 127.0.0.1（修改前将创建带时间戳的 .bak 备份）？",
    true
  );

  if (!confirmed) {
    console.log("已取消自动修复。");
    return;
  }

  for (const c of candidates) {
    try {
      const backupPath = await applyHostFix(c);
      console.log(
        `已修复 ${c.filePath}（备份文件：${backupPath}）。`
      );
    } catch (error) {
      console.error(
        `修复配置文件 ${c.filePath} 时出错：`,
        error
      );
    }
  }
}

