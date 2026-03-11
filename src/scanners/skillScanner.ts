import fs from "fs/promises";
import path from "path";
import os from "os";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface SkillFinding {
  level: RiskLevel;
  filePath: string;
  description: string;
  recommendation?: string;
}

export interface SkillAuditResult {
  findings: SkillFinding[];
  scannedFiles: string[];
}

const EXEC_PATTERN = /child_process\s*\.\s*exec\s*\(/;
const SPAWN_PATTERN = /child_process\s*\.\s*spawn\s*\(/;
const EVAL_PATTERN = /\beval\s*\(/;
const FUNCTION_CTOR_PATTERN = /\bnew\s+Function\s*\(|\bFunction\s*\(/;

async function collectSkillFiles(root: string): Promise<string[]> {
  const result: string[] = [];

  async function walk(current: string): Promise<void> {
    let entries;
    try {
      entries = await fs.readdir(current, { withFileTypes: true });
    } catch (error: any) {
      if (error && (error.code === "ENOENT" || error.code === "ENOTDIR")) {
        return;
      }
      throw error;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        if (fullPath.endsWith(".js") || fullPath.endsWith(".ts")) {
          result.push(fullPath);
        }
      }
    }
  }

  await walk(root);
  return result;
}

export async function runSkillAudit(): Promise<SkillAuditResult> {
  const findings: SkillFinding[] = [];
  const scannedFiles: string[] = [];

  const homeDir = os.homedir();
  const skillsRoot = homeDir
    ? path.join(homeDir, ".openclaw", "skills")
    : null;

  if (!skillsRoot) {
    return { findings, scannedFiles };
  }

  const skillFiles = await collectSkillFiles(skillsRoot);

  for (const filePath of skillFiles) {
    let content: string;
    try {
      content = await fs.readFile(filePath, "utf8");
    } catch (error: any) {
      continue;
    }

    scannedFiles.push(filePath);

    if (EXEC_PATTERN.test(content)) {
      findings.push({
        level: "CRITICAL",
        filePath,
        description:
          "检测到使用 child_process.exec 调用，可能导致远程命令执行（RCE）风险。",
        recommendation:
          "尽量避免在 Skill 中直接使用 child_process.exec。如确需调用外部命令，请增加严格的参数白名单与沙箱控制。",
      });
    }

    if (SPAWN_PATTERN.test(content)) {
      findings.push({
        level: "CRITICAL",
        filePath,
        description:
          "检测到使用 child_process.spawn 调用，可能导致远程命令执行（RCE）风险。",
        recommendation:
          "避免在 Skill 中直接使用 child_process.spawn；如必须使用，请限制可执行命令并使用严格的参数白名单。",
      });
    }

    if (EVAL_PATTERN.test(content)) {
      findings.push({
        level: "CRITICAL",
        filePath,
        description:
          "检测到使用 eval 调用，可能导致任意代码执行风险。",
        recommendation:
          "避免在 Skill 中使用 eval；改用安全的解析或映射逻辑，禁止执行来自外部输入的代码片段。",
      });
    }

    if (FUNCTION_CTOR_PATTERN.test(content)) {
      findings.push({
        level: "CRITICAL",
        filePath,
        description:
          "检测到使用 Function 构造函数（如 new Function(...)），可能导致任意代码执行风险。",
        recommendation:
          "避免在 Skill 中使用 Function 构造函数；如需动态逻辑，请使用配置驱动的分支或受控的脚本引擎。",
      });
    }
  }

  return { findings, scannedFiles };
}

