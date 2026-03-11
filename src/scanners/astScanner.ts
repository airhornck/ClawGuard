import fs from "fs/promises";
import path from "path";
import os from "os";
import { parse } from "@babel/parser";
import traverse from "@babel/traverse";
import type { File, StringLiteral, TemplateLiteral, CallExpression } from "@babel/types";
import { shannonEntropy } from "../utils/entropy.js";
import signatures from "../rules/signatures.json" assert { type: "json" };

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM";

export interface AstFinding {
  id: string;
  severity: Severity;
  filePath: string;
  line: number;
  column: number;
  description: string;
  remediation: string;
  snippet: string;
}

export interface AstAuditResult {
  findings: AstFinding[];
  scannedFiles: string[];
}

interface FunctionCallPattern {
  module?: string;
  methods?: string[];
  globalIdentifiers?: string[];
  dangerousArgPattern?: string;
  httpClients?: string[];
  allowedDomains?: string[];
}

interface EntropyPattern {
  minLength: number;
  minEntropy: number;
}

interface SignatureRule {
  id: string;
  severity: Severity;
  type: "function_call" | "pattern" | "entropy";
  pattern: FunctionCallPattern | EntropyPattern | Record<string, unknown>;
  description: string;
  remediation: string;
}

const RULES = signatures as SignatureRule[];

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

function isEntropyRule(rule: SignatureRule): rule is SignatureRule & { pattern: EntropyPattern } {
  return rule.type === "entropy";
}

function isFunctionCallRule(
  rule: SignatureRule
): rule is SignatureRule & { pattern: FunctionCallPattern } {
  return rule.type === "function_call";
}

function getSourceSnippet(source: string, line: number, column: number): string {
  const lines = source.split(/\r?\n/);
  const idx = line - 1;
  if (idx < 0 || idx >= lines.length) {
    return "";
  }
  const codeLine = lines[idx];
  const pointerLine =
    column > 0 ? `${" ".repeat(Math.max(0, column - 1))}^` : "";
  return `${codeLine}\n${pointerLine}`;
}

function matchesChildProcessMethod(
  calleeModule: string | null,
  calleeName: string | null,
  pattern: FunctionCallPattern
): boolean {
  if (!pattern.module || !pattern.methods) return false;
  if (!calleeName) return false;
  if (calleeModule !== pattern.module) return false;
  return pattern.methods.includes(calleeName);
}

function matchesGlobalIdentifier(
  calleeName: string | null,
  pattern: FunctionCallPattern
): boolean {
  if (!pattern.globalIdentifiers || !calleeName) return false;
  return pattern.globalIdentifiers.includes(calleeName);
}

function extractUrlFromArgs(node: CallExpression): string | null {
  if (!node.arguments.length) return null;
  const first = node.arguments[0];
  if (first.type === "StringLiteral") {
    return first.value;
  }
  if (first.type === "TemplateLiteral" && first.quasis.length === 1) {
    return first.quasis[0].value.cooked ?? null;
  }
  return null;
}

function isPostRequest(node: CallExpression): boolean {
  // axios.post(url, data, config?)
  if (
    node.callee.type === "MemberExpression" &&
    node.callee.property.type === "Identifier" &&
    node.callee.property.name.toLowerCase() === "post"
  ) {
    return true;
  }

  // fetch(url, { method: 'POST', ... })
  if (
    node.callee.type === "Identifier" &&
    node.callee.name === "fetch" &&
    node.arguments.length >= 2
  ) {
    const second = node.arguments[1];
    if (second.type === "ObjectExpression") {
      for (const prop of second.properties) {
        if (
          prop.type === "ObjectProperty" &&
          prop.key.type === "Identifier" &&
          prop.key.name === "method"
        ) {
          if (
            prop.value.type === "StringLiteral" &&
            prop.value.value.toUpperCase() === "POST"
          ) {
            return true;
          }
        }
      }
    }
  }

  return false;
}

function isAllowedDomain(url: string, allowedDomains: string[]): boolean {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    return allowedDomains.some((d) => host === d.toLowerCase());
  } catch {
    return false;
  }
}

export async function runAstSkillAudit(): Promise<AstAuditResult> {
  const findings: AstFinding[] = [];
  const scannedFiles: string[] = [];

  const homeDir = os.homedir();
  const skillsRoot = homeDir
    ? path.join(homeDir, ".openclaw", "skills")
    : null;

  if (!skillsRoot) {
    return { findings, scannedFiles };
  }

  const files = await collectSkillFiles(skillsRoot);

  for (const filePath of files) {
    let source: string;
    try {
      source = await fs.readFile(filePath, "utf8");
    } catch {
      continue;
    }

    scannedFiles.push(filePath);

    let ast: File;
    try {
      ast = parse(source, {
        sourceType: "unambiguous",
        plugins: ["typescript", "jsx"],
      }) as unknown as File;
    } catch {
      continue;
    }

    traverse(ast, {
      StringLiteral(path) {
        const node = path.node as StringLiteral;
        const value = node.value;

        for (const rule of RULES) {
          if (!isEntropyRule(rule)) continue;
          const pattern = rule.pattern;
          if (value.length < pattern.minLength) continue;
          const entropy = shannonEntropy(value);
          if (entropy < pattern.minEntropy) continue;

          const loc = node.loc?.start ?? { line: 0, column: 0 };
          findings.push({
            id: rule.id,
            severity: rule.severity,
            filePath,
            line: loc.line,
            column: loc.column + 1,
            description: rule.description,
            remediation: rule.remediation,
            snippet: getSourceSnippet(source, loc.line, loc.column + 1),
          });
        }
      },

      TemplateLiteral(path) {
        const node = path.node as TemplateLiteral;
        const text = node.quasis.map((q) => q.value.cooked ?? "").join("");
        if (!text) return;

        for (const rule of RULES) {
          if (!isEntropyRule(rule)) continue;
          const pattern = rule.pattern;
          if (text.length < pattern.minLength) continue;
          const entropy = shannonEntropy(text);
          if (entropy < pattern.minEntropy) continue;

          const loc = node.loc?.start ?? { line: 0, column: 0 };
          findings.push({
            id: rule.id,
            severity: rule.severity,
            filePath,
            line: loc.line,
            column: loc.column + 1,
            description: rule.description,
            remediation: rule.remediation,
            snippet: getSourceSnippet(source, loc.line, loc.column + 1),
          });
        }
      },

      CallExpression(path) {
        const node = path.node as CallExpression;

        const callee = node.callee;
        let calleeName: string | null = null;
        let calleeModule: string | null = null;
        let httpClientKey: string | null = null;

        if (callee.type === "Identifier") {
          calleeName = callee.name;
        } else if (callee.type === "MemberExpression") {
          const object = callee.object;
          const property = callee.property;
          if (property.type === "Identifier") {
            const propName = property.name;
            if (object.type === "Identifier") {
              calleeModule = object.name;
              calleeName = propName;
              httpClientKey = `${calleeModule}.${calleeName}`;
            }
          }
        }

        for (const rule of RULES) {
          if (!isFunctionCallRule(rule)) continue;
          const pattern = rule.pattern;

          let matched = false;

          if (matchesChildProcessMethod(calleeModule, calleeName, pattern)) {
            matched = true;
          }

          if (!matched && matchesGlobalIdentifier(calleeName, pattern)) {
            matched = true;
          }

          if (
            !matched &&
            pattern.httpClients &&
            (httpClientKey || calleeName)
          ) {
            const key = httpClientKey ?? calleeName!;
            const isClient = pattern.httpClients.includes(key);
            if (isClient && isPostRequest(node)) {
              const url = extractUrlFromArgs(node);
              if (
                url &&
                pattern.allowedDomains &&
                !isAllowedDomain(url, pattern.allowedDomains)
              ) {
                matched = true;
              }
            }
          }

          if (!matched) continue;

          if (pattern.dangerousArgPattern && node.arguments.length) {
            const first = node.arguments[0];
            const regex = new RegExp(pattern.dangerousArgPattern);
            let argText: string | null = null;
            if (first.type === "StringLiteral") {
              argText = first.value;
            } else if (
              first.type === "TemplateLiteral" &&
              first.quasis.length === 1
            ) {
              argText = first.quasis[0].value.cooked ?? null;
            }
            if (argText && !regex.test(argText)) {
              // still worth a lower-priority review, but current rule assumes explicit pattern
              continue;
            }
          }

          const loc = node.loc?.start ?? { line: 0, column: 0 };
          findings.push({
            id: rule.id,
            severity: rule.severity,
            filePath,
            line: loc.line,
            column: loc.column + 1,
            description: rule.description,
            remediation: rule.remediation,
            snippet: getSourceSnippet(source, loc.line, loc.column + 1),
          });
        }
      },
    });
  }

  return { findings, scannedFiles };
}

