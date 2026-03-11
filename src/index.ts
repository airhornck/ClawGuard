#!/usr/bin/env node

import { Command } from "commander";
import * as chalk from "chalk";
import { runConfigAudit } from "./scanners/configScanner.js";
import { runAstSkillAudit } from "./scanners/astScanner.js";
import { runConfigFixInteractive } from "./remediations/configFixer.js";
import Table from "cli-table3";

const program = new Command();

program
  .name("clawguard")
  .description("ClawGuard - OpenClaw 安全审计与加固 CLI 工具")
  .version("0.1.0");

const audit = program.command("audit").description("运行安全审计");

audit
  .command("config")
  .description("审计 OpenClaw 配置与凭证风险")
  .action(async () => {
    try {
      const result = await runConfigAudit();

      if (result.findings.length === 0) {
        console.log(chalk.green("✓ 未发现配置与凭证方面的明显风险。"));
        return;
      }

      const table = new Table({
        head: ["风险等级", "文件路径", "问题描述", "建议操作"],
        wordWrap: true,
      });

      for (const finding of result.findings) {
        const baseLevel =
          finding.level === "CRITICAL"
            ? "CRITICAL"
            : finding.level === "HIGH"
            ? "HIGH"
            : finding.level === "MEDIUM"
            ? "MEDIUM"
            : "LOW";

        const levelLabel =
          baseLevel === "CRITICAL"
            ? chalk.red("🔴 CRITICAL")
            : baseLevel === "HIGH"
            ? chalk.hex("#ff8c00")("🟠 HIGH")
            : baseLevel === "MEDIUM"
            ? chalk.yellow("🟡 MEDIUM")
            : chalk.blue("🟢 LOW");

        table.push([
          levelLabel,
          finding.source,
          finding.title,
          finding.recommendation ?? "",
        ]);
      }

      console.log(chalk.bold("配置与凭证审计结果："));
      console.log(table.toString());
    } catch (error) {
      console.error(chalk.red("运行配置审计时出错："), error);
      process.exitCode = 1;
    }
  });

audit
  .command("skills")
  .description("审计已安装的 OpenClaw Skills 供应链风险（AST 深度扫描）")
  .action(async () => {
    try {
      const result = await runAstSkillAudit();

      if (result.findings.length === 0) {
        console.log(
          chalk.green("✓ 未在 Skills 目录中发现已知的高危代码模式。")
        );
        return;
      }

      const table = new Table({
        head: ["规则 ID", "风险等级", "位置", "问题描述"],
        wordWrap: true,
      });

      for (const finding of result.findings) {
        const levelLabel =
          finding.severity === "CRITICAL"
            ? chalk.red("🔴 CRITICAL")
            : finding.severity === "HIGH"
            ? chalk.hex("#ff8c00")("🟠 HIGH")
            : chalk.yellow("🟡 MEDIUM");

        const location = `${finding.filePath}:${finding.line}:${finding.column}`;

        table.push([
          finding.id,
          levelLabel,
          location,
          `${finding.description}\n${chalk.gray(
            finding.remediation
          )}\n\n${finding.snippet}`,
        ]);
      }

      console.log(chalk.bold("Skills AST 静态审计结果："));
      console.log(table.toString());
    } catch (error) {
      console.error(chalk.red("运行 Skills AST 审计时出错："), error);
      process.exitCode = 1;
    }
  });

program
  .command("fix:auto")
  .description("自动修复常见配置风险（如 host: \"0.0.0.0\"）")
  .action(async () => {
    try {
      await runConfigFixInteractive();
    } catch (error) {
      console.error(chalk.red("运行自动修复向导时出错："), error);
      process.exitCode = 1;
    }
  });

program
  .command("report")
  .description("生成安全报告（占位，MVP 中将实现）")
  .action(() => {
    console.log(
      chalk.yellow("report 功能将在后续步骤中实现，目前仅提供命令占位。")
    );
  });

program.parseAsync(process.argv);

