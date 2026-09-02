/**
 * Smoke test -- tool shapes, extension registration, and the skill manifest.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { SshSetupTool } from "../src/tools/ssh-setup.ts";
import { SshStatusTool } from "../src/tools/ssh-status.ts";
import { SshProfileTool } from "../src/tools/ssh-profile.ts";
import { SshExecTool } from "../src/tools/ssh-exec.ts";
import { SshListTool } from "../src/tools/ssh-list.ts";
import { SshUploadTool } from "../src/tools/ssh-upload.ts";
import { SshDownloadTool } from "../src/tools/ssh-download.ts";
import { SshKeygenTool } from "../src/tools/ssh-keygen.ts";
import { SshAuthorizeTool } from "../src/tools/ssh-authorize.ts";
import { SshDoctorTool } from "../src/tools/ssh-doctor.ts";

const allTools = [
  SshSetupTool,
  SshStatusTool,
  SshProfileTool,
  SshExecTool,
  SshListTool,
  SshUploadTool,
  SshDownloadTool,
  SshKeygenTool,
  SshAuthorizeTool,
  SshDoctorTool,
];

describe("Tool structure smoke test", () => {
  it("has exactly 10 tools", () => {
    assert.strictEqual(allTools.length, 10);
  });

  for (const tool of allTools) {
    it(`${tool.name} has required fields`, () => {
      assert.ok(tool.name);
      assert.ok(tool.label);
      assert.ok(tool.description);
      assert.ok(tool.parameters !== undefined);
      assert.strictEqual(typeof tool.execute, "function");
    });
  }

  it("all tool names are unique", () => {
    const names = allTools.map((tool) => tool.name);
    assert.strictEqual(new Set(names).size, names.length);
  });

  it("all tool names follow the ssh_ prefix convention", () => {
    for (const tool of allTools) {
      assert.ok(/^ssh_/.test(tool.name), `${tool.name} lacks the prefix`);
    }
  });

  it("every description explains when to use the tool", () => {
    for (const tool of allTools) {
      assert.ok(tool.description.length > 40, `${tool.name} is too terse`);
    }
  });
});

describe("Extension entry point", () => {
  it("registers every tool and command without errors", async () => {
    const registered: string[] = [];
    const commands: string[] = [];
    const mod = await import("../index.ts");

    mod.default({
      registerTool: (tool: { name: string }) => registered.push(tool.name),
      registerCommand: (name: string) => commands.push(name),
      sendUserMessage: () => {},
    } as any);

    assert.deepStrictEqual(registered.sort(), allTools.map((t) => t.name).sort());
    assert.deepStrictEqual(commands.sort(), ["ssh", "ssh-key"]);
  });
});

describe("Skills", () => {
  it("ships a SKILL.md with valid frontmatter for every skill", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const skillsDir = path.join(import.meta.dirname, "..", "skills");
    const names = fs
      .readdirSync(skillsDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);

    assert.ok(names.length >= 1);

    for (const name of names) {
      const file = path.join(skillsDir, name, "SKILL.md");
      assert.ok(fs.existsSync(file), `${name} has no SKILL.md`);

      const content = fs.readFileSync(file, "utf-8");
      assert.ok(content.startsWith("---\n"), `${name} has no frontmatter`);

      const frontmatter = content.slice(4, content.indexOf("\n---", 4));
      const declaredName = /^name:\s*(.+)$/m.exec(frontmatter)?.[1]?.trim();
      const description = /^description:\s*(.+)$/m.exec(frontmatter)?.[1]?.trim();

      assert.strictEqual(declaredName, name, `${name}: frontmatter name mismatch`);
      assert.match(declaredName!, /^[a-z0-9-]{1,64}$/);
      assert.ok(description && description.length <= 1024);
    }
  });
});

describe("Portability", () => {
  it("never shells out, so Windows behaves like the rest", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");

    const walk = (dir: string): string[] =>
      fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
        const full = path.join(dir, entry.name);
        return entry.isDirectory() ? walk(full) : full.endsWith(".ts") ? [full] : [];
      });

    const sources = [
      ...walk(path.join(import.meta.dirname, "..", "src")),
      path.join(import.meta.dirname, "..", "index.ts"),
    ];

    for (const file of sources) {
      const content = fs.readFileSync(file, "utf-8");
      assert.ok(
        !/from "node:child_process"/.test(content),
        `${path.basename(file)} spawns a process; keys and SSH must stay in process`,
      );
    }
  });
});
