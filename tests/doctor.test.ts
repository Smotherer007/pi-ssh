import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { formatChecks, runChecks } from "../src/doctor.ts";

describe("doctor", () => {
  const checks = runChecks();

  it("reports on the things that actually matter", () => {
    const names = checks.map((check) => check.name);
    for (const expected of ["Node", "SSH implementation", "Key generation", "known_hosts"]) {
      assert.ok(names.includes(expected), `${expected} is not checked`);
    }
  });

  it("states that no SSH binary is required", () => {
    const ssh = checks.find((check) => check.name === "SSH implementation")!;
    assert.strictEqual(ssh.status, "ok");
    assert.match(ssh.detail, /no ssh binary needed/);
  });

  it("states that ssh-keygen is not required", () => {
    const keys = checks.find((check) => check.name === "Key generation")!;
    assert.strictEqual(keys.status, "ok");
    assert.match(keys.detail, /not required/);
  });

  it("treats a missing ssh command as optional, not a problem", () => {
    const client = checks.find((check) => check.name.startsWith("OpenSSH client"))!;
    assert.notStrictEqual(client.status, "problem");
  });

  it("gives a remedy with every note or problem", () => {
    for (const check of checks) {
      if (check.status === "problem") {
        assert.ok(check.remedy, `${check.name} reports a problem without saying what to do`);
      }
    }
  });

  it("renders a report that names the platform and a conclusion", () => {
    const text = formatChecks(checks);
    assert.match(text, new RegExp(`Environment \\(${process.platform}`));
    assert.match(text, /Nothing needs to be installed|problem\(s\) need attention/);
  });

  it("renders remedies indented under their check", () => {
    const text = formatChecks([
      { name: "Thing", status: "problem", detail: "broken", remedy: "fix it" },
    ]);
    assert.match(text, /\[FAIL\] Thing: broken\n {9}fix it/);
  });
});
