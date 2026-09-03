/**
 * Passwords with awkward characters.
 *
 * A password only ever travels as a JavaScript string: it is read from JSON
 * and handed to ssh2, which puts it in an SSH authentication packet. No shell
 * is involved anywhere on that path, so characters that would be dangerous in
 * a command line -- $ # * ` " \ and spaces -- have no special meaning. This
 * asserts that, because "it should be fine" is exactly the kind of assumption
 * that turns into a login that mysteriously fails.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { buildAuthMethods } from "../src/clients/ssh-client.ts";
import type { SshProfile } from "../src/types.ts";

/**
 * Every character class that has ever broken a password field: shell
 * metacharacters, quotes, a backslash, a space, and a trailing space that a
 * careless trim() would eat.
 */
const NASTY_PASSWORDS = [
  "a$#dgU0v6*I2ZZb",           // the shape of a generated password
  "$(whoami)",                  // command substitution, if a shell saw it
  "`id`",                       // backticks
  "pass word",                  // a space
  " leading",
  "trailing ",
  'quo"te',
  "apo'strophe",
  "back\\slash",
  "semi;colon && and | pipe",
  "new\nline",
  "100%|>redirect",
  "umlautsäöüß",
  "emoji😀",
  "!history",
  "~tilde",
];

describe("passwords reach ssh2 byte for byte", () => {
  for (const password of NASTY_PASSWORDS) {
    it(`keeps ${JSON.stringify(password)} intact`, () => {
      const profile: SshProfile = { host: "h", port: 22, user: "u", password };
      const methods = buildAuthMethods(profile, undefined);

      assert.strictEqual(methods.length, 1);
      assert.strictEqual(methods[0].type, "password");
      // Not trimmed, not escaped, not re-encoded.
      assert.strictEqual(methods[0].password, password);
    });
  }
});

describe("passwords survive the config file", () => {
  const testHome = path.join(os.tmpdir(), "pi-ssh-pw-" + Date.now());
  const configFile = path.join(testHome, ".pi", "ssh-config.json");
  const originalHome = process.env.HOME;

  beforeEach(() => {
    fs.mkdirSync(path.join(testHome, ".pi"), { recursive: true, mode: 0o700 });
    process.env.HOME = testHome;
    if (fs.existsSync(configFile)) fs.unlinkSync(configFile);
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(testHome, { recursive: true, force: true });
  });

  for (const password of NASTY_PASSWORDS) {
    it(`round-trips ${JSON.stringify(password)} through JSON`, async () => {
      const mod = await import("../src/config.ts");
      mod._resetForTesting();
      mod.saveProfile("host", { host: "h", port: 22, user: "u", password });

      mod._resetForTesting();
      mod.loadConfig();
      assert.strictEqual(mod.getProfile("host")!.password, password);

      // And through the auth layer afterwards, which is what actually logs in.
      const methods = buildAuthMethods(mod.getProfile("host")!, undefined);
      assert.strictEqual(methods[0].password, password);
    });
  }

  it("stores a password JSON has to escape without corrupting it", async () => {
    const password = 'has "quotes" and \\backslashes\\';
    const mod = await import("../src/config.ts");
    mod._resetForTesting();
    mod.saveProfile("host", { host: "h", port: 22, user: "u", password });

    // The file is valid JSON, and the value is unchanged when read back.
    const raw = JSON.parse(fs.readFileSync(configFile, "utf-8"));
    assert.strictEqual(raw.profiles.host.password, password);
  });
});

describe("the password never reaches a shell", () => {
  it("is not part of any command the extension runs", async () => {
    // The only remote commands are in authorize.ts, and they carry the public
    // key, never the password. A change that interpolated a password into a
    // command would make every one of the characters above dangerous.
    const source = fs.readFileSync(
      path.join(import.meta.dirname, "..", "src", "authorize.ts"),
      "utf-8",
    );
    const execCalls = source.match(/execCommand\([^;]*?\)/gs) ?? [];
    assert.ok(execCalls.length > 0, "expected authorize.ts to run remote commands");

    for (const call of execCalls) {
      assert.ok(
        !/password/i.test(call),
        `a remote command references a password: ${call.slice(0, 80)}`,
      );
    }
  });
});
