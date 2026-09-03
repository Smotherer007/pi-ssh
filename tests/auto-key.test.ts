/**
 * The first-use upgrade from a password to a key.
 *
 * The success path needs a server that accepts password authentication,
 * which the test sshd cannot do without root, so it is covered by the
 * bootstrap tests in ssh-e2e. What is checked here is the decision logic and
 * the failure behaviour, which is the part that must not block work: a host
 * that refuses public keys should still be usable.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const testHome = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ssh-autokey-"));
const originalHome = process.env.HOME;
process.env.HOME = testHome;
fs.mkdirSync(path.join(testHome, ".pi"), { recursive: true, mode: 0o700 });

const { ensureKeyAuthentication, needsKeyUpgrade } = await import("../src/auto-key.ts");
const config = await import("../src/config.ts");
const { startTestServer } = await import("./sshd.ts");
type TestServer = Awaited<ReturnType<typeof startTestServer>>;

let server: TestServer = null;

before(async () => {
  server = await startTestServer();
});

after(() => {
  server?.stop();
  process.env.HOME = originalHome;
  fs.rmSync(testHome, { recursive: true, force: true });
});

describe("needsKeyUpgrade", () => {
  const base = { host: "h", port: 22, user: "u" };

  it("is true for a profile that has only a password", () => {
    assert.strictEqual(needsKeyUpgrade({ ...base, password: "p" }), true);
  });

  it("is false once a key is configured", () => {
    assert.strictEqual(needsKeyUpgrade({ ...base, password: "p", privateKeyPath: "/k" }), false);
    assert.strictEqual(needsKeyUpgrade({ ...base, privateKeyPath: "/k" }), false);
  });

  it("is false when the profile opted out", () => {
    assert.strictEqual(needsKeyUpgrade({ ...base, password: "p", autoKey: false }), false);
  });

  it("is false when there is nothing to upgrade from", () => {
    assert.strictEqual(needsKeyUpgrade(base), false);
  });
});

describe("ensureKeyAuthentication", () => {
  it("opens no connection when there is nothing to do", async () => {
    const profile = { host: "192.0.2.1", port: 22, user: "u", privateKeyPath: "/k" };
    // 192.0.2.1 is reserved for documentation and will not answer, so a
    // connection attempt here would hang rather than return quickly.
    const outcome = await ensureKeyAuthentication("noop", profile);
    assert.strictEqual(outcome.upgraded, false);
    assert.strictEqual(outcome.note, undefined);
    assert.strictEqual(outcome.profile, profile);
  });

  it("respects the opt-out without touching the network", async () => {
    const profile = { host: "192.0.2.1", port: 22, user: "u", password: "p", autoKey: false };
    const outcome = await ensureKeyAuthentication("manual", profile);
    assert.strictEqual(outcome.upgraded, false);
    assert.strictEqual(outcome.profile.password, "p");
  });

  it("keeps the password and explains itself when the upgrade fails", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    // The test server refuses password authentication, so the bootstrap
    // cannot get in. Work must continue rather than being blocked.
    config._resetForTesting();
    config.saveProfile("pw-only", {
      host: "127.0.0.1",
      port: server.port,
      user: server.user,
      password: "not-accepted",
      knownHostsFile: path.join(testHome, "known_hosts"),
      strictHostKey: false,
    });

    const { profile } = config.resolveProfile("pw-only");
    const outcome = await ensureKeyAuthentication("pw-only", profile, {
      acceptNewHostKey: true,
    });

    assert.strictEqual(outcome.upgraded, false);
    assert.ok(outcome.note, "a failed upgrade has to say so");
    assert.match(outcome.note!, /Could not switch|could not be verified/);
    // The password is the only way in, so it must survive.
    assert.strictEqual(config.getProfile("pw-only")!.password, "not-accepted");
    assert.strictEqual(outcome.profile.password, "not-accepted");
  });
});
