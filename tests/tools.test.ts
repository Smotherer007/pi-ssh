/**
 * Tool-level tests.
 *
 * Argument validation is checked directly; everything that touches a host is
 * driven against the same real sshd the end-to-end tests use, so the tool
 * layer is exercised the way pi will call it.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const testHome = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ssh-tools-"));
const originalHome = process.env.HOME;
process.env.HOME = testHome;
fs.mkdirSync(path.join(testHome, ".pi"), { recursive: true, mode: 0o700 });

const { SshSetupTool } = await import("../src/tools/ssh-setup.ts");
const { SshStatusTool } = await import("../src/tools/ssh-status.ts");
const { SshProfileTool } = await import("../src/tools/ssh-profile.ts");
const { SshExecTool } = await import("../src/tools/ssh-exec.ts");
const { SshListTool } = await import("../src/tools/ssh-list.ts");
const { SshUploadTool } = await import("../src/tools/ssh-upload.ts");
const { SshDownloadTool } = await import("../src/tools/ssh-download.ts");
const { SshKeygenTool } = await import("../src/tools/ssh-keygen.ts");
const { SshAuthorizeTool } = await import("../src/tools/ssh-authorize.ts");
const { SshDoctorTool } = await import("../src/tools/ssh-doctor.ts");
const config = await import("../src/config.ts");
const { startTestServer } = await import("./sshd.ts");
type TestServer = Awaited<ReturnType<typeof startTestServer>>;

const signal = new AbortController().signal;
let server: TestServer = null;

before(async () => {
  server = await startTestServer();
});

after(() => {
  server?.stop();
  process.env.HOME = originalHome;
  fs.rmSync(testHome, { recursive: true, force: true });
});

describe("ssh_setup validation", () => {
  it("refuses an empty host or user", () => {
    assert.throws(
      () => SshSetupTool.execute("1", { name: "a", host: "  ", user: "u", password: "p" }, signal),
      /host must not be empty/,
    );
    assert.throws(
      () => SshSetupTool.execute("1", { name: "a", host: "h", user: " ", password: "p" }, signal),
      /user must not be empty/,
    );
  });

  it("refuses an impossible port", () => {
    assert.throws(
      () => SshSetupTool.execute("1", { name: "a", host: "h", user: "u", password: "p", port: 0 }, signal),
      /between 1 and 65535/,
    );
  });

  it("refuses a profile with no way to log in", () => {
    assert.throws(
      () => SshSetupTool.execute("1", { name: "a", host: "h", user: "u" }, signal),
      /password or a privateKeyPath/,
    );
  });

  it("nudges towards ssh_authorize when only a password is given", () => {
    const result = SshSetupTool.execute(
      "1",
      { name: "pw", host: "h", user: "u", password: "p" },
      signal,
    );
    assert.match(result.content[0].text, /ssh_authorize/);
    assert.strictEqual(result.details.hasPassword, true);
    assert.strictEqual(result.details.hasKey, false);
  });

  it("expands a tilde in the key path", () => {
    const result = SshSetupTool.execute(
      "1",
      { name: "keyed", host: "h", user: "u", privateKeyPath: "~/.ssh/id_test" },
      signal,
    );
    assert.strictEqual(result.details.hasKey, true);
    assert.strictEqual(
      config.getProfile("keyed")!.privateKeyPath,
      path.join(testHome, ".ssh/id_test"),
    );
  });
});

describe("ssh_profile", () => {
  it("lists profiles without arguments", () => {
    const result = SshProfileTool.execute("1", {}, signal);
    assert.ok(result.details.profiles.includes("pw"));
  });

  it("requires a name for use and delete", () => {
    assert.throws(() => SshProfileTool.execute("1", { action: "use" }, signal), /requires a profile name/);
  });

  it("rejects an unknown action", () => {
    assert.throws(
      () => SshProfileTool.execute("1", { action: "rename", name: "pw" }, signal),
      /Unknown action/,
    );
  });

  it("reports a missing profile on delete", () => {
    const result = SshProfileTool.execute("1", { action: "delete", name: "ghost" }, signal);
    assert.strictEqual(result.details.deleted, false);
  });
});

describe("ssh_doctor", () => {
  it("reports the environment and finds no blocking problem", () => {
    const result = SshDoctorTool.execute("1", {}, signal);
    assert.deepStrictEqual(result.details.problems, []);
    assert.match(result.content[0].text, /Nothing needs to be installed/);
  });
});

describe("ssh_keygen", () => {
  it("writes both halves with sane permissions", () => {
    const target = path.join(testHome, "keys", "generated");
    const result = SshKeygenTool.execute("1", { path: target, comment: "unit test" }, signal);

    assert.ok(fs.existsSync(target));
    assert.ok(fs.existsSync(`${target}.pub`));
    assert.strictEqual(fs.statSync(target).mode & 0o777, 0o600);
    assert.match(result.details.fingerprint, /^SHA256:/);
    assert.match(result.details.publicKey, /^ssh-ed25519 .* unit test$/);
  });

  it("refuses to overwrite an existing key", () => {
    const target = path.join(testHome, "keys", "generated");
    assert.throws(
      () => SshKeygenTool.execute("1", { path: target }, signal),
      /already exists/,
    );
  });

  it("overwrites only when told to", () => {
    const target = path.join(testHome, "keys", "generated");
    const before = fs.readFileSync(target, "utf-8");
    SshKeygenTool.execute("1", { path: target, overwrite: true }, signal);
    assert.notStrictEqual(fs.readFileSync(target, "utf-8"), before);
  });

  it("refuses to attach the key to a profile that does not exist", () => {
    assert.throws(
      () =>
        SshKeygenTool.execute(
          "1",
          { path: path.join(testHome, "keys", "other"), profile: "ghost" },
          signal,
        ),
      /does not exist/,
    );
  });

  it("records the key in a profile when asked", () => {
    const target = path.join(testHome, "keys", "attached");
    SshKeygenTool.execute("1", { path: target, profile: "pw" }, signal);
    assert.strictEqual(config.getProfile("pw")!.privateKeyPath, target);
  });
});

describe("tools against a real server", () => {
  before(() => {
    if (!server) return;
    config.saveProfile("live", {
      host: "127.0.0.1",
      port: server.port,
      user: server.user,
      privateKeyPath: server.clientKeyPath,
      knownHostsFile: path.join(testHome, "known_hosts"),
      strictHostKey: true,
    });
  });

  it("ssh_status verifies a connection when asked", async (t) => {
    if (!server) return t.skip("no sshd on this machine");
    // First contact has to record the host key, which status does not do.
    await SshExecTool.execute(
      "1",
      { command: "true", profile: "live", acceptNewHostKey: true },
      signal,
    );

    const result = await SshStatusTool.execute("1", { profile: "live", connect: true }, signal);
    assert.strictEqual(result.details.reachable, true);
    assert.match(result.content[0].text, /Authenticated with: key/);
  });

  it("ssh_exec returns output and the exit code", async (t) => {
    if (!server) return t.skip("no sshd on this machine");
    const result = await SshExecTool.execute(
      "1",
      { command: "echo from-the-tool; exit 7", profile: "live" },
      signal,
    );
    assert.strictEqual(result.details.exitCode, 7);
    assert.match(result.content[0].text, /from-the-tool/);
  });

  it("ssh_exec rejects an empty command", async () => {
    await assert.rejects(
      () => SshExecTool.execute("1", { command: "   ", profile: "live" }, signal),
      /must not be empty/,
    );
  });

  it("ssh_list, ssh_upload and ssh_download work together", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const local = path.join(testHome, "payload.txt");
    const remote = path.join(server.dir, "payload.txt");
    const back = path.join(testHome, "returned", "payload.txt");
    fs.writeFileSync(local, "tool round trip");

    const uploaded = await SshUploadTool.execute(
      "1",
      { localPath: local, remotePath: remote, profile: "live" },
      signal,
    );
    assert.strictEqual(uploaded.details.size, 15);

    const listed = await SshListTool.execute("1", { path: server.dir, profile: "live" }, signal);
    assert.ok(listed.details.count > 0);
    assert.match(listed.content[0].text, /payload\.txt/);

    await SshDownloadTool.execute(
      "1",
      { remotePath: remote, localPath: back, profile: "live" },
      signal,
    );
    assert.strictEqual(fs.readFileSync(back, "utf-8"), "tool round trip");
  });

  it("ssh_authorize sets up a key login through the tool layer", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const result = await SshAuthorizeTool.execute(
      "1",
      {
        profile: "live",
        keyPath: path.join(testHome, "keys", "via_tool"),
        authorizedKeysPath: server.authorizedKeysPath,
      },
      signal,
    );

    assert.strictEqual(result.details.installed, true);
    assert.strictEqual(result.details.verified, true);
    assert.strictEqual(result.details.passwordRemoved, false);
    assert.match(result.content[0].text, /no password is needed from now on/);
  });

  it("an unknown host is refused rather than trusted silently", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    config.saveProfile("fresh", {
      host: "127.0.0.1",
      port: server.port,
      user: server.user,
      privateKeyPath: server.clientKeyPath,
      knownHostsFile: path.join(testHome, "empty_known_hosts"),
      strictHostKey: true,
    });

    await assert.rejects(
      () => SshExecTool.execute("1", { command: "true", profile: "fresh" }, signal),
      /not in .*empty_known_hosts/s,
    );
  });
});
