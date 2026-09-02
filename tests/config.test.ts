import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { SshProfile } from "../src/types.ts";

const testHome = path.join(os.tmpdir(), "pi-ssh-cfg-" + Date.now());
const configFile = path.join(testHome, ".pi", "ssh-config.json");
const originalHome = process.env.HOME;

const staging: SshProfile = { host: "staging.example", port: 22, user: "deploy", password: "s3cret" };
const nas: SshProfile = { host: "10.0.0.5", port: 2222, user: "pat", privateKeyPath: "/keys/nas" };

async function freshConfig() {
  const mod = await import("../src/config.ts");
  mod._resetForTesting();
  return mod;
}

describe("config", () => {
  beforeEach(() => {
    fs.mkdirSync(path.join(testHome, ".pi"), { recursive: true, mode: 0o700 });
    process.env.HOME = testHome;
    if (fs.existsSync(configFile)) fs.unlinkSync(configFile);
  });

  afterEach(() => {
    if (fs.existsSync(configFile)) fs.unlinkSync(configFile);
    process.env.HOME = originalHome;
  });

  describe("profiles", () => {
    it("makes the first profile active", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      assert.strictEqual(mod.getActiveProfile(), "staging");
      assert.deepStrictEqual(mod.getConfig(), staging);
    });

    it("does not steal the active slot with a second profile", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      mod.saveProfile("nas", nas);
      assert.strictEqual(mod.getActiveProfile(), "staging");
    });

    it("switches and refuses unknown names", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      mod.saveProfile("nas", nas);
      mod.setActiveProfile("nas");
      assert.strictEqual(mod.getConfig()?.host, "10.0.0.5");
      assert.throws(() => mod.setActiveProfile("ghost"), /does not exist/);
    });

    it("falls back to another profile on delete", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      mod.saveProfile("nas", nas);
      assert.strictEqual(mod.deleteProfile("staging"), true);
      assert.strictEqual(mod.getActiveProfile(), "nas");
      assert.strictEqual(mod.deleteProfile("ghost"), false);
    });

    it("clears the active profile when the last one goes", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      mod.deleteProfile("staging");
      assert.strictEqual(mod.getActiveProfile(), null);
      assert.strictEqual(mod.getConfig(), null);
    });
  });

  describe("updateProfile", () => {
    it("merges without dropping the other fields", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      const updated = mod.updateProfile("staging", { privateKeyPath: "/keys/new" });
      assert.strictEqual(updated.privateKeyPath, "/keys/new");
      assert.strictEqual(updated.password, "s3cret");
      assert.strictEqual(updated.host, "staging.example");
    });

    it("can clear a field, which is how the password is dropped", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      const updated = mod.updateProfile("staging", { password: undefined });
      assert.strictEqual(updated.password, undefined);
    });

    it("refuses an unknown profile", async () => {
      const mod = await freshConfig();
      assert.throws(() => mod.updateProfile("ghost", { user: "x" }), /does not exist/);
    });
  });

  describe("resolveProfile", () => {
    it("returns the named profile with its name", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      mod.saveProfile("nas", nas);
      const resolved = mod.resolveProfile("nas");
      assert.strictEqual(resolved.name, "nas");
      assert.strictEqual(resolved.profile.host, "10.0.0.5");
    });

    it("lists what is available when the name is wrong", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      assert.throws(() => mod.resolveProfile("ghost"), /Available: staging/);
    });

    it("points at ssh_setup when nothing is configured", async () => {
      const mod = await freshConfig();
      assert.throws(() => mod.resolveProfile(), /ssh_setup/);
    });
  });

  describe("persistence", () => {
    it("writes the file owner-only, because it holds passwords", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      assert.strictEqual(fs.statSync(configFile).mode & 0o777, 0o600);
    });

    it("round-trips through loadConfig", async () => {
      const mod = await freshConfig();
      mod.saveProfile("staging", staging);
      mod.saveProfile("nas", nas);
      mod.setActiveProfile("nas");

      mod._resetForTesting();
      mod.loadConfig();
      assert.strictEqual(mod.getActiveProfile(), "nas");
      assert.strictEqual(mod.getProfile("staging")?.password, "s3cret");
    });

    it("repairs an active profile that no longer exists", async () => {
      fs.writeFileSync(
        configFile,
        JSON.stringify({ profiles: { staging }, activeProfile: "gone" }),
        { mode: 0o600 },
      );
      const mod = await freshConfig();
      mod.loadConfig();
      assert.strictEqual(mod.getActiveProfile(), "staging");
    });

    it("tightens permissions on a world-readable file", async () => {
      fs.writeFileSync(
        configFile,
        JSON.stringify({ profiles: { staging }, activeProfile: "staging" }),
        { mode: 0o644 },
      );
      fs.chmodSync(configFile, 0o644);
      const mod = await freshConfig();
      mod.loadConfig();
      assert.strictEqual(fs.statSync(configFile).mode & 0o777, 0o600);
    });

    it("survives a corrupt file", async () => {
      fs.writeFileSync(configFile, "{ not json", { mode: 0o600 });
      const mod = await freshConfig();
      mod.loadConfig();
      assert.deepStrictEqual(mod.getProfiles(), {});
    });
  });

  describe("expandPath", () => {
    it("expands a leading tilde", async () => {
      const mod = await freshConfig();
      assert.strictEqual(mod.expandPath("~/.ssh/id"), path.join(testHome, ".ssh/id"));
      assert.strictEqual(mod.expandPath("~"), testHome);
    });

    it("leaves an absolute path alone and makes a relative one absolute", async () => {
      const mod = await freshConfig();
      assert.strictEqual(mod.expandPath("/etc/hosts"), "/etc/hosts");
      assert.ok(path.isAbsolute(mod.expandPath("./relative")));
    });

    it("passes an empty value through untouched", async () => {
      const mod = await freshConfig();
      assert.strictEqual(mod.expandPath(""), "");
    });
  });
});
