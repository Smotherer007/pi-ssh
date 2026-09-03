/**
 * Not losing configuration that pi did not write itself.
 *
 * The failure this guards against: pi reads the file at startup, the user (or
 * a second pi session) edits it, and then an unrelated write from pi dumps its
 * stale in-memory copy over the file and the edit is gone. The automatic
 * key upgrade made writes routine rather than rare, which is what turned a
 * latent flaw into lost hosts.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

let home: string;
let configFile: string;
const originalHome = process.env.HOME;

/** Write the file behind pi's back, as a person or another session would. */
function editOnDisk(change: (data: any) => void): void {
  const data = JSON.parse(fs.readFileSync(configFile, "utf-8"));
  change(data);
  fs.writeFileSync(configFile, JSON.stringify(data, null, 2));
}

async function freshConfig() {
  const mod = await import("../src/config.ts");
  mod._resetForTesting();
  return mod;
}

const alpha = { host: "a.example", port: 22, user: "u", password: "p" };
const beta = { host: "b.example", port: 22, user: "u", privateKeyPath: "/keys/b" };

describe("configuration written by someone else", () => {
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ssh-conc-"));
    fs.mkdirSync(path.join(home, ".pi"), { recursive: true, mode: 0o700 });
    process.env.HOME = home;
    configFile = path.join(home, ".pi", "ssh-config.json");
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("survives an unrelated write from pi", async () => {
    const mod = await freshConfig();
    mod.saveProfile("alpha", alpha);

    // A second session, or a hand edit, adds a host.
    editOnDisk((data) => {
      data.profiles.beta = beta;
    });

    // pi now writes for a completely different reason.
    mod.updateProfile("alpha", { privateKeyPath: "/keys/a", password: undefined });

    const onDisk = JSON.parse(fs.readFileSync(configFile, "utf-8"));
    assert.ok("beta" in onDisk.profiles, "a host added elsewhere must not be erased");
    assert.strictEqual(onDisk.profiles.beta.host, "b.example");
    assert.strictEqual(onDisk.profiles.alpha.privateKeyPath, "/keys/a");
    assert.strictEqual(onDisk.profiles.alpha.password, undefined);
  });

  it("keeps top-level keys it does not understand", async () => {
    const mod = await freshConfig();
    mod.saveProfile("alpha", alpha);

    editOnDisk((data) => {
      data.somethingFromANewerVersion = { keep: "me" };
    });
    mod.saveProfile("gamma", { host: "c", port: 22, user: "u", password: "p" });

    const onDisk = JSON.parse(fs.readFileSync(configFile, "utf-8"));
    assert.deepStrictEqual(onDisk.somethingFromANewerVersion, { keep: "me" });
  });

  it("keeps unknown fields inside a profile", async () => {
    const mod = await freshConfig();
    mod.saveProfile("alpha", alpha);

    editOnDisk((data) => {
      data.profiles.alpha.comment = "the old jump host";
    });
    mod.updateProfile("alpha", { port: 2222 });

    const onDisk = JSON.parse(fs.readFileSync(configFile, "utf-8"));
    assert.strictEqual(onDisk.profiles.alpha.comment, "the old jump host");
    assert.strictEqual(onDisk.profiles.alpha.port, 2222);
  });

  it("notices an outside edit without pi being restarted", async () => {
    const mod = await freshConfig();
    mod.saveProfile("alpha", alpha);
    assert.deepStrictEqual(Object.keys(mod.getProfiles()), ["alpha"]);

    editOnDisk((data) => {
      data.profiles.beta = beta;
    });

    assert.deepStrictEqual(Object.keys(mod.getProfiles()).sort(), ["alpha", "beta"]);
    assert.strictEqual(mod.getProfile("beta")?.host, "b.example");
  });

  it("refuses to update a profile that was deleted elsewhere", async () => {
    const mod = await freshConfig();
    mod.saveProfile("alpha", alpha);

    editOnDisk((data) => {
      delete data.profiles.alpha;
    });

    assert.throws(() => mod.updateProfile("alpha", { port: 2222 }), /does not exist/);
  });

  it("does not resurrect a profile deleted elsewhere", async () => {
    const mod = await freshConfig();
    mod.saveProfile("alpha", alpha);
    mod.saveProfile("beta", beta);

    editOnDisk((data) => {
      delete data.profiles.beta;
    });
    mod.updateProfile("alpha", { port: 2222 });

    const onDisk = JSON.parse(fs.readFileSync(configFile, "utf-8"));
    assert.ok(!("beta" in onDisk.profiles), "a deletion elsewhere must stick");
  });
});

describe("writes that change nothing", () => {
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ssh-noop-"));
    fs.mkdirSync(path.join(home, ".pi"), { recursive: true, mode: 0o700 });
    process.env.HOME = home;
    configFile = path.join(home, ".pi", "ssh-config.json");
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(home, { recursive: true, force: true });
  });

  /** Wait long enough that a rewrite would show a different mtime. */
  async function settle() {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  it("leaves the file untouched when a profile is saved unchanged", async () => {
    const mod = await freshConfig();
    mod.saveProfile("alpha", alpha);

    const before = fs.statSync(configFile).mtimeMs;
    await settle();
    mod.saveProfile("alpha", alpha);

    assert.strictEqual(fs.statSync(configFile).mtimeMs, before, "an unchanged save must not rewrite");
  });

  it("leaves the file untouched when deleting a profile that is not there", async () => {
    const mod = await freshConfig();
    mod.saveProfile("alpha", alpha);

    const before = fs.statSync(configFile).mtimeMs;
    await settle();
    assert.strictEqual(mod.deleteProfile("ghost"), false);

    assert.strictEqual(fs.statSync(configFile).mtimeMs, before);
  });

  it("leaves the file untouched when the active profile is already active", async () => {
    const mod = await freshConfig();
    mod.saveProfile("alpha", alpha);

    const before = fs.statSync(configFile).mtimeMs;
    await settle();
    mod.setActiveProfile("alpha");

    assert.strictEqual(fs.statSync(configFile).mtimeMs, before);
  });

  it("still writes when something really did change", async () => {
    const mod = await freshConfig();
    mod.saveProfile("alpha", alpha);

    const before = fs.statSync(configFile).mtimeMs;
    await settle();
    mod.updateProfile("alpha", { port: 2222 });

    assert.notStrictEqual(fs.statSync(configFile).mtimeMs, before);
    assert.strictEqual(mod.getProfile("alpha")!.port, 2222);
  });
});
