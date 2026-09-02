/**
 * known_hosts parsing and host key verdicts.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  addKnownHost,
  checkHostKey,
  describeChangedKey,
  entryMatchesHost,
  hostPattern,
  parseKnownHosts,
} from "../src/known-hosts.ts";
import { generateKeyPair, publicKeyBlob } from "../src/keys.ts";
import ssh2 from "ssh2";

function blobFor(): Buffer {
  const parsed = ssh2.utils.parseKey(generateKeyPair("host").privateKey) as any;
  return parsed.getPublicSSH();
}

/** A hashed entry exactly as OpenSSH writes them. */
function hashedHost(pattern: string): string {
  const salt = crypto.randomBytes(20);
  const hash = crypto.createHmac("sha1", salt).update(pattern).digest("base64");
  return `|1|${salt.toString("base64")}|${hash}`;
}

describe("hostPattern", () => {
  it("uses the bare host on the default port", () => {
    assert.strictEqual(hostPattern("example.com", 22), "example.com");
  });

  it("brackets the host when the port is non-standard", () => {
    assert.strictEqual(hostPattern("example.com", 2222), "[example.com]:2222");
  });
});

describe("parseKnownHosts", () => {
  it("skips comments and blank lines", () => {
    const entries = parseKnownHosts("# a comment\n\n   \nexample.com ssh-ed25519 AAAA\n");
    assert.strictEqual(entries.length, 1);
    assert.strictEqual(entries[0].hosts, "example.com");
  });

  it("keeps the marker of a revoked entry", () => {
    const entries = parseKnownHosts("@revoked example.com ssh-ed25519 AAAA");
    assert.strictEqual(entries[0].marker, "revoked");
    assert.strictEqual(entries[0].hosts, "example.com");
  });

  it("ignores lines with too few fields", () => {
    assert.strictEqual(parseKnownHosts("example.com ssh-ed25519").length, 0);
  });
});

describe("entryMatchesHost", () => {
  it("matches one host in a comma-separated list", () => {
    assert.strictEqual(entryMatchesHost("a.example,b.example", "b.example"), true);
    assert.strictEqual(entryMatchesHost("a.example,b.example", "c.example"), false);
  });

  it("matches a hashed entry", () => {
    const hashed = hashedHost("example.com");
    assert.strictEqual(entryMatchesHost(hashed, "example.com"), true);
    assert.strictEqual(entryMatchesHost(hashed, "evil.example"), false);
  });

  it("matches a hashed entry for a non-default port", () => {
    const hashed = hashedHost("[example.com]:2222");
    assert.strictEqual(entryMatchesHost(hashed, "[example.com]:2222"), true);
  });

  it("survives a malformed hashed entry", () => {
    assert.strictEqual(entryMatchesHost("|1|broken", "example.com"), false);
  });
});

describe("checkHostKey", () => {
  let file: string;
  let key: Buffer;

  beforeEach(() => {
    file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "kh-")), "known_hosts");
    key = blobFor();
  });

  afterEach(() => {
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  });

  it("reports an unknown host when the file does not exist", () => {
    const check = checkHostKey("example.com", 22, key, file);
    assert.strictEqual(check.verdict, "unknown");
    assert.match(check.fingerprint, /^SHA256:/);
    assert.strictEqual(check.keyType, "ssh-ed25519");
  });

  it("matches after the key is recorded", () => {
    addKnownHost("example.com", 22, key, file);
    assert.strictEqual(checkHostKey("example.com", 22, key, file).verdict, "match");
  });

  it("keeps ports apart", () => {
    addKnownHost("example.com", 22, key, file);
    assert.strictEqual(checkHostKey("example.com", 2222, key, file).verdict, "unknown");
  });

  it("flags a different key of the same type as changed", () => {
    addKnownHost("example.com", 22, key, file);
    const check = checkHostKey("example.com", 22, blobFor(), file);
    assert.strictEqual(check.verdict, "changed");
    assert.strictEqual(check.knownFingerprints.length, 1);
  });

  it("does not cry foul when the host offers a different key type", () => {
    // A host with both an RSA and an ed25519 key is normal, not an attack.
    fs.writeFileSync(file, `example.com ssh-rsa ${Buffer.from("fake").toString("base64")}\n`);
    assert.strictEqual(checkHostKey("example.com", 22, key, file).verdict, "unknown");
  });

  it("honours a revoked marker", () => {
    fs.writeFileSync(file, `@revoked example.com ssh-ed25519 ${key.toString("base64")}\n`);
    assert.strictEqual(checkHostKey("example.com", 22, key, file).verdict, "revoked");
  });

  it("recognises a hashed entry written by OpenSSH", () => {
    fs.writeFileSync(file, `${hashedHost("example.com")} ssh-ed25519 ${key.toString("base64")}\n`);
    assert.strictEqual(checkHostKey("example.com", 22, key, file).verdict, "match");
  });
});

describe("addKnownHost", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "kh-add-"));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("creates the directory and file when missing", () => {
    const file = path.join(dir, "nested", "known_hosts");
    addKnownHost("example.com", 22, blobFor(), file);
    assert.ok(fs.existsSync(file));
    assert.match(fs.readFileSync(file, "utf-8"), /^example\.com ssh-ed25519 /);
  });

  it("does not glue a new entry onto an unterminated last line", () => {
    const file = path.join(dir, "known_hosts");
    fs.writeFileSync(file, "old.example ssh-ed25519 AAAA");
    addKnownHost("new.example", 22, blobFor(), file);

    const lines = fs.readFileSync(file, "utf-8").trim().split("\n");
    assert.strictEqual(lines.length, 2);
    assert.match(lines[1], /^new\.example /);
  });
});

describe("describeChangedKey", () => {
  it("says what happened and how to fix it deliberately", () => {
    const message = describeChangedKey(
      {
        verdict: "changed",
        fingerprint: "SHA256:new",
        keyType: "ssh-ed25519",
        knownFingerprints: ["SHA256:old"],
        file: "/home/pat/.ssh/known_hosts",
      },
      "example.com",
    );
    assert.match(message, /HOST KEY CHANGED for example\.com/);
    assert.match(message, /SHA256:new/);
    assert.match(message, /SHA256:old/);
    assert.match(message, /ssh-keygen -R example\.com/);
    assert.match(message, /machine-in-the-middle/);
  });
});
