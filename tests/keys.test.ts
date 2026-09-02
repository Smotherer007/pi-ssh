/**
 * Key generation.
 *
 * The format is the point: a key that Node can read but OpenSSH cannot is
 * useless, so these assert the encoding rather than just that bytes came out.
 * ssh2's parser stands in for OpenSSH here, which keeps the suite working on
 * Windows where ssh-keygen may not exist.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import ssh2 from "ssh2";

import {
  defaultKeyComment,
  formatPublicKeyLine,
  formatPublicKeyLineFromBlob,
  generateKeyPair,
  keyBlobType,
  keyFingerprint,
  publicKeyBlob,
  sameKeyMaterial,
} from "../src/keys.ts";

describe("generateKeyPair", () => {
  const pair = generateKeyPair("test@example");

  it("writes an OpenSSH private key, not a PKCS#8 one", () => {
    assert.match(pair.privateKey, /^-----BEGIN OPENSSH PRIVATE KEY-----\n/);
    assert.match(pair.privateKey, /-----END OPENSSH PRIVATE KEY-----\n$/);
  });

  it("produces a private key OpenSSH's own parser accepts", () => {
    const parsed = ssh2.utils.parseKey(pair.privateKey);
    assert.ok(!(parsed instanceof Error), `parse failed: ${(parsed as Error).message}`);
    assert.strictEqual((parsed as any).type, "ssh-ed25519");
  });

  it("derives the same public key from the private one", () => {
    const parsed = ssh2.utils.parseKey(pair.privateKey) as any;
    const derived = formatPublicKeyLineFromBlob(parsed.getPublicSSH(), "test@example");
    assert.strictEqual(derived, pair.publicKey);
  });

  it("writes an authorized_keys line in the expected shape", () => {
    assert.match(pair.publicKey, /^ssh-ed25519 [A-Za-z0-9+/]+=* test@example$/);
  });

  it("reports the fingerprint OpenSSH would show", () => {
    assert.match(pair.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/);
    assert.ok(!pair.fingerprint.includes("="), "the fingerprint is unpadded base64");
  });

  it("agrees with the fingerprint computed from the public blob", () => {
    const parsed = ssh2.utils.parseKey(pair.privateKey) as any;
    assert.strictEqual(keyFingerprint(parsed.getPublicSSH()), pair.fingerprint);
  });

  it("generates a different key every time", () => {
    assert.notStrictEqual(generateKeyPair("a").publicKey, generateKeyPair("a").publicKey);
  });

  it("handles an empty comment", () => {
    const bare = generateKeyPair("");
    assert.match(bare.publicKey, /^ssh-ed25519 [A-Za-z0-9+/]+=*$/);
    assert.ok(!(ssh2.utils.parseKey(bare.privateKey) instanceof Error));
  });

  it("round-trips a signature, so the key material really belongs together", () => {
    const parsed = ssh2.utils.parseKey(pair.privateKey) as any;
    const signature = parsed.sign(Buffer.from("payload"));
    assert.strictEqual(parsed.verify(Buffer.from("payload"), signature), true);
    assert.strictEqual(parsed.verify(Buffer.from("tampered"), signature), false);
  });
});

describe("public key helpers", () => {
  it("builds and reads back a key blob", () => {
    const raw = Buffer.alloc(32, 7);
    const blob = publicKeyBlob(raw);
    assert.strictEqual(keyBlobType(blob), "ssh-ed25519");
  });

  it("reports an unreadable blob as unknown rather than throwing", () => {
    assert.strictEqual(keyBlobType(Buffer.from([1, 2])), "unknown");
  });

  it("omits the trailing space when there is no comment", () => {
    const line = formatPublicKeyLine(Buffer.alloc(32, 1), "   ");
    assert.ok(!line.endsWith(" "));
  });
});

describe("sameKeyMaterial", () => {
  const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample keyMaterial";

  it("ignores a differing comment", () => {
    assert.strictEqual(
      sameKeyMaterial(key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample other@host"),
      true,
    );
  });

  it("ignores an options prefix, as authorized_keys allows", () => {
    assert.strictEqual(
      sameKeyMaterial(`no-pty,no-agent-forwarding ${key}`, key),
      true,
    );
  });

  it("distinguishes different key material", () => {
    assert.strictEqual(
      sameKeyMaterial(key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAADifferent comment"),
      false,
    );
  });

  it("treats comments, blanks and junk as no match", () => {
    assert.strictEqual(sameKeyMaterial("# a comment", key), false);
    assert.strictEqual(sameKeyMaterial("", key), false);
    assert.strictEqual(sameKeyMaterial("   ", ""), false);
  });
});

describe("defaultKeyComment", () => {
  it("names where the key came from", () => {
    assert.strictEqual(defaultKeyComment("pat", "server"), "pi-ssh pat@server");
  });
});
