/**
 * SSH key generation, in process.
 *
 * `ssh-keygen` is not something to depend on: it is absent on plenty of
 * Windows installs, and the whole point of the key bootstrap is that it works
 * without the user preparing anything first. Node can generate and sign with
 * ed25519; what it cannot do is write OpenSSH's key formats, so those are
 * encoded here.
 *
 * The output is byte-for-byte what ssh-keygen produces for an unencrypted
 * ed25519 key, so the result also works with the plain `ssh` command.
 */

import * as crypto from "node:crypto";

const KEY_TYPE = "ssh-ed25519";
const AUTH_MAGIC = Buffer.from("openssh-key-v1\0", "binary");

// --- SSH wire primitives --------------------------------------------------

/** An SSH "string": a 32-bit big-endian length followed by the bytes. */
function sshString(value: Buffer | string): Buffer {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf-8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length, 0);
  return Buffer.concat([length, bytes]);
}

function uint32(value: number): Buffer {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value >>> 0, 0);
  return buffer;
}

/** Read an SSH string, returning it and the offset after it. */
function readSshString(buffer: Buffer, offset: number): [Buffer, number] {
  const length = buffer.readUInt32BE(offset);
  const start = offset + 4;
  return [buffer.subarray(start, start + length), start + length];
}

// --- Public keys ----------------------------------------------------------

/** The wire-format blob for an ed25519 public key. */
export function publicKeyBlob(publicKeyRaw: Buffer): Buffer {
  return Buffer.concat([sshString(KEY_TYPE), sshString(publicKeyRaw)]);
}

/** One authorized_keys / .pub line: "ssh-ed25519 <base64> <comment>". */
export function formatPublicKeyLine(publicKeyRaw: Buffer, comment: string): string {
  const encoded = publicKeyBlob(publicKeyRaw).toString("base64");
  const suffix = comment.trim() ? ` ${comment.trim()}` : "";
  return `${KEY_TYPE} ${encoded}${suffix}`;
}

/** One line built from an already-encoded key blob, e.g. one ssh2 parsed. */
export function formatPublicKeyLineFromBlob(blob: Buffer, comment: string): string {
  const suffix = comment.trim() ? ` ${comment.trim()}` : "";
  return `${keyBlobType(blob)} ${blob.toString("base64")}${suffix}`;
}

/**
 * The fingerprint OpenSSH shows: SHA256 over the key blob, base64, unpadded.
 */
export function keyFingerprint(blob: Buffer): string {
  const digest = crypto.createHash("sha256").update(blob).digest("base64");
  return `SHA256:${digest.replace(/=+$/, "")}`;
}

/** Pull the algorithm name out of a wire-format key blob. */
export function keyBlobType(blob: Buffer): string {
  try {
    const [type] = readSshString(blob, 0);
    return type.toString("utf-8");
  } catch {
    return "unknown";
  }
}

// --- Private keys ---------------------------------------------------------

function toPem(body: Buffer): string {
  const encoded = body.toString("base64").replace(/(.{70})/g, "$1\n").replace(/\n$/, "");
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${encoded}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

/**
 * Encode an unencrypted ed25519 private key in OpenSSH's container format.
 *
 * The layout is: magic, cipher/kdf names (all "none" here), the public key,
 * then a "private" section holding a repeated check integer, the key pair,
 * the comment, and padding to the cipher block size.
 */
function encodeOpenSshPrivateKey(
  publicKeyRaw: Buffer,
  privateSeed: Buffer,
  comment: string,
): string {
  const pubBlob = publicKeyBlob(publicKeyRaw);

  // The two check integers must match; a wrong passphrase shows up as a
  // mismatch when the section is encrypted. Unencrypted, they are a checksum.
  const check = crypto.randomBytes(4);
  const privateSection: Buffer[] = [
    check,
    check,
    sshString(KEY_TYPE),
    sshString(publicKeyRaw),
    // OpenSSH stores seed and public key together as the 64-byte private key.
    sshString(Buffer.concat([privateSeed, publicKeyRaw])),
    sshString(comment),
  ];

  let body = Buffer.concat(privateSection);
  // Pad to a multiple of 8 with 1, 2, 3, ... as OpenSSH does.
  const blockSize = 8;
  const padding: number[] = [];
  for (let i = 1; (body.length + padding.length) % blockSize !== 0; i += 1) {
    padding.push(i);
  }
  body = Buffer.concat([body, Buffer.from(padding)]);

  return toPem(
    Buffer.concat([
      AUTH_MAGIC,
      sshString("none"), // ciphername
      sshString("none"), // kdfname
      sshString(""), // kdfoptions
      uint32(1), // number of keys
      sshString(pubBlob),
      sshString(body),
    ]),
  );
}

export interface GeneratedKeyPair {
  /** OpenSSH private key, ready to write to a file or hand to ssh2. */
  readonly privateKey: string;
  /** One authorized_keys line. */
  readonly publicKey: string;
  readonly fingerprint: string;
  readonly comment: string;
}

/**
 * Generate an ed25519 key pair.
 *
 * ed25519 rather than RSA: every OpenSSH released in the last decade accepts
 * it, the keys are short enough to paste, and generation is instant.
 */
export function generateKeyPair(comment: string): GeneratedKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

  // The JWK export is the only way to get the raw 32-byte values out of Node.
  const publicJwk = publicKey.export({ format: "jwk" }) as { x: string };
  const privateJwk = privateKey.export({ format: "jwk" }) as { d: string };

  const publicRaw = Buffer.from(publicJwk.x, "base64url");
  const seed = Buffer.from(privateJwk.d, "base64url");

  if (publicRaw.length !== 32 || seed.length !== 32) {
    throw new Error("Unexpected ed25519 key size from the crypto module.");
  }

  return {
    privateKey: encodeOpenSshPrivateKey(publicRaw, seed, comment),
    publicKey: formatPublicKeyLine(publicRaw, comment),
    fingerprint: keyFingerprint(publicKeyBlob(publicRaw)),
    comment,
  };
}

/** A default comment identifying where the key was made. */
export function defaultKeyComment(user: string, host: string): string {
  return `pi-ssh ${user}@${host}`;
}

/**
 * Compare two authorized_keys lines by their key material, ignoring the
 * comment and any options prefix, so re-running the bootstrap does not append
 * a second copy of the same key.
 */
export function sameKeyMaterial(a: string, b: string): boolean {
  const material = (line: string) => {
    const parts = line.trim().split(/\s+/);
    const index = parts.findIndex((part) => /^(ssh|ecdsa|sk)-/.test(part));
    return index === -1 ? "" : parts.slice(index, index + 2).join(" ");
  };
  const left = material(a);
  return left.length > 0 && left === material(b);
}
