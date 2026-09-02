/**
 * Host key verification against known_hosts.
 *
 * Trust on first use: an unknown host is recorded with its fingerprint, and
 * from then on a changed key is a hard failure rather than a prompt. That is
 * the only part of SSH that protects against someone sitting between you and
 * the server, so it is not something to skip for convenience.
 *
 * OpenSSH's own file is used by default, which means hosts already visited
 * with `ssh` are recognised, and hosts recorded here are recognised by `ssh`.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { keyBlobType, keyFingerprint } from "./keys.ts";

export type HostKeyVerdict = "match" | "unknown" | "changed" | "revoked";

export interface HostKeyCheck {
  readonly verdict: HostKeyVerdict;
  readonly fingerprint: string;
  readonly keyType: string;
  /** Fingerprints already on record for this host, when the key changed. */
  readonly knownFingerprints: ReadonlyArray<string>;
  readonly file: string;
}

export interface KnownHostEntry {
  readonly hosts: string;
  readonly keyType: string;
  readonly blob: Buffer;
  readonly marker?: string;
}

export function defaultKnownHostsPath(): string {
  const home = process.env.HOME || process.env.USERPROFILE || os.homedir();
  return path.join(home, ".ssh", "known_hosts");
}

/** How OpenSSH writes a host: bare, or [host]:port for a non-default port. */
export function hostPattern(host: string, port: number): string {
  return port === 22 ? host : `[${host}]:${port}`;
}

// --- Parsing --------------------------------------------------------------

export function parseKnownHosts(content: string): KnownHostEntry[] {
  const entries: KnownHostEntry[] = [];

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    let parts = line.split(/\s+/);
    let marker: string | undefined;

    // A line may start with @cert-authority or @revoked.
    if (parts[0]?.startsWith("@")) {
      marker = parts[0].slice(1);
      parts = parts.slice(1);
    }
    if (parts.length < 3) continue;

    const [hosts, keyType, encoded] = parts;
    let blob: Buffer;
    try {
      blob = Buffer.from(encoded, "base64");
    } catch {
      continue;
    }
    if (blob.length === 0) continue;

    entries.push({ hosts, keyType, blob, marker });
  }
  return entries;
}

/**
 * Does this entry cover the given host?
 *
 * Handles the three forms OpenSSH writes: a comma-separated list of plain
 * patterns, and hashed entries of the form |1|salt|hash.
 */
export function entryMatchesHost(entryHosts: string, pattern: string): boolean {
  if (entryHosts.startsWith("|1|")) {
    const [, salt, hash] = entryHosts.split("|").filter((part) => part.length > 0);
    if (!salt || !hash) return false;
    try {
      const digest = crypto
        .createHmac("sha1", Buffer.from(salt, "base64"))
        .update(pattern)
        .digest("base64");
      return digest === hash;
    } catch {
      return false;
    }
  }

  return entryHosts.split(",").some((candidate) => candidate.trim() === pattern);
}

// --- Verification ---------------------------------------------------------

export function readKnownHosts(file: string): KnownHostEntry[] {
  try {
    return parseKnownHosts(fs.readFileSync(file, "utf-8"));
  } catch {
    // A missing file simply means nothing is known yet.
    return [];
  }
}

/**
 * Compare a host key offered during the handshake against what is on record.
 */
export function checkHostKey(
  host: string,
  port: number,
  key: Buffer,
  file = defaultKnownHostsPath(),
): HostKeyCheck {
  const pattern = hostPattern(host, port);
  const fingerprint = keyFingerprint(key);
  const keyType = keyBlobType(key);
  const entries = readKnownHosts(file).filter((entry) =>
    entryMatchesHost(entry.hosts, pattern),
  );

  const base = { fingerprint, keyType, file };

  if (entries.some((entry) => entry.marker === "revoked" && entry.blob.equals(key))) {
    return { ...base, verdict: "revoked", knownFingerprints: [] };
  }
  if (entries.some((entry) => entry.marker !== "revoked" && entry.blob.equals(key))) {
    return { ...base, verdict: "match", knownFingerprints: [] };
  }

  // Only keys of the same type count as a conflict: a host legitimately
  // offers an ed25519 key even when only its RSA key was recorded.
  const sameType = entries.filter((entry) => entry.keyType === keyType);
  if (sameType.length > 0) {
    return {
      ...base,
      verdict: "changed",
      knownFingerprints: sameType.map((entry) => keyFingerprint(entry.blob)),
    };
  }

  return { ...base, verdict: "unknown", knownFingerprints: [] };
}

/** Append a host key, creating the file and its directory if needed. */
export function addKnownHost(
  host: string,
  port: number,
  key: Buffer,
  file = defaultKnownHostsPath(),
): void {
  const line = `${hostPattern(host, port)} ${keyBlobType(key)} ${key.toString("base64")}\n`;
  const dir = path.dirname(file);

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  // A known_hosts that already exists keeps its permissions; a new one is
  // created the way OpenSSH would.
  const needsNewline =
    fs.existsSync(file) && fs.statSync(file).size > 0 && !fs.readFileSync(file, "utf-8").endsWith("\n");

  fs.appendFileSync(file, `${needsNewline ? "\n" : ""}${line}`, { mode: 0o600 });
}

/** The message shown when a host's key does not match what was recorded. */
export function describeChangedKey(check: HostKeyCheck, host: string): string {
  return [
    `HOST KEY CHANGED for ${host}.`,
    "",
    `Offered:  ${check.keyType} ${check.fingerprint}`,
    `Recorded: ${check.knownFingerprints.join(", ")}`,
    `In:       ${check.file}`,
    "",
    "This is what a machine-in-the-middle looks like. It is also what a",
    "legitimately reinstalled server looks like. Do not connect until you know",
    "which one it is: confirm the fingerprint out of band, then remove the old",
    `line with: ssh-keygen -R ${host}`,
  ].join("\n");
}
