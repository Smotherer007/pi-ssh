import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  describeAuth,
  formatAuthorizeResult,
  formatBytes,
  formatDirectory,
  formatExecResult,
  formatIdentity,
  formatProfileStatus,
  formatTransfer,
} from "../src/formatting/formatters.ts";
import type { SshProfile } from "../src/types.ts";

const staging: SshProfile = { host: "staging.example", port: 22, user: "deploy", password: "hunter2-swordfish" };
const nas: SshProfile = { host: "10.0.0.5", port: 2222, user: "pat", privateKeyPath: "/keys/nas" };

describe("formatBytes", () => {
  it("scales through the units", () => {
    assert.strictEqual(formatBytes(0), "0 B");
    assert.strictEqual(formatBytes(1536), "1.5 KB");
    assert.strictEqual(formatBytes(1024 * 1024 * 5), "5.0 MB");
  });

  it("handles nonsense", () => {
    assert.strictEqual(formatBytes(-1), "unknown size");
    assert.strictEqual(formatBytes(Number.NaN), "unknown size");
  });
});

describe("describeAuth", () => {
  it("names the key path but never the password itself", () => {
    assert.strictEqual(describeAuth(nas), "key /keys/nas");
    const both = describeAuth({ ...nas, password: "hunter2" });
    assert.match(both, /password \(stored\)/);
    assert.ok(!both.includes("hunter2"));
  });

  it("says so when nothing is configured", () => {
    assert.strictEqual(describeAuth({ host: "h", port: 22, user: "u" }), "none configured");
  });
});

describe("formatProfileStatus", () => {
  it("points at ssh_setup when empty", () => {
    assert.match(formatProfileStatus({}, null), /ssh_setup/);
  });

  it("marks the active host and hides the port when it is 22", () => {
    const text = formatProfileStatus({ staging, nas }, "staging");
    assert.match(text, /\* staging: deploy@staging\.example$/m);
    assert.match(text, /^ {2}nas: pat@10\.0\.0\.5:2222$/m);
  });

  it("calls out a profile with host key checking disabled", () => {
    const text = formatProfileStatus({ risky: { ...nas, strictHostKey: false } }, "risky");
    assert.match(text, /host key checking is OFF/);
  });

  it("never prints a stored password", () => {
    assert.ok(!formatProfileStatus({ staging }, "staging").includes("hunter2-swordfish"));
  });
});

describe("formatIdentity", () => {
  it("shows the fingerprint and how authentication happened", () => {
    const text = formatIdentity({
      host: "h", port: 22, user: "u",
      fingerprint: "SHA256:abc", keyType: "ssh-ed25519",
      hostKeyVerdict: "match", authMethod: "key",
    });
    assert.match(text, /Connected: u@h:22/);
    assert.match(text, /Authenticated with: key/);
    assert.match(text, /ssh-ed25519 SHA256:abc \(match\)/);
  });
});

describe("formatExecResult", () => {
  const base = { command: "ls", stdout: "", stderr: "", code: 0, durationMs: 12, truncated: false };

  it("echoes the command and the exit status", () => {
    const text = formatExecResult({ ...base, stdout: "a\nb\n" });
    assert.match(text, /^\$ ls/m);
    assert.match(text, /\[exit 0, 12 ms\]/);
    assert.match(text, /a\nb/);
  });

  it("labels stderr separately", () => {
    const text = formatExecResult({ ...base, code: 1, stderr: "went wrong\n" });
    assert.match(text, /\[exit 1/);
    assert.match(text, /stderr:\nwent wrong/);
  });

  it("reports a signal instead of a code when killed", () => {
    const text = formatExecResult({ ...base, code: null, signal: "SIGKILL" });
    assert.match(text, /killed by SIGKILL/);
  });

  it("says so when there was no output at all", () => {
    assert.match(formatExecResult(base), /\(no output\)/);
  });
});

describe("formatDirectory", () => {
  it("says when a directory is empty", () => {
    assert.match(formatDirectory([], "/tmp"), /\/tmp is empty/);
  });

  it("marks directories and symlinks", () => {
    const text = formatDirectory(
      [
        { name: "logs", type: "directory", size: 0, mode: "rwxr-xr-x" },
        { name: "link", type: "symlink", size: 0, mode: "rwxrwxrwx" },
        { name: "a.txt", type: "file", size: 2048, mode: "rw-r--r--", modified: "2026-01-02T03:04:05.000Z" },
      ],
      "/srv",
    );
    assert.match(text, /logs\/$/m);
    assert.match(text, /link@$/m);
    assert.match(text, /2\.0 KB {2}a\.txt$/m);
    assert.match(text, /2026-01-02/);
  });
});

describe("formatTransfer", () => {
  it("names both ends and the size", () => {
    const result = { localPath: "/l/a", remotePath: "/r/a", size: 1024 };
    assert.match(formatTransfer(result, "up"), /Uploaded \/l\/a to \/r\/a \(1\.0 KB\)/);
    assert.match(formatTransfer(result, "down"), /Downloaded \/r\/a to \/l\/a/);
  });
});

describe("formatAuthorizeResult", () => {
  const base = {
    profile: "staging",
    keyPath: "/home/pat/.ssh/id_ed25519_pi_staging",
    publicKeyPath: "/home/pat/.ssh/id_ed25519_pi_staging.pub",
    fingerprint: "SHA256:abc",
    authorizedKeysPath: "/home/deploy/.ssh/authorized_keys",
    installed: true,
    verified: true,
  };

  it("confirms a fresh install and the verification", () => {
    const text = formatAuthorizeResult(base);
    assert.match(text, /Key installed on the remote host/);
    assert.match(text, /no password is needed from now on/);
    assert.match(text, /SHA256:abc/);
  });

  it("says plainly when the key was already there", () => {
    assert.match(formatAuthorizeResult({ ...base, installed: false }), /already in/);
  });

  it("warns rather than claiming success when verification failed", () => {
    const text = formatAuthorizeResult({ ...base, verified: false });
    assert.match(text, /Warning/);
    assert.match(text, /still in the profile as a fallback/);
  });
});
