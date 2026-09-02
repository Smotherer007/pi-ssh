/**
 * Turning a password login into a key login.
 *
 * This is what `ssh-copy-id` does, except it runs inside pi and therefore
 * works on Windows too, where neither ssh-copy-id nor ssh-keygen is normally
 * present. The steps are deliberately conservative: the existing
 * authorized_keys is read before anything is written, the key is only
 * appended when it is not already there, and the password stays in the
 * profile unless the caller asks for it to go -- losing both at once would
 * lock the user out of their own host.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import ssh2 from "ssh2";
import type { AuthorizeResult, SshProfile } from "./types.ts";
import { execCommand, shellQuote, withConnection } from "./clients/ssh-client.ts";
import { expandPath, updateProfile } from "./config.ts";
import {
  defaultKeyComment,
  formatPublicKeyLineFromBlob,
  generateKeyPair,
  keyFingerprint,
  publicKeyBlob,
  sameKeyMaterial,
} from "./keys.ts";

export interface AuthorizeOptions {
  readonly profileName: string;
  readonly profile: SshProfile;
  /** Where the key lives. Defaults to ~/.ssh/id_ed25519_pi_<profile>. */
  readonly keyPath?: string;
  readonly comment?: string;
  readonly acceptNewHostKey?: boolean;
  /** Drop the stored password once a key-only login is proven to work. */
  readonly removePassword?: boolean;
  /**
   * Absolute path of the remote authorized_keys, for hosts whose sshd is
   * configured with a non-standard AuthorizedKeysFile. Defaults to
   * ~/.ssh/authorized_keys on the remote account.
   */
  readonly authorizedKeysPath?: string;
  readonly signal?: AbortSignal;
}

/** Dirname on the remote host, which is POSIX regardless of our platform. */
function posixDirname(remotePath: string): string {
  const trimmed = remotePath.replace(/\/+$/, "");
  const index = trimmed.lastIndexOf("/");
  return index <= 0 ? "/" : trimmed.slice(0, index);
}

/** A profile name reduced to something safe to put in a file name. */
export function keyFileNameFor(profileName: string): string {
  const slug = profileName.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  return `id_ed25519_pi_${slug || "host"}`;
}

export function defaultKeyPath(profileName: string): string {
  const home = process.env.HOME || process.env.USERPROFILE || os.homedir();
  return path.join(home, ".ssh", keyFileNameFor(profileName));
}

interface LocalKey {
  readonly privateKeyPath: string;
  readonly publicKeyPath: string;
  readonly publicKeyLine: string;
  readonly fingerprint: string;
  readonly created: boolean;
}

/**
 * Use the key at `keyPath`, generating one if it is not there.
 *
 * An existing key is reused rather than replaced: overwriting it would
 * silently invalidate every other host that already trusts it.
 */
export function ensureLocalKey(
  keyPath: string,
  comment: string,
): LocalKey {
  const privateKeyPath = expandPath(keyPath);
  const publicKeyPath = `${privateKeyPath}.pub`;

  if (fs.existsSync(privateKeyPath)) {
    const parsed = ssh2.utils.parseKey(fs.readFileSync(privateKeyPath));
    if (parsed instanceof Error) {
      throw new Error(
        `The key at ${privateKeyPath} could not be read: ${parsed.message}. If it has a passphrase, this bootstrap cannot use it; point keyPath somewhere else.`,
      );
    }
    const blob = (parsed as { getPublicSSH(): Buffer }).getPublicSSH();
    const line = fs.existsSync(publicKeyPath)
      ? fs.readFileSync(publicKeyPath, "utf-8").trim()
      : formatPublicKeyLineFromBlob(blob, comment);

    return {
      privateKeyPath,
      publicKeyPath,
      publicKeyLine: line,
      fingerprint: keyFingerprint(blob),
      created: false,
    };
  }

  const generated = generateKeyPair(comment);
  fs.mkdirSync(path.dirname(privateKeyPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(privateKeyPath, generated.privateKey, { mode: 0o600 });
  fs.chmodSync(privateKeyPath, 0o600);
  fs.writeFileSync(publicKeyPath, `${generated.publicKey}\n`, { mode: 0o644 });

  return {
    privateKeyPath,
    publicKeyPath,
    publicKeyLine: generated.publicKey,
    fingerprint: generated.fingerprint,
    created: true,
  };
}

/**
 * Put a public key into the remote authorized_keys, exactly once.
 *
 * Done over exec rather than SFTP so that ~ is expanded by the remote shell
 * and the permissions are set in the same breath -- sshd silently ignores an
 * authorized_keys that is group-writable.
 */
export async function installPublicKey(
  connection: Parameters<typeof execCommand>[0],
  publicKeyLine: string,
  options: { signal?: AbortSignal; authorizedKeysPath?: string } = {},
): Promise<{ path: string; installed: boolean }> {
  const { signal } = options;

  // Without an override the remote shell expands $HOME, which is the only
  // way to learn where the account actually lives. A host configured with a
  // non-standard AuthorizedKeysFile needs to say so explicitly.
  const file = options.authorizedKeysPath
    ? shellQuote(options.authorizedKeysPath)
    : '"$HOME/.ssh/authorized_keys"';
  const dir = options.authorizedKeysPath
    ? shellQuote(posixDirname(options.authorizedKeysPath))
    : '"$HOME/.ssh"';

  const prepare = await execCommand(
    connection,
    `umask 077 && mkdir -p ${dir} && touch ${file} && chmod 700 ${dir} && chmod 600 ${file} && printf '%s' ${file}`,
    { signal, timeoutMs: 30_000 },
  );
  if (prepare.code !== 0) {
    throw new Error(
      `Could not prepare the remote .ssh directory: ${prepare.stderr.trim() || `exit ${prepare.code}`}`,
    );
  }
  const authorizedKeysPath = prepare.stdout.trim() || "~/.ssh/authorized_keys";

  const existing = await execCommand(connection, `cat ${file}`, {
    signal,
    timeoutMs: 30_000,
  });
  const alreadyThere = existing.stdout
    .split(/\r?\n/)
    .some((line) => sameKeyMaterial(line, publicKeyLine));

  if (alreadyThere) {
    return { path: authorizedKeysPath, installed: false };
  }

  const append = await execCommand(
    connection,
    `printf '%s\\n' ${shellQuote(publicKeyLine)} >> ${file}`,
    { signal, timeoutMs: 30_000 },
  );
  if (append.code !== 0) {
    throw new Error(
      `Could not write to the remote authorized_keys: ${append.stderr.trim() || `exit ${append.code}`}`,
    );
  }
  return { path: authorizedKeysPath, installed: true };
}

/**
 * Generate a key if needed, install it on the host, switch the profile over,
 * and prove that a key-only login works.
 */
export async function authorizeKey(options: AuthorizeOptions): Promise<AuthorizeResult> {
  const { profile, profileName } = options;
  const comment = options.comment ?? defaultKeyComment(profile.user, profile.host);
  const keyPath = options.keyPath ?? defaultKeyPath(profileName);

  const local = ensureLocalKey(keyPath, comment);

  // The first connection deliberately does not use the new key: it is not on
  // the host yet, and falling back would hide a broken password.
  const only = profile.password ? "password" : undefined;
  const { path: authorizedKeysPath, installed } = await withConnection(
    profile,
    { signal: options.signal, acceptNewHostKey: options.acceptNewHostKey, only },
    (connection) =>
      installPublicKey(connection, local.publicKeyLine, {
        signal: options.signal,
        authorizedKeysPath: options.authorizedKeysPath,
      }),
  );

  // Record the key before verifying, so a failed verification still leaves a
  // usable profile that the user can retry with.
  updateProfile(profileName, { privateKeyPath: local.privateKeyPath });

  let verified = false;
  try {
    await withConnection(
      { ...profile, privateKeyPath: local.privateKeyPath },
      { signal: options.signal, only: "key" },
      async () => undefined,
    );
    verified = true;
  } catch {
    verified = false;
  }

  // Only give up the password once the key is proven, and only on request.
  if (verified && options.removePassword) {
    updateProfile(profileName, { password: undefined });
  }

  return {
    profile: profileName,
    keyPath: local.privateKeyPath,
    publicKeyPath: local.publicKeyPath,
    fingerprint: local.fingerprint,
    installed,
    verified,
    authorizedKeysPath,
  };
}
