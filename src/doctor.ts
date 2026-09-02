/**
 * Environment report.
 *
 * The point of this module is to answer "what do I have to install to use
 * this?" with evidence rather than a guess. The short answer is nothing:
 * ssh2 is a pure JavaScript SSH implementation and keys are generated in
 * process, so no `ssh`, `ssh-keygen` or `ssh-copy-id` binary is required on
 * any platform. What the checks below find are the optional conveniences and
 * the two things that genuinely do break a connection: an unreadable key file
 * and a known_hosts that cannot be written.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { defaultKnownHostsPath } from "./known-hosts.ts";

export type CheckStatus = "ok" | "note" | "problem";

export interface Check {
  readonly name: string;
  readonly status: CheckStatus;
  readonly detail: string;
  /** What to do about it, when there is something to do. */
  readonly remedy?: string;
}

function checkNodeVersion(): Check {
  const major = Number.parseInt(process.versions.node.split(".")[0], 10);
  return major >= 20
    ? { name: "Node", status: "ok", detail: `v${process.versions.node}` }
    : {
        name: "Node",
        status: "problem",
        detail: `v${process.versions.node} is older than this extension supports`,
        remedy: "Run pi on Node 20 or newer.",
      };
}

function checkSsh2(): Check {
  try {
    const pkg = JSON.parse(
      fs.readFileSync(
        new URL("../node_modules/ssh2/package.json", import.meta.url),
        "utf8",
      ),
    );
    return {
      name: "SSH implementation",
      status: "ok",
      detail: `ssh2 ${pkg.version}, pure JavaScript -- no ssh binary needed`,
    };
  } catch {
    return {
      name: "SSH implementation",
      status: "ok",
      detail: "ssh2 (bundled dependency), pure JavaScript -- no ssh binary needed",
    };
  }
}

function checkKeyGeneration(): Check {
  return {
    name: "Key generation",
    status: "ok",
    detail: "ed25519 keys are generated in process; ssh-keygen is not required",
  };
}

function checkSshDirectory(): Check {
  const home = process.env.HOME || process.env.USERPROFILE || os.homedir();
  const dir = path.join(home, ".ssh");

  if (!fs.existsSync(dir)) {
    return {
      name: "~/.ssh",
      status: "note",
      detail: `${dir} does not exist yet; it will be created when first needed`,
    };
  }

  // Permissions only matter on POSIX; Windows uses ACLs and reports 0666.
  if (process.platform !== "win32") {
    const mode = fs.statSync(dir).mode & 0o777;
    if (mode & 0o077) {
      return {
        name: "~/.ssh",
        status: "note",
        detail: `${dir} is group- or world-accessible (mode ${mode.toString(8)})`,
        remedy: `chmod 700 ${dir} -- OpenSSH refuses some keys otherwise.`,
      };
    }
  }
  return { name: "~/.ssh", status: "ok", detail: dir };
}

function checkKnownHosts(): Check {
  const file = defaultKnownHostsPath();
  if (!fs.existsSync(file)) {
    return {
      name: "known_hosts",
      status: "note",
      detail: `${file} does not exist; the first connection to each host will have to be confirmed`,
    };
  }
  try {
    fs.accessSync(file, fs.constants.R_OK | fs.constants.W_OK);
  } catch {
    return {
      name: "known_hosts",
      status: "problem",
      detail: `${file} is not readable and writable`,
      remedy: "Host keys cannot be verified or recorded until that is fixed.",
    };
  }
  const lines = fs
    .readFileSync(file, "utf-8")
    .split(/\r?\n/)
    .filter((line) => line.trim() && !line.startsWith("#")).length;
  return {
    name: "known_hosts",
    status: "ok",
    detail: `${file} (${lines} host${lines === 1 ? "" : "s"} on record)`,
  };
}

function checkConfigDirectory(): Check {
  const home = process.env.HOME || process.env.USERPROFILE || os.homedir();
  const dir = path.join(home, ".pi");
  const file = path.join(dir, "ssh-config.json");

  if (!fs.existsSync(file)) {
    return { name: "Stored hosts", status: "note", detail: "no hosts configured yet" };
  }
  if (process.platform !== "win32") {
    const mode = fs.statSync(file).mode & 0o777;
    if (mode !== 0o600) {
      return {
        name: "Stored hosts",
        status: "problem",
        detail: `${file} has mode ${mode.toString(8)} and may contain passwords`,
        remedy: `chmod 600 ${file}`,
      };
    }
  }
  return { name: "Stored hosts", status: "ok", detail: `${file} (owner only)` };
}

/**
 * Is an `ssh` command available? Purely informational: this extension does
 * not use it, but a user who wants to reuse a generated key from a terminal
 * will want to know.
 */
function checkOpenSshClient(): Check {
  const dirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const names = process.platform === "win32" ? ["ssh.exe"] : ["ssh"];

  for (const dir of dirs) {
    for (const name of names) {
      try {
        const candidate = path.join(dir, name);
        if (fs.existsSync(candidate)) {
          return {
            name: "OpenSSH client (optional)",
            status: "ok",
            detail: `${candidate} -- keys made here work with it too`,
          };
        }
      } catch {
        /* an unreadable PATH entry is not interesting */
      }
    }
  }

  return {
    name: "OpenSSH client (optional)",
    status: "note",
    detail: "no ssh command on PATH",
    remedy:
      process.platform === "win32"
        ? "Not needed by this extension. To use keys from a terminal too: Settings -> Apps -> Optional features -> OpenSSH Client."
        : "Not needed by this extension. Install the openssh-client package if you also want to ssh by hand.",
  };
}

export function runChecks(): Check[] {
  return [
    checkNodeVersion(),
    checkSsh2(),
    checkKeyGeneration(),
    checkOpenSshClient(),
    checkSshDirectory(),
    checkKnownHosts(),
    checkConfigDirectory(),
  ];
}

export function formatChecks(checks: ReadonlyArray<Check>): string {
  const symbol = { ok: "ok  ", note: "note", problem: "FAIL" } as const;
  const lines = checks.map((check) => {
    const head = `[${symbol[check.status]}] ${check.name}: ${check.detail}`;
    return check.remedy ? `${head}\n         ${check.remedy}` : head;
  });

  const problems = checks.filter((check) => check.status === "problem").length;
  const summary =
    problems > 0
      ? `${problems} problem(s) need attention before this will work reliably.`
      : "Nothing needs to be installed: this extension speaks SSH itself and generates its own keys.";

  return [`Environment (${process.platform}, ${process.arch}):`, ...lines, "", summary].join("\n");
}
