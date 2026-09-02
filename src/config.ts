/**
 * Configuration persistence and state.
 *
 * Stores named host profiles in ~/.pi/ssh-config.json.
 * Supports multiple profiles with an active profile selector.
 *
 * File format:
 *   { "profiles": { "name": SshProfile, ... }, "activeProfile": "name" }
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { SshProfile, SshProfiles } from "./types.ts";
import { SshNotConfiguredError } from "./types.ts";

let profiles: Record<string, SshProfile> = {};
let activeProfile: string | null = null;

function configPath(): string {
  const home = process.env.HOME || process.env.USERPROFILE || "~";
  return path.join(home, ".pi", "ssh-config.json");
}

/** Expand a leading ~ and resolve to an absolute path. */
export function expandPath(input: string): string {
  const raw = String(input ?? "").trim();
  if (!raw) return raw;
  const home = process.env.HOME || process.env.USERPROFILE || os.homedir();
  if (raw === "~") return home;
  if (raw.startsWith("~/") || raw.startsWith("~\\")) {
    return path.join(home, raw.slice(2));
  }
  return path.resolve(raw);
}

/**
 * Write the profile store.
 *
 * The file can hold passwords and key passphrases, so it must never be group-
 * or world-readable. writeFileSync's `mode` only applies when the file is
 * created, so an existing file keeps its old permissions -- we therefore write
 * to a private temp file and rename it into place, which is also atomic.
 */
function persistProfiles(): void {
  const filePath = configPath();
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const data: SshProfiles = { profiles, activeProfile };
  const tmpPath = `${filePath}.${process.pid}.tmp`;

  try {
    fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), {
      encoding: "utf-8",
      mode: 0o600,
    });
    fs.chmodSync(tmpPath, 0o600);
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      /* ignore */
    }
    throw err;
  }
}

export function loadConfig(): void {
  try {
    const filePath = configPath();
    if (!fs.existsSync(filePath)) {
      profiles = {};
      activeProfile = null;
      return;
    }

    const raw = JSON.parse(fs.readFileSync(filePath, "utf-8"));

    // Tighten permissions on files written by older versions.
    try {
      const mode = fs.statSync(filePath).mode & 0o777;
      if (mode !== 0o600) fs.chmodSync(filePath, 0o600);
    } catch {
      /* ignore */
    }

    if (raw && typeof raw === "object" && raw.profiles) {
      profiles = raw.profiles;
      if (raw.activeProfile && profiles[raw.activeProfile]) {
        activeProfile = raw.activeProfile;
      } else {
        const names = Object.keys(profiles);
        activeProfile = names.length > 0 ? names[0] : null;
      }
    }
  } catch {
    profiles = {};
    activeProfile = null;
  }
}

export function getConfig(): SshProfile | null {
  if (!activeProfile) return null;
  return profiles[activeProfile] ?? null;
}

export function getProfile(name: string): SshProfile | null {
  return profiles[name] ?? null;
}

/**
 * Resolve a profile parameter: if a name is given, return that profile
 * (or throw if not found). Otherwise, return the active profile or throw.
 */
export function resolveProfile(name?: string): { name: string; profile: SshProfile } {
  if (name) {
    const profile = getProfile(name);
    if (!profile) {
      throw new Error(
        `Profile "${name}" not found. Available: ${Object.keys(profiles).join(", ") || "none"}`,
      );
    }
    return { name, profile };
  }
  const profile = getConfig();
  if (!profile || !activeProfile) {
    throw new SshNotConfiguredError();
  }
  return { name: activeProfile, profile };
}

export function getProfiles(): Record<string, SshProfile> {
  return { ...profiles };
}

export function getActiveProfile(): string | null {
  return activeProfile;
}

export function saveProfile(name: string, profile: SshProfile): void {
  profiles[name] = profile;
  if (!activeProfile || Object.keys(profiles).length === 1) {
    activeProfile = name;
  }
  persistProfiles();
}

/** Merge changes into an existing profile, keeping everything else. */
export function updateProfile(name: string, patch: Partial<SshProfile>): SshProfile {
  const existing = profiles[name];
  if (!existing) {
    throw new Error(`Profile "${name}" does not exist.`);
  }
  const updated = { ...existing, ...patch };
  profiles[name] = updated;
  persistProfiles();
  return updated;
}

export function setActiveProfile(name: string): void {
  if (!profiles[name]) {
    throw new Error(
      `Profile "${name}" does not exist. Available: ${Object.keys(profiles).join(", ") || "none"}`,
    );
  }
  activeProfile = name;
  persistProfiles();
}

export function deleteProfile(name: string): boolean {
  if (!profiles[name]) return false;
  delete profiles[name];
  if (activeProfile === name) {
    const names = Object.keys(profiles);
    activeProfile = names.length > 0 ? names[0] : null;
  }
  persistProfiles();
  return true;
}

/** @internal Reset state -- for testing only */
export function _resetForTesting(): void {
  profiles = {};
  activeProfile = null;
}
