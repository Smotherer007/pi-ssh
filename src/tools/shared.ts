/**
 * What every tool that opens a connection does first.
 *
 * Resolving the profile and upgrading it to key authentication belong
 * together: the upgrade has to happen before the connection the tool actually
 * wants, and its outcome has to reach the user, so both are done in one place
 * rather than repeated in each tool.
 */

import { resolveProfile } from "../config.ts";
import { ensureKeyAuthentication } from "../auto-key.ts";
import type { SshProfile } from "../types.ts";

export interface ConnectionContext {
  readonly name: string;
  readonly profile: SshProfile;
  /** Worth showing the user, e.g. that the password was just replaced. */
  readonly note?: string;
}

export async function resolveForConnection(
  profileName: string | undefined,
  options: { acceptNewHostKey?: boolean; signal?: AbortSignal } = {},
): Promise<ConnectionContext> {
  const { name, profile } = resolveProfile(profileName);
  const outcome = await ensureKeyAuthentication(name, profile, options);
  return { name, profile: outcome.profile, note: outcome.note };
}

/** Append a note to a tool's text output, when there is one. */
export function withNote(text: string, note?: string): string {
  return note ? `${text}\n\n${note}` : text;
}
