/**
 * ssh_status tool -- Show configured hosts and optionally test one.
 */

import { Type } from "typebox";
import { getActiveProfile, getProfiles, resolveProfile } from "../config.ts";
import { withConnection } from "../clients/ssh-client.ts";
import { formatIdentity, formatProfileStatus } from "../formatting/formatters.ts";

export const SshStatusTool = {
  name: "ssh_status",
  label: "SSH Status",
  description:
    "List the configured SSH hosts and how each authenticates. With connect: true it also opens a connection to verify that the credentials and host key still work.",
  parameters: Type.Object({
    profile: Type.Optional(
      Type.String({ description: "Profile to check. Defaults to the active one." }),
    ),
    connect: Type.Optional(
      Type.Boolean({
        description: "Actually connect to verify the host works. Default false.",
        default: false,
      }),
    ),
  }),

  async execute(
    _toolCallId: string,
    params: { profile?: string; connect?: boolean },
    signal: AbortSignal,
  ) {
    const profiles = getProfiles();
    const overview = formatProfileStatus(profiles, getActiveProfile());

    if (Object.keys(profiles).length === 0 || !params.connect) {
      return {
        content: [{ type: "text" as const, text: overview }],
        details: {
          count: Object.keys(profiles).length,
          profiles: Object.keys(profiles),
          activeProfile: getActiveProfile(),
        },
      };
    }

    const { name, profile } = resolveProfile(params.profile);
    let connection: string;
    let reachable = false;
    try {
      const identity = await withConnection(profile, { signal }, async (conn) =>
        conn.identity,
      );
      connection = formatIdentity(identity);
      reachable = true;
    } catch (err) {
      connection = `Connection to "${name}" failed:\n${(err as Error).message}`;
    }

    return {
      content: [{ type: "text" as const, text: `${overview}\n\n${connection}` }],
      details: {
        count: Object.keys(profiles).length,
        profiles: Object.keys(profiles),
        activeProfile: getActiveProfile(),
        checked: name,
        reachable,
      },
    };
  },
};
