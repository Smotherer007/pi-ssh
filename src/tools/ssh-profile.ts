/**
 * ssh_profile tool -- List, switch or delete stored hosts.
 */

import { Type } from "typebox";
import {
  deleteProfile,
  getActiveProfile,
  getProfiles,
  setActiveProfile,
} from "../config.ts";
import { formatProfileStatus } from "../formatting/formatters.ts";

export const SshProfileTool = {
  name: "ssh_profile",
  label: "Manage SSH Profiles",
  description:
    "List configured SSH hosts, switch the active one, or delete one. Without arguments it lists them.",
  parameters: Type.Object({
    action: Type.Optional(
      Type.String({ description: "One of: list, use, delete. Defaults to list." }),
    ),
    name: Type.Optional(
      Type.String({ description: "Profile name for 'use' and 'delete'." }),
    ),
  }),

  execute(
    _toolCallId: string,
    params: { action?: string; name?: string },
    _signal: AbortSignal,
  ) {
    const action = (params.action || "list").toLowerCase();

    if (action === "list") {
      return {
        content: [
          {
            type: "text" as const,
            text: formatProfileStatus(getProfiles(), getActiveProfile()),
          },
        ],
        details: {
          profiles: Object.keys(getProfiles()),
          activeProfile: getActiveProfile(),
        },
      };
    }

    if (!params.name) {
      throw new Error(`The "${action}" action requires a profile name.`);
    }

    if (action === "use") {
      setActiveProfile(params.name);
      return {
        content: [
          { type: "text" as const, text: `Active SSH profile is now "${params.name}".` },
        ],
        details: { activeProfile: params.name },
      };
    }

    if (action === "delete") {
      const removed = deleteProfile(params.name);
      const text = removed
        ? `Profile "${params.name}" deleted. Active profile is now ${getActiveProfile() ? `"${getActiveProfile()}"` : "unset"}.`
        : `No profile named "${params.name}".`;
      return {
        content: [{ type: "text" as const, text }],
        details: { deleted: removed, activeProfile: getActiveProfile() },
      };
    }

    throw new Error(`Unknown action "${params.action}". Use one of: list, use, delete.`);
  },
};
