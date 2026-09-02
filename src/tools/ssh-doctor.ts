/**
 * ssh_doctor tool -- Report what the environment can do and what it cannot.
 */

import { Type } from "typebox";
import { formatChecks, runChecks } from "../doctor.ts";

export const SshDoctorTool = {
  name: "ssh_doctor",
  label: "SSH Doctor",
  description:
    "Check whether this machine can use the SSH tools and report anything that needs fixing or installing. Run it when a connection fails for reasons that are not about the remote host, or when the user asks what they need to install. Nothing external is normally required.",
  parameters: Type.Object({}),

  execute(_toolCallId: string, _params: {}, _signal: AbortSignal) {
    const checks = runChecks();
    return {
      content: [{ type: "text" as const, text: formatChecks(checks) }],
      details: {
        platform: process.platform,
        problems: checks.filter((check) => check.status === "problem").map((c) => c.name),
        checks: checks.map((check) => ({ name: check.name, status: check.status })),
      },
    };
  },
};
