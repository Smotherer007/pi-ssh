/**
 * Keeping running tunnels visible.
 *
 * A tunnel outlives the tool call that opened it, so a listing that has
 * scrolled out of view is not enough: an open forward the user has forgotten
 * about is a port on their machine reaching into someone else's network. pi
 * offers two surfaces that survive scrolling -- a widget above the editor and
 * a status line in the footer -- and this uses whichever exists.
 *
 * Everything here is defensive. Extensions also run in rpc, json and print
 * modes where there is no interface at all, and an older pi may have neither
 * method; none of that is a reason for a transfer to fail.
 */

import type { RunningTunnel } from "./types.ts";

const SURFACE_ID = "pi-ssh-tunnels";

/** The subset of pi's UI this module touches, all of it optional. */
export interface UiSurface {
  setWidget?: (id: string, lines: string[]) => void;
  setStatus?: (id: string, text: string) => void;
}

export interface UiContext {
  hasUI?: boolean;
  ui?: UiSurface;
}

/** One compact line per tunnel, for the widget above the editor. */
export function renderTunnelLines(tunnels: ReadonlyArray<RunningTunnel>): string[] {
  return tunnels.map((tunnel) => {
    const arrow = tunnel.definition.kind === "local" ? "->" : "<-";
    const dest = `${tunnel.definition.destHost}:${tunnel.definition.destPort}`;
    const expiry = tunnel.expiresAt ? ` until ${tunnel.expiresAt.slice(11, 16)}Z` : "";
    return `SSH tunnel ${tunnel.profile}/${tunnel.name}: ${tunnel.listenAddress} ${arrow} ${dest}${expiry}`;
  });
}

/** A single line for the footer, where there is only room for a count. */
export function renderTunnelStatus(tunnels: ReadonlyArray<RunningTunnel>): string {
  if (tunnels.length === 0) return "";
  if (tunnels.length === 1) {
    const [only] = tunnels;
    return `SSH tunnel ${only.name} on ${only.listenAddress}`;
  }
  return `${tunnels.length} SSH tunnels open`;
}

/**
 * Build the function that pushes the current tunnels onto the interface.
 * Returns a no-op when there is nothing to draw on, so callers need no
 * special case.
 */
export function createTunnelIndicator(ctx: UiContext | undefined): (
  tunnels: ReadonlyArray<RunningTunnel>,
) => void {
  const ui = ctx?.ui;
  if (!ui || ctx?.hasUI === false) {
    return () => {};
  }

  return (tunnels) => {
    try {
      if (typeof ui.setWidget === "function") {
        // An empty array clears the widget when the last tunnel closes.
        ui.setWidget(SURFACE_ID, renderTunnelLines(tunnels));
      }
      if (typeof ui.setStatus === "function") {
        ui.setStatus(SURFACE_ID, renderTunnelStatus(tunnels));
      }
    } catch {
      // Whatever the interface does with this, it must not break a tunnel.
    }
  };
}
