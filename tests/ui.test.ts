/**
 * Keeping open tunnels on screen.
 *
 * The display has to survive the two things that make it useful: an interface
 * that does not exist (rpc, json and print modes, or an older pi without
 * these methods), and a tunnel closing, which must clear the surface rather
 * than leave a stale entry claiming a forward is still open.
 */
import { describe, it, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  createTunnelIndicator,
  renderTunnelLines,
  renderTunnelStatus,
} from "../src/ui.ts";
import {
  _clearListeners,
  onTunnelsChanged,
  startTunnel,
  stopAllTunnels,
  stopTunnel,
} from "../src/tunnels.ts";
import type { RunningTunnel, SshProfile } from "../src/types.ts";
import { startTestServer, type TestServer } from "./sshd.ts";

const local: RunningTunnel = {
  id: "staging:db",
  profile: "staging",
  name: "db",
  definition: { kind: "local", listenPort: 5432, destHost: "db.internal", destPort: 5432 },
  listenAddress: "127.0.0.1:5432",
  startedAt: "2026-09-02T10:00:00.000Z",
  connections: 3,
};

const remote: RunningTunnel = {
  ...local,
  id: "staging:preview",
  name: "preview",
  definition: { kind: "remote", listenPort: 8080, destHost: "127.0.0.1", destPort: 3000 },
  listenAddress: "127.0.0.1:8080",
  expiresAt: "2026-09-02T11:30:00.000Z",
};

describe("what the indicator shows", () => {
  it("shows where a local tunnel listens and where it goes", () => {
    const [line] = renderTunnelLines([local]);
    assert.match(line, /staging\/db/);
    assert.match(line, /127\.0\.0\.1:5432 -> db\.internal:5432/);
  });

  it("points the arrow the other way for a remote tunnel", () => {
    const [line] = renderTunnelLines([remote]);
    assert.match(line, /127\.0\.0\.1:8080 <- 127\.0\.0\.1:3000/);
  });

  it("mentions a time limit when there is one", () => {
    assert.match(renderTunnelLines([remote])[0], /until 11:30Z/);
    assert.ok(!renderTunnelLines([local])[0].includes("until"));
  });

  it("renders one line per tunnel, and none for none", () => {
    assert.strictEqual(renderTunnelLines([local, remote]).length, 2);
    assert.deepStrictEqual(renderTunnelLines([]), []);
  });

  it("names the single tunnel in the footer, and counts several", () => {
    assert.match(renderTunnelStatus([local]), /SSH tunnel db on 127\.0\.0\.1:5432/);
    assert.strictEqual(renderTunnelStatus([local, remote]), "2 SSH tunnels open");
  });

  it("says nothing in the footer when nothing is open", () => {
    assert.strictEqual(renderTunnelStatus([]), "");
  });
});

describe("drawing on whatever pi offers", () => {
  it("uses both surfaces when both exist", () => {
    const calls: string[] = [];
    const show = createTunnelIndicator({
      hasUI: true,
      ui: {
        setWidget: (id, lines) => calls.push(`widget:${id}:${lines.length}`),
        setStatus: (id, text) => calls.push(`status:${id}:${text}`),
      },
    });

    show([local]);
    assert.deepStrictEqual(calls, [
      "widget:pi-ssh-tunnels:1",
      "status:pi-ssh-tunnels:SSH tunnel db on 127.0.0.1:5432",
    ]);
  });

  it("clears both when the last tunnel closes", () => {
    const calls: Array<{ lines?: string[]; text?: string }> = [];
    const show = createTunnelIndicator({
      ui: {
        setWidget: (_id, lines) => calls.push({ lines }),
        setStatus: (_id, text) => calls.push({ text }),
      },
    });

    show([]);
    // An empty widget and an empty status are how the surface is cleared; a
    // stale entry would claim a forward is open when it is not.
    assert.deepStrictEqual(calls[0].lines, []);
    assert.strictEqual(calls[1].text, "");
  });

  it("copes with a pi that has only one of the two", () => {
    let seen = "";
    const onlyStatus = createTunnelIndicator({ ui: { setStatus: (_id, text) => (seen = text) } });
    onlyStatus([local]);
    assert.match(seen, /SSH tunnel db/);

    let lines: string[] = [];
    const onlyWidget = createTunnelIndicator({ ui: { setWidget: (_id, l) => (lines = l) } });
    onlyWidget([local]);
    assert.strictEqual(lines.length, 1);
  });

  it("does nothing at all when there is no interface", () => {
    // rpc, json and print modes have none, and that is not an error.
    assert.doesNotThrow(() => createTunnelIndicator(undefined)([local]));
    assert.doesNotThrow(() => createTunnelIndicator({})([local]));
    assert.doesNotThrow(() => createTunnelIndicator({ hasUI: false, ui: {} })([local]));
  });

  it("survives an interface that throws", () => {
    const show = createTunnelIndicator({
      ui: {
        setWidget: () => {
          throw new Error("terminal went away");
        },
      },
    });
    // A broken display must never take a tunnel down with it.
    assert.doesNotThrow(() => show([local]));
  });
});

describe("the indicator follows real tunnels", () => {
  let server: TestServer = null;
  let workspace: string;

  beforeEach(() => {
    _clearListeners();
  });

  after(async () => {
    await stopAllTunnels();
    _clearListeners();
    server?.stop();
    if (workspace) fs.rmSync(workspace, { recursive: true, force: true });
  });

  it("is told when a tunnel opens and when it closes", async (t) => {
    server = await startTestServer();
    if (!server) return t.skip("no sshd on this machine");
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ssh-ui-"));

    const seen: number[] = [];
    onTunnelsChanged((tunnels) => seen.push(tunnels.length));

    const profile: SshProfile = {
      host: "127.0.0.1",
      port: server.port,
      user: server.user,
      privateKeyPath: server.clientKeyPath,
      knownHostsFile: path.join(workspace, "known_hosts"),
      strictHostKey: false,
    };

    await startTunnel({
      profileName: "ui",
      profile,
      name: "watched",
      definition: { kind: "local", listenPort: 0, destHost: "127.0.0.1", destPort: server.port },
    });
    await stopTunnel("ui", "watched");

    assert.deepStrictEqual(seen, [1, 0], "expected one notification on open and one on close");
  });
});
