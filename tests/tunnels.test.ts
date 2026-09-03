/**
 * Port forwarding, end to end.
 *
 * A tunnel that reports itself as up but moves no bytes is worse than one
 * that fails loudly, so these push real data through both directions against
 * the real sshd rather than asserting on state.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import * as net from "node:net";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  _runningCount,
  listTunnels,
  startTunnel,
  stopAllTunnels,
  stopTunnel,
  validateDefinition,
} from "../src/tunnels.ts";
import type { SshProfile } from "../src/types.ts";
import { startTestServer, type TestServer } from "./sshd.ts";

let server: TestServer = null;
let echo: net.Server;
let echoPort = 0;
let workspace: string;

/** A service to forward to: it echoes whatever it receives, upper-cased. */
function startEcho(): Promise<{ server: net.Server; port: number }> {
  return new Promise((resolve) => {
    const srv = net.createServer((socket) => {
      socket.on("data", (chunk) => socket.write(chunk.toString().toUpperCase()));
    });
    srv.listen(0, "127.0.0.1", () => {
      resolve({ server: srv, port: (srv.address() as net.AddressInfo).port });
    });
  });
}

/** Send one line through a port and wait for the reply. */
function roundTrip(port: number, payload: string, host = "127.0.0.1"): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, host, () => socket.write(payload));
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("no reply through the tunnel"));
    }, 5000);

    socket.on("data", (chunk) => {
      clearTimeout(timer);
      socket.destroy();
      resolve(chunk.toString());
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

function profileFor(): SshProfile {
  return {
    host: "127.0.0.1",
    port: server!.port,
    user: server!.user,
    privateKeyPath: server!.clientKeyPath,
    knownHostsFile: path.join(workspace, "known_hosts"),
    strictHostKey: false,
  };
}

before(async () => {
  server = await startTestServer();
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ssh-tunnel-"));
  const started = await startEcho();
  echo = started.server;
  echoPort = started.port;
});

after(async () => {
  await stopAllTunnels();
  echo?.close();
  server?.stop();
  if (workspace) fs.rmSync(workspace, { recursive: true, force: true });
});

describe("validateDefinition", () => {
  it("rejects an unknown direction", () => {
    assert.throws(
      () => validateDefinition({ kind: "sideways" as any, listenPort: 1, destHost: "h", destPort: 2 }),
      /Unknown tunnel kind/,
    );
  });

  it("rejects impossible ports", () => {
    assert.throws(
      () => validateDefinition({ kind: "local", listenPort: 1, destHost: "h", destPort: 0 }),
      /destPort must be an integer between 1/,
    );
    assert.throws(
      () => validateDefinition({ kind: "local", listenPort: -1, destHost: "h", destPort: 2 }),
      /listenPort/,
    );
  });

  it("allows listenPort 0, which means pick a free one", () => {
    validateDefinition({ kind: "local", listenPort: 0, destHost: "h", destPort: 2 });
  });

  it("rejects an empty destination", () => {
    assert.throws(
      () => validateDefinition({ kind: "local", listenPort: 1, destHost: " ", destPort: 2 }),
      /destHost/,
    );
  });
});

describe("local forwarding", () => {
  it("carries real traffic from this machine to a service behind the server", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const tunnel = await startTunnel({
      profileName: "p",
      profile: profileFor(),
      name: "echo",
      definition: { kind: "local", listenPort: 0, destHost: "127.0.0.1", destPort: echoPort },
    });

    const localPort = Number(tunnel.listenAddress.split(":")[1]);
    assert.ok(localPort > 0);
    assert.strictEqual(await roundTrip(localPort, "through the tunnel"), "THROUGH THE TUNNEL");

    await stopTunnel("p", "echo");
  });

  it("binds loopback unless told otherwise", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const tunnel = await startTunnel({
      profileName: "p",
      profile: profileFor(),
      name: "loopback",
      definition: { kind: "local", listenPort: 0, destHost: "127.0.0.1", destPort: echoPort },
    });
    assert.match(tunnel.listenAddress, /^127\.0\.0\.1:/);
    await stopTunnel("p", "loopback");
  });

  it("refuses a second tunnel with the same name", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const definition = { kind: "local" as const, listenPort: 0, destHost: "127.0.0.1", destPort: echoPort };
    await startTunnel({ profileName: "p", profile: profileFor(), name: "dup", definition });

    await assert.rejects(
      () => startTunnel({ profileName: "p", profile: profileFor(), name: "dup", definition }),
      /already running/,
    );
    await stopTunnel("p", "dup");
  });

  it("reports a port that is already taken", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const blocker = net.createServer();
    const taken = await new Promise<number>((resolve) => {
      blocker.listen(0, "127.0.0.1", () => resolve((blocker.address() as net.AddressInfo).port));
    });

    try {
      await assert.rejects(
        () =>
          startTunnel({
            profileName: "p",
            profile: profileFor(),
            name: "busy",
            definition: { kind: "local", listenPort: taken, destHost: "127.0.0.1", destPort: echoPort },
          }),
        /already in use/,
      );
    } finally {
      blocker.close();
    }
  });

  it("stops listening once stopped", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const tunnel = await startTunnel({
      profileName: "p",
      profile: profileFor(),
      name: "transient",
      definition: { kind: "local", listenPort: 0, destHost: "127.0.0.1", destPort: echoPort },
    });
    const port = Number(tunnel.listenAddress.split(":")[1]);
    assert.strictEqual(await stopTunnel("p", "transient"), true);

    await assert.rejects(() => roundTrip(port, "anyone there"), /ECONNREFUSED|no reply/);
    assert.strictEqual(await stopTunnel("p", "transient"), false);
  });
});

describe("remote forwarding", () => {
  it("lets the server reach a service on this machine", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const tunnel = await startTunnel({
      profileName: "p",
      profile: profileFor(),
      name: "back",
      definition: { kind: "remote", listenPort: 0, destHost: "127.0.0.1", destPort: echoPort },
    });

    const remotePort = Number(tunnel.listenAddress.split(":")[1]);
    assert.ok(remotePort > 0, "the server should report the port it bound");

    // sshd and this test share a machine, so its listening port is reachable
    // here -- the bytes still travel out through the SSH connection and back.
    assert.strictEqual(await roundTrip(remotePort, "reverse"), "REVERSE");

    await stopTunnel("p", "back");
  });
});

describe("the registry", () => {
  it("lists what is running with its destination", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    await startTunnel({
      profileName: "p",
      profile: profileFor(),
      name: "listed",
      definition: {
        kind: "local",
        listenPort: 0,
        destHost: "127.0.0.1",
        destPort: echoPort,
        description: "the echo service",
      },
    });

    const entry = listTunnels().find((tunnel) => tunnel.name === "listed");
    assert.ok(entry);
    assert.strictEqual(entry!.profile, "p");
    assert.strictEqual(entry!.definition.destPort, echoPort);
    assert.match(entry!.startedAt, /^\d{4}-/);
  });

  it("counts the connections that went through", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const before = listTunnels().find((tunnel) => tunnel.name === "listed")!.connections;
    const port = Number(
      listTunnels().find((tunnel) => tunnel.name === "listed")!.listenAddress.split(":")[1],
    );
    await roundTrip(port, "one");
    await roundTrip(port, "two");

    const after = listTunnels().find((tunnel) => tunnel.name === "listed")!.connections;
    assert.ok(after >= before + 2, `expected at least two more connections, saw ${after - before}`);
  });

  it("records a time limit when one is given", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const tunnel = await startTunnel({
      profileName: "p",
      profile: profileFor(),
      name: "timed",
      definition: { kind: "local", listenPort: 0, destHost: "127.0.0.1", destPort: echoPort },
      durationSeconds: 60,
    });
    assert.ok(tunnel.expiresAt);
    assert.ok(Date.parse(tunnel.expiresAt!) > Date.now());
    await stopTunnel("p", "timed");
  });

  it("closes everything at once, which is what session shutdown does", async (t) => {
    if (!server) return t.skip("no sshd on this machine");

    const stopped = await stopAllTunnels();
    assert.ok(stopped >= 1);
    assert.strictEqual(_runningCount(), 0);
    assert.deepStrictEqual(listTunnels(), []);
  });
});
