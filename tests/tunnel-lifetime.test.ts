/**
 * What happens to a tunnel when nobody stops it.
 *
 * A tunnel outlives the tool call that opened it, which makes its failure
 * modes worth pinning down: when the SSH connection underneath dies, the
 * local listener must die with it rather than accepting connections that go
 * nowhere, and the registry must stop claiming the tunnel is up.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import * as net from "node:net";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { listTunnels, startTunnel, stopAllTunnels } from "../src/tunnels.ts";
import { connect } from "../src/clients/ssh-client.ts";
import type { SshProfile } from "../src/types.ts";
import { startTestServer, type TestServer } from "./sshd.ts";

const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ssh-life-"));

after(async () => {
  await stopAllTunnels();
  fs.rmSync(workspace, { recursive: true, force: true });
});

function profileFor(server: NonNullable<TestServer>): SshProfile {
  return {
    host: "127.0.0.1",
    port: server.port,
    user: server.user,
    privateKeyPath: server.clientKeyPath,
    knownHostsFile: path.join(workspace, "known_hosts"),
    strictHostKey: false,
  };
}

function isAccepting(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    const done = (result: boolean) => {
      socket.destroy();
      resolve(result);
    };
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
    setTimeout(() => done(false), 2000);
  });
}

describe("a tunnel outlives its tool call", () => {
  it("is still listening long after startTunnel returned", async (t) => {
    const server = await startTestServer();
    if (!server) return t.skip("no sshd on this machine");

    try {
      const tunnel = await startTunnel({
        profileName: "life",
        profile: profileFor(server),
        name: "persistent",
        definition: { kind: "local", listenPort: 0, destHost: "127.0.0.1", destPort: server.port },
      });
      const port = Number(tunnel.listenAddress.split(":")[1]);

      // The call has returned; nothing is holding the tunnel open but itself.
      await new Promise((resolve) => setTimeout(resolve, 750));

      assert.strictEqual(await isAccepting(port), true);
      assert.ok(listTunnels().some((entry) => entry.name === "persistent"));
    } finally {
      await stopAllTunnels();
      server.stop();
    }
  });

  it("takes the local listener down when the SSH connection dies", async (t) => {
    const server = await startTestServer();
    if (!server) return t.skip("no sshd on this machine");

    // Killing sshd would not do it: established sessions live in child
    // processes and keep running. To cut the connection the way a dropped
    // network does, the tunnel is pointed at a proxy whose sockets we destroy.
    const live = new Set<net.Socket>();
    const proxy = net.createServer((incoming) => {
      const upstream = net.connect(server.port, "127.0.0.1");
      live.add(incoming);
      live.add(upstream);
      incoming.pipe(upstream);
      upstream.pipe(incoming);
      incoming.on("error", () => upstream.destroy());
      upstream.on("error", () => incoming.destroy());
    });
    const proxyPort = await new Promise<number>((resolve) => {
      proxy.listen(0, "127.0.0.1", () => resolve((proxy.address() as net.AddressInfo).port));
    });

    try {
      const tunnel = await startTunnel({
        profileName: "life",
        profile: { ...profileFor(server), port: proxyPort },
        name: "orphaned",
        definition: { kind: "local", listenPort: 0, destHost: "127.0.0.1", destPort: server.port },
      });
      const port = Number(tunnel.listenAddress.split(":")[1]);
      assert.strictEqual(await isAccepting(port), true);

      // The network goes away underneath the tunnel.
      for (const socket of live) socket.destroy();

      const deadline = Date.now() + 5000;
      while (listTunnels().some((entry) => entry.name === "orphaned") && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }

      assert.ok(
        !listTunnels().some((entry) => entry.name === "orphaned"),
        "the registry must not keep claiming a dead tunnel is up",
      );
      assert.strictEqual(
        await isAccepting(port),
        false,
        "the local port must stop accepting once the tunnel is dead",
      );
    } finally {
      await stopAllTunnels();
      proxy.close();
      server.stop();
    }
  });
});

describe("keepalives", () => {
  it("are enabled, so an idle connection notices when it dies", async (t) => {
    const server = await startTestServer();
    if (!server) return t.skip("no sshd on this machine");

    try {
      // ssh2 sends no keepalives unless asked. Without them an idle tunnel
      // behind a NAT looks alive after the path has already been dropped.
      const connection = await connect(profileFor(server), {});
      const config = (connection.client as any).config;
      assert.ok(config.keepaliveInterval > 0, "keepaliveInterval must be set");
      assert.ok(config.keepaliveCountMax > 0, "keepaliveCountMax must be set");
      connection.client.end();
    } finally {
      server.stop();
    }
  });
});
