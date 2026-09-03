/**
 * Port forwarding.
 *
 * This is the one place where something deliberately outlives the tool call
 * that created it: a tunnel is only useful while it is open, so it runs in the
 * background and is stopped explicitly. Everything else about the design is
 * there to keep that from becoming a leak -- every tunnel is in a registry
 * that `ssh_tunnel list` and `ssh_status` show, each one can carry a time
 * limit, and the extension closes all of them when the pi session ends.
 *
 * Each tunnel owns its own SSH connection. Sharing one would be tidier on the
 * wire, but a single dropped connection would then take every tunnel with it.
 */

import * as net from "node:net";
import type { Connection } from "./clients/ssh-client.ts";
import { connect } from "./clients/ssh-client.ts";
import type { RunningTunnel, SshProfile, TunnelDefinition } from "./types.ts";
import { TunnelError } from "./types.ts";

const DEFAULT_BIND = "127.0.0.1";

interface TunnelHandle {
  readonly id: string;
  readonly profile: string;
  readonly name: string;
  readonly definition: TunnelDefinition;
  readonly startedAt: Date;
  listenAddress: string;
  connections: number;
  expiresAt?: Date;
  stopped: boolean;
  stop(): Promise<void>;
}

const running = new Map<string, TunnelHandle>();

/**
 * Anything that wants to know when the set of tunnels changes.
 *
 * A tunnel is the one thing here that keeps running unattended, so something
 * has to be able to keep showing it. The registry stays ignorant of what that
 * something is.
 */
type ChangeListener = (tunnels: RunningTunnel[]) => void;
const listeners = new Set<ChangeListener>();

export function onTunnelsChanged(listener: ChangeListener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function notifyChanged(): void {
  const snapshot = listTunnels();
  for (const listener of listeners) {
    try {
      listener(snapshot);
    } catch {
      // A broken display must never take a tunnel down with it.
    }
  }
}

function tunnelId(profile: string, name: string): string {
  return `${profile}:${name}`;
}

/** Reject a definition before anything is opened. */
export function validateDefinition(definition: TunnelDefinition): void {
  if (definition.kind !== "local" && definition.kind !== "remote") {
    throw new TunnelError(`Unknown tunnel kind "${definition.kind}". Use local or remote.`);
  }
  for (const [label, port] of [
    ["listenPort", definition.listenPort],
    ["destPort", definition.destPort],
  ] as const) {
    // 0 is allowed for listenPort only: it means "pick a free one".
    const min = label === "listenPort" ? 0 : 1;
    if (!Number.isInteger(port) || port < min || port > 65535) {
      throw new TunnelError(`${label} must be an integer between ${min} and 65535.`);
    }
  }
  if (!definition.destHost?.trim()) {
    throw new TunnelError("destHost must not be empty.");
  }
}

/** Pipe two streams together and tear both down when either ends. */
function join(a: NodeJS.ReadWriteStream & { destroy?: () => void }, b: NodeJS.ReadWriteStream & { destroy?: () => void }): void {
  a.pipe(b);
  b.pipe(a);

  const close = () => {
    try {
      a.destroy?.();
    } catch {
      /* already gone */
    }
    try {
      b.destroy?.();
    } catch {
      /* already gone */
    }
  };

  a.on("error", close);
  b.on("error", close);
  a.on("close", close);
  b.on("close", close);
}

/**
 * ssh -L: listen here, let the server reach the destination.
 */
async function startLocal(
  connection: Connection,
  definition: TunnelDefinition,
  handle: TunnelHandle,
): Promise<string> {
  const bind = definition.bind ?? DEFAULT_BIND;
  const sockets = new Set<net.Socket>();

  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));

    connection.client.forwardOut(
      socket.remoteAddress ?? "127.0.0.1",
      socket.remotePort ?? 0,
      definition.destHost,
      definition.destPort,
      (err, stream) => {
        if (err) {
          // The destination refused or does not resolve from the server. The
          // tunnel itself stays up; only this connection fails.
          socket.destroy();
          return;
        }
        handle.connections += 1;
        join(socket, stream);
      },
    );
  });

  const address = await new Promise<string>((resolve, reject) => {
    server.once("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        reject(
          new TunnelError(
            `Local port ${definition.listenPort} is already in use. Pick another listenPort, or 0 to let the system choose.`,
          ),
        );
        return;
      }
      if (err.code === "EACCES") {
        reject(
          new TunnelError(
            `Not allowed to listen on port ${definition.listenPort}. Ports below 1024 need elevated rights.`,
          ),
        );
        return;
      }
      reject(err);
    });
    server.listen(definition.listenPort, bind, () => {
      const info = server.address() as net.AddressInfo;
      resolve(`${bind}:${info.port}`);
    });
  });

  const originalStop = handle.stop;
  handle.stop = async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await originalStop();
  };

  return address;
}

/**
 * ssh -R: the server listens, and connections come back here.
 */
async function startRemote(
  connection: Connection,
  definition: TunnelDefinition,
  handle: TunnelHandle,
): Promise<string> {
  const bind = definition.bind ?? DEFAULT_BIND;
  const sockets = new Set<net.Socket>();

  const boundPort = await new Promise<number>((resolve, reject) => {
    connection.client.forwardIn(bind, definition.listenPort, (err, port) => {
      if (err) {
        reject(
          new TunnelError(
            [
              `The server refused to listen on ${bind}:${definition.listenPort}: ${err.message}.`,
              "Usually the port is taken, or sshd only allows loopback binds -- binding to anything other than 127.0.0.1 needs GatewayPorts in its sshd_config.",
            ].join(" "),
          ),
        );
        return;
      }
      resolve(definition.listenPort === 0 ? (port as number) : definition.listenPort);
    });
  });

  connection.client.on("tcp connection", (details, accept, reject) => {
    // One connection carries one tunnel, but the server still reports which
    // binding a connection arrived on.
    if (details.destPort !== boundPort) {
      reject();
      return;
    }

    const stream = accept();
    handle.connections += 1;

    const socket = net.connect(definition.destPort, definition.destHost, () => {
      join(socket, stream);
    });
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {
      // Nothing is listening on our side; drop the forwarded connection.
      stream.destroy();
      socket.destroy();
    });
  });

  const originalStop = handle.stop;
  handle.stop = async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => {
      try {
        connection.client.unforwardIn(bind, boundPort, () => resolve());
      } catch {
        resolve();
      }
    });
    await originalStop();
  };

  return `${bind}:${boundPort}`;
}

export interface StartTunnelOptions {
  readonly profileName: string;
  readonly profile: SshProfile;
  readonly name: string;
  readonly definition: TunnelDefinition;
  readonly acceptNewHostKey?: boolean;
  /** Close the tunnel automatically after this long. */
  readonly durationSeconds?: number;
  readonly signal?: AbortSignal;
}

export async function startTunnel(options: StartTunnelOptions): Promise<RunningTunnel> {
  const { definition, name, profileName } = options;
  validateDefinition(definition);

  const id = tunnelId(profileName, name);
  if (running.has(id)) {
    throw new TunnelError(
      `A tunnel called "${name}" is already running for profile "${profileName}". Stop it first, or give this one another name.`,
    );
  }

  const connection = await connect(options.profile, {
    acceptNewHostKey: options.acceptNewHostKey,
    signal: options.signal,
  });

  const handle: TunnelHandle = {
    id,
    profile: profileName,
    name,
    definition,
    startedAt: new Date(),
    listenAddress: "",
    connections: 0,
    stopped: false,
    stop: async () => {
      connection.client.end();
      running.delete(id);
    },
  };

  try {
    handle.listenAddress =
      definition.kind === "local"
        ? await startLocal(connection, definition, handle)
        : await startRemote(connection, definition, handle);
  } catch (err) {
    connection.client.end();
    throw err;
  }

  // A dropped SSH connection means the tunnel is dead. Removing it from the
  // registry is not enough: the local listener would keep accepting
  // connections that can no longer go anywhere, so it has to be torn down
  // too.
  connection.client.on("close", () => {
    void teardown(handle);
  });

  if (options.durationSeconds && options.durationSeconds > 0) {
    handle.expiresAt = new Date(Date.now() + options.durationSeconds * 1000);
    const timer = setTimeout(() => {
      void teardown(handle);
    }, options.durationSeconds * 1000);
    timer.unref?.();
  }

  running.set(id, handle);
  notifyChanged();
  return describe(handle);
}

/** Stop a tunnel once, whether the caller asked or the connection died. */
async function teardown(handle: TunnelHandle): Promise<void> {
  if (handle.stopped) return;
  handle.stopped = true;
  try {
    await handle.stop();
  } finally {
    running.delete(handle.id);
    notifyChanged();
  }
}

function describe(handle: TunnelHandle): RunningTunnel {
  return {
    id: handle.id,
    profile: handle.profile,
    name: handle.name,
    definition: handle.definition,
    listenAddress: handle.listenAddress,
    startedAt: handle.startedAt.toISOString(),
    connections: handle.connections,
    expiresAt: handle.expiresAt?.toISOString(),
  };
}

export function listTunnels(): RunningTunnel[] {
  return [...running.values()].map(describe).sort((a, b) => a.id.localeCompare(b.id));
}

export async function stopTunnel(profileName: string, name: string): Promise<boolean> {
  const handle = running.get(tunnelId(profileName, name));
  if (!handle) return false;
  await teardown(handle);
  return true;
}

/** Close everything. Called when the pi session ends. */
export async function stopAllTunnels(): Promise<number> {
  const handles = [...running.values()];
  await Promise.all(handles.map((handle) => teardown(handle).catch(() => undefined)));
  running.clear();
  notifyChanged();
  return handles.length;
}

/** @internal for tests */
export function _runningCount(): number {
  return running.size;
}

/** @internal for tests */
export function _clearListeners(): void {
  listeners.clear();
}
