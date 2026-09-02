# pi-ssh

SSH client extension for the [pi coding agent](https://github.com/earendil-works/pi).

Run commands on remote hosts, move files over SFTP, and turn a password login into a key login — all from a pi session.

**Nothing has to be installed.** No `ssh`, no `ssh-keygen`, no `ssh-copy-id`. The SSH protocol comes from [ssh2](https://github.com/mscdex/ssh2), a pure JavaScript implementation, and keys are generated with Node's own crypto. Windows, macOS and Linux behave identically.

## Installation

```bash
# Install from npm
pi install npm:@patimweb/pi-ssh

# Install from local path during development
pi install /path/to/pi-ssh
```

## Quick Start

```
ssh_setup:
  name: staging
  host: staging.example.com
  user: deploy
  password: <password>

ssh_authorize          # generates a key, installs it, verifies passwordless login

ssh_exec:
  command: systemctl status nginx --no-pager
```

After `ssh_authorize` the password is no longer needed. It stays in the profile as a fallback until you pass `removePassword: true`.

## Tools

| Tool | Description |
|------|-------------|
| `ssh_setup` | Store a host: address, user, and a password or key path. |
| `ssh_status` | List configured hosts and how each authenticates; optionally test a connection. |
| `ssh_profile` | List, switch, or delete hosts. |
| `ssh_exec` | Run a command and return its output and exit code. |
| `ssh_list` | List a remote directory with sizes, permissions and dates over SFTP. |
| `ssh_upload` | Copy a file to the remote host. |
| `ssh_download` | Copy a file from the remote host. |
| `ssh_keygen` | Create an ed25519 key pair in process. |
| `ssh_authorize` | Install a key on a host and stop needing the password. |
| `ssh_doctor` | Report what this machine can do and what needs fixing. |

### Passwordless login

`ssh_authorize` is `ssh-copy-id` without the binary:

```yaml
ssh_authorize:
  # profile: staging          # defaults to the active one
  # keyPath: ~/.ssh/id_ed25519_pi_staging
  # removePassword: true      # only after verification succeeds
  # authorizedKeysPath: /custom/authorized_keys
```

It generates a key if the profile has none, appends the public key to the remote `~/.ssh/authorized_keys` with the permissions sshd requires, points the profile at the key, and then opens a **second connection using only the key** to prove it works before reporting success. Running it twice is safe: the key is appended only once.

An existing key at the target path is reused, never overwritten — overwriting would invalidate every other host that already trusts it.

### Running commands

```yaml
ssh_exec:
  command: journalctl -u api --since "1 hour ago" --no-pager
  # cwd: /srv/app
  # timeoutSeconds: 120
```

Each call opens a connection, runs one command, and closes it. There is no persistent shell, so `cd` does not carry over — use `cwd` or chain with `&&`. There is also no TTY: anything interactive (a `sudo` password prompt, `top`, an editor) will hang until the timeout.

Output is capped at 200,000 characters per stream and marked as truncated rather than silently cut.

### Files

```yaml
ssh_list:     { path: /var/log }
ssh_download: { remotePath: /var/log/app.log, localPath: ./logs/app.log }
ssh_upload:   { localPath: ./dist/app.tar.gz, remotePath: /tmp/app.tar.gz }
```

Missing local directories are created on download. Prefer these over `cat` through `ssh_exec`: SFTP handles binary content and does not push the file through the model.

## Commands

| Command | Description |
|---------|-------------|
| `/ssh <command>` | Run a command on the active host. |
| `/ssh-key` | Set up passwordless login for the active host. |

## Skills

| Skill | Purpose |
|-------|---------|
| `ssh-remote-work` | Choosing the right host, the absence of a shell and a TTY, reading before writing, and what each connection error actually means. |
| `ssh-key-setup` | The password-to-key switch, why an existing key is never overwritten, and why the password stays until the key is proven. |

## Host key verification

Host keys are checked against `~/.ssh/known_hosts` — the same file OpenSSH uses, so hosts you have already visited with `ssh` are recognised, and hosts recorded here are recognised by `ssh`. Hashed entries (`ssh-keygen -H`) and `[host]:port` forms are both understood.

- **Unknown host** → the connection is refused and the fingerprint shown. Confirm it, then re-run with `acceptNewHostKey: true` to record it.
- **Changed key** → a hard failure with both fingerprints. This is what a machine-in-the-middle looks like; it is also what a reinstalled server looks like. It has to be resolved deliberately with `ssh-keygen -R <host>`.
- **Revoked key** (`@revoked` in known_hosts) → always refused.

`strictHostKey: false` in a profile turns the check off. It removes the only protection SSH has against an attacker on the network path, so it exists for throwaway lab machines and nothing else.

## Configuration

Profiles live in `~/.pi/ssh-config.json`, written atomically with mode `0600` because it can hold passwords and key passphrases.

```json
{
  "profiles": {
    "staging": {
      "host": "staging.example.com",
      "port": 22,
      "user": "deploy",
      "privateKeyPath": "/home/pat/.ssh/id_ed25519_pi_staging"
    }
  },
  "activeProfile": "staging"
}
```

Every tool also takes a one-off `profile` parameter, so several hosts can be used in one session without switching.

## Development

```bash
npm install
npm test
npm run test:coverage
```

The suite runs end-to-end against a real OpenSSH server: it starts `sshd` on a loopback port with a host key generated by this package, then exercises the handshake, host key verification (including a simulated key change), exit codes, SFTP, and the full key bootstrap. Those tests skip themselves on machines without `sshd` rather than failing.

## License

MIT
