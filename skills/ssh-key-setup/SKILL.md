---
name: ssh-key-setup
description: Set up SSH key authentication so a host stops asking for a password, and manage the keys involved. Use when the user configures a new server with a password, says they are tired of typing a password, asks about ssh-copy-id, ssh-keygen, "install my key", "passwordless login", "authorized_keys", or when a login fails because a key is missing or not accepted. Also covers what has to be installed for any of this to work, which on every platform is nothing.
allowed-tools: ssh_setup, ssh_status, ssh_keygen, ssh_authorize, ssh_exec, ssh_doctor
---

# Key-based login

A password in a config file is a password on disk, and typing one into every
session is friction. A key fixes both. The whole switch is one tool call.

## The normal path

1. `ssh_setup` with host, user and the password.
2. `ssh_authorize` on that profile.

`ssh_authorize` does what `ssh-copy-id` does: it generates an ed25519 key if
the profile has none, appends the public key to the remote
`~/.ssh/authorized_keys` with the permissions sshd insists on, points the
profile at the new key, and then **opens a second connection using only the
key** to prove it works before claiming success.

Report the fingerprint and whether verification succeeded. If it did not, say
so plainly - the key is installed but something is rejecting it, and the
password is still there as a fallback.

## What has to be installed

Nothing. Not `ssh`, not `ssh-keygen`, not `ssh-copy-id`. The SSH protocol is
implemented in JavaScript and keys are generated with Node's own crypto, so
Windows, macOS and Linux behave identically. If a user asks what to install,
run `ssh_doctor` and show them the report rather than guessing.

The keys produced are ordinary OpenSSH ed25519 keys, so `ssh -i` and any other
SSH client can use the same file.

## Things worth getting right

- **Never overwrite an existing key.** Every host that already trusts it would
  stop accepting it. `ssh_authorize` reuses a key at the given path; `ssh_keygen`
  refuses to replace one unless explicitly told to.
- **Keep the password until the key is proven.** `ssh_authorize` leaves it in
  the profile by default. Only pass `removePassword: true` once verification
  has succeeded, and prefer to ask the user first: if `authorized_keys` is ever
  reset, that password is the way back in.
- **One key per host is a reasonable default.** The default path is
  `~/.ssh/id_ed25519_pi_<profile>`, which keeps a compromise contained to one
  host. Pass `keyPath` to reuse an existing key across hosts if the user wants
  that.
- **A passphrase-protected key cannot be bootstrapped.** If the user points at
  one, this flow cannot read it; either use a different key path or configure
  the passphrase in the profile.

## If the key is not accepted afterwards

The usual causes, in order:

1. Permissions. sshd silently ignores `~/.ssh` or `authorized_keys` if they are
   group- or world-writable. `ssh_exec` with `ls -ld ~/.ssh ~/.ssh/authorized_keys`
   shows it; 700 and 600 are what is wanted.
2. The account's home is not where you think - a different `AuthorizedKeysFile`
   in `sshd_config`, or a chrooted account. `ssh_authorize` takes an
   `authorizedKeysPath` for that case.
3. The server does not allow public key auth at all (`PubkeyAuthentication no`),
   which needs a change on the server side.

## Keys without a host

`ssh_keygen` just makes a key pair and prints the public key, for cases where
the user installs it themselves - a cloud provider's web console, a deploy key
in a Git host, a colleague who will add it for them.
