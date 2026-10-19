# NFC-backed SSH key utility

This Python CLI stores an XOR-masked Ed25519 private-key seed on an NFC tag and can reconstruct it into `ssh-agent`. The implementation is functional with the reader and tag setup it was built and tested for.

## NFC reader and tag

Developed and tested with an **Alcor Link AK9567** reader and an **NXP ICODE SLIX-compatible ISO 15693** tag. The NFC helper sends 4-byte block read/write commands through PC/SC (`FF B0` and `FF D6`); compatibility depends on the PC/SC stack and reader APDU handling. The tool uses block index 0 as the starting point for its 32-byte payload.

By default, the tool selects the first reader whose reported name contains `contactless`. `--reader` is optional and can select a reader explicitly by its exact PC/SC name, for example `--reader "Alcor Link AK9567"`.

## Requirements

- Python 3.10 or newer.
- Python packages: `cryptography` and `pyscard`.
- A PC/SC service and a compatible reader/tag; developed and tested with the Alcor Link AK9567 and an NXP ICODE SLIX-compatible ISO 15693 tag.
- OpenSSH `ssh-add` and a running `ssh-agent` (`SSH_AUTH_SOCK` must be set when using the agent).
- An unencrypted Ed25519 OpenSSH private key at `~/.ssh/id_ed25519`.

Install the Python dependencies in your preferred virtual environment or package manager, for example:

```sh
python3 -m pip install cryptography pyscard
```

## Install the `nfc-key` command

If the checkout is at `~/Documents/nfc-key`, create the local bin directory if needed and symlink the executable:

```sh
mkdir -p ~/.local/bin
ln -s ~/Documents/nfc-key/main.py ~/.local/bin/nfc-key
```

Ensure `~/.local/bin` is included in your `PATH`. Change the source path in the `ln` command if the checkout is elsewhere. The SSH config example below invokes `nfc-key` by this command name.

Reader availability and APDU support depend on the reader, PC/SC stack, and tag.

## How the tool works

- `prepare` reads the 32-byte seed from `~/.ssh/id_ed25519` and uses it as an XOR mask. It generates a **new** random Ed25519 key, XORs that key's seed with the mask, and attempts to write the 32-byte result to the tag. It prints the generated key's public key.
- `pub` reads 32 bytes from the tag, XORs them with the local mask seed, and prints the reconstructed public key.
- `load` performs the same reconstruction, serializes the private key in OpenSSH format in memory, and pipes it to `ssh-add`. The private key is not deliberately written to a file. By default, the agent key lifetime is 60 seconds.

The seed in `~/.ssh/id_ed25519` is used as a **mask**, not as the identity that `prepare` prints. Each `prepare` run generates a different SSH identity; if you provision a new one, install its newly printed public key on the intended server.

## Commands

```sh
./main.py prepare [--reader READER]
./main.py pub [--reader READER]
./main.py load [--reader READER] [--timeout SECONDS] [--only-missing]
```

### Provision (once per generated identity)

Place the supported tag on the reader and run:

```sh
./main.py prepare
```

Save the public key printed to stdout and add it to the target account's `~/.ssh/authorized_keys`. `prepare` creates a fresh identity each time, so rerunning it means updating the server with the newly printed public key.

### Print the public key again

With the same local mask key and provisioned tag:

```sh
./main.py pub
```

### Load into the agent

```sh
./main.py load
./main.py load --timeout 120
```

The timeout is in seconds. To skip NFC access and agent loading if `ssh-add -l` output already contains the text `stdin`, use:

```sh
./main.py load --only-missing
```

On a match, the tool prints `NFC Key: Already loaded, skipping.` to stderr. This is a substring/comment check, not a cryptographic fingerprint comparison. The flag only affects the `load` command.

## SSH config integration

To invoke the loader when connecting to a specific SSH host alias, add a `Match` condition to `~/.ssh/config`:

```sshconfig
Match final Host server_name exec "nfc-key load --only-missing; exit 1"
```

Replace `server_name` with the host alias used in your `ssh` command. `Match` checks both the host and the `exec` condition; the command runs locally for that host. The trailing `; exit 1` deliberately makes the condition false after running the loader, so this line acts as a command hook rather than enabling SSH options in a matching block. Make sure `nfc-key` is available in the environment used by `ssh`; use its absolute path if needed.

A false `Match` does **not** abort the SSH connection. If NFC loading fails, SSH may still authenticate using other configured methods or identities. This configuration is not a fail-closed authentication requirement. Also, directives following a `Match` remain in that conditional section until the next `Host` or `Match` line.

## User systemd SSH agent

The following user unit runs `ssh-agent` on a stable socket and publishes `SSH_AUTH_SOCK` to D-Bus/systemd activation. This approach fits modern **systemd-based** Linux desktop sessions.

```sh
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/ssh-agent.service <<'EOF'
[Unit]
Description=SSH authentication agent
Wants=dbus.socket
After=dbus.socket
Before=graphical-session-pre.target

[Service]
Type=simple
Environment="SSH_AUTH_SOCK=%t/ssh-agent.socket"
ExecStart=/usr/bin/ssh-agent -D -a ${SSH_AUTH_SOCK}
ExecStartPost=dbus-update-activation-environment --systemd --verbose SSH_AUTH_SOCK=${SSH_AUTH_SOCK}
ExecStop=dbus-update-activation-environment --systemd --verbose SSH_AUTH_SOCK=
ExecStop=/usr/bin/ssh-agent -k

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now ssh-agent.service
```

`%t` resolves to the user runtime directory, typically `$XDG_RUNTIME_DIR`. The shell running `ssh` and `nfc-key` must also have `SSH_AUTH_SOCK` set to the agent socket; if your session does not inherit it, set it in your shell startup file:

```sh
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/ssh-agent.socket"
```

## Security and operational limitations

- The tag payload is XOR masking, not encryption or a proof that the original physical tag is present. Anyone who obtains both the tag data and the local mask can reconstruct the key.
- Keep `~/.ssh/id_ed25519` backed up and protected: losing it makes the tag payload unrecoverable; compromise of it together with a copy of the tag reveals the generated identity.
- Once loaded, the key remains usable through the agent until its lifetime expires or it is removed. Removing the tag does not revoke a key already loaded into the agent, and does not terminate existing SSH sessions.
- This tool does not configure SSH to require this key or disable password/other-key authentication. Configure and test server/client authentication policy separately if that is required.
- In-memory handling avoids intentionally creating a plaintext private-key file during `load`, but does not guarantee secure erasure from process memory, prevent core dumps, or protect against a compromised host.

## Project files

- `main.py` — command-line flow and agent interaction.
- `key.py` — Ed25519 seed and OpenSSH serialization helpers.
- `nfc.py` — PC/SC reader selection and block-based APDU access.
