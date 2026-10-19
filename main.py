#!/usr/bin/env python3
"""NFC-backed SSH key utilities."""

import argparse
import subprocess
import sys
from pathlib import Path

import smartcard.Exceptions

from key import SSH
from nfc import NFCTag, get_reader


def _xor_bytes(data, key):
    # Strict zip prevents silently truncating a mismatched seed or mask.
    return bytes(left ^ right for left, right in zip(data, key, strict=True))


def log(message):
    print(f"NFC Key: {message}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", choices=("prepare", "pub", "load"))
    parser.add_argument("--reader", default=None)
    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help=f"tag byte offset for this key's {SSH.PRIVATE_SEED_SIZE}-byte payload (default: 0)",
    )
    parser.add_argument(
        "--timeout", type=int, default=60, help="agent key lifetime in seconds"
    )
    parser.add_argument(
        "--only-missing",
        action="store_true",
        help="skip load if ssh-agent already has an identity commented 'stdin'",
    )
    args = parser.parse_args()

    try:
        start_block = NFCTag.start_block_for_byte_range(
            args.offset, SSH.PRIVATE_SEED_SIZE
        )
    except ValueError as error:
        parser.error(str(error))

    if args.cmd == "load" and args.only_missing:
        try:
            agent_keys = subprocess.run(
                ["ssh-add", "-l"], capture_output=True, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            if e.returncode != 1:  # 1 means no identities
                log(f"Failed to check loaded keys: {e.stderr}")
                sys.exit(1)
        else:
            if "stdin" in agent_keys.stdout:
                log("Already loaded, skipping.")
                return

    # The local Ed25519 seed is the tag's XOR mask; keep it unchanged.
    mask = SSH.private_bytes_from_openssh(
        (Path.home() / ".ssh" / "id_ed25519").read_text()
    )[0]
    connection = get_reader(args.reader).createConnection()

    try:
        connection.connect()
    except smartcard.Exceptions.NoCardException:
        log("No tag detected.")
        return

    try:
        tag = NFCTag(connection)
        if args.cmd == "prepare":
            private_bytes, private_key = SSH.private_bytes_generate()
            # Store only the masked seed on the tag.
            tag.write_mem(start_block, _xor_bytes(private_bytes, mask))
        else:  # read for "load" or "pub" command
            private_bytes = _xor_bytes(
                tag.read_mem(start_block, SSH.PRIVATE_SEED_SIZE), mask
            )
            openssh_key, private_key = SSH.openssh_from_private_bytes(private_bytes)
    finally:
        connection.disconnect()

    if args.cmd == "load":
        # Send the reconstructed key over stdin instead of writing it to disk.
        try:
            subprocess.run(
                ["ssh-add", "-t", str(args.timeout), "-"],
                input=openssh_key,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            log(f"Failed to load key: {e.stderr}")
            sys.exit(1)
        else:
            log("Successfully loaded.")
    else:  # "prepare" or "pub" command
        print(SSH.private_key_to_public_openssh(private_key))


if __name__ == "__main__":
    main()
