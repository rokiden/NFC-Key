from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class SSH:
    @staticmethod
    def private_bytes_generate() -> tuple[bytes, Ed25519PrivateKey]:
        priv_key = Ed25519PrivateKey.generate()

        raw_seed = priv_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return raw_seed, priv_key

    @staticmethod
    def private_bytes_from_openssh(
        openssh_key_text: str,
    ) -> tuple[bytes, Ed25519PrivateKey]:
        # The source key must be an unencrypted Ed25519 OpenSSH key.
        priv_key = serialization.load_ssh_private_key(
            openssh_key_text.encode("utf-8"), password=None
        )
        if not isinstance(priv_key, Ed25519PrivateKey):
            raise TypeError("expected an Ed25519 private key")
        raw_seed = priv_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return raw_seed, priv_key

    @staticmethod
    def openssh_from_private_bytes(seed: bytes) -> tuple[str, Ed25519PrivateKey]:
        # Build an unencrypted OpenSSH key for the agent without a disk file.
        priv_key = Ed25519PrivateKey.from_private_bytes(seed)
        openssh_key = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return openssh_key.decode("ascii"), priv_key

    @staticmethod
    def private_key_to_public_openssh(priv_key: Ed25519PrivateKey) -> str:
        pub_key = priv_key.public_key()
        openssh_pub_key = pub_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        return openssh_pub_key.decode("ascii")


if __name__ == "__main__":
    # 1. Generate a brand new key
    private_bytes, priv_key_1 = SSH.private_bytes_generate()
    print(f"Generated: {private_bytes.hex()}")
    print(f"Generated pub: {SSH.private_key_to_public_openssh(priv_key_1)}")

    # 2. Rebuild the OpenSSH private key from the raw seed
    openssh_key, priv_key_2 = SSH.openssh_from_private_bytes(private_bytes)
    print(f"Rebuilt:\n{openssh_key}")
    print(f"Rebuilt pub: {SSH.private_key_to_public_openssh(priv_key_2)}")

    # 3. Extract the raw seed from the rebuilt OpenSSH key
    extracted_seed, priv_key_3 = SSH.private_bytes_from_openssh(openssh_key)
    print(f"Extracted: {extracted_seed.hex()}")
    print(f"Extracted pub: {SSH.private_key_to_public_openssh(priv_key_3)}")
