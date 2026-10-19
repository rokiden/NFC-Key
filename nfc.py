"""Minimal PC/SC access to the contactless reader and 4-byte-block NFC tag."""

from smartcard.System import readers as _sc_readers


def get_reader(name=None):
    readers = _sc_readers()

    if name is None:
        for reader in readers:
            if "contactless" in str(reader).casefold():
                return reader
        raise RuntimeError("Contactless NFC reader not found")

    for reader in readers:
        if str(reader) == name:
            return reader

    raise RuntimeError(f"NFC reader not found: {name}")


class NFCTag:
    # PC/SC commands for block access and tag UID retrieval.
    BLOCK_SIZE = 4
    BLOCK_COUNT = 0x100
    _READ_COMMAND = bytes.fromhex("FF B0 00")
    _WRITE_COMMAND = bytes.fromhex("FF D6 00")
    _GET_ID_COMMAND = bytes.fromhex("FF CA 00 00 00")
    _SUCCESS_STATUS = (0x90, 0x00)

    def __init__(self, connection):
        self._connection = connection

    @classmethod
    def start_block_for_byte_range(cls, byte_offset, length):
        if byte_offset < 0:
            raise ValueError("byte offset must be non-negative")
        if byte_offset % cls.BLOCK_SIZE:
            raise ValueError(
                f"byte offset must be aligned to {cls.BLOCK_SIZE}-byte blocks"
            )
        if length <= 0 or length % cls.BLOCK_SIZE:
            raise ValueError(f"length must be a positive multiple of {cls.BLOCK_SIZE}")

        start_block = byte_offset // cls.BLOCK_SIZE
        block_count = length // cls.BLOCK_SIZE
        if start_block + block_count > cls.BLOCK_COUNT:
            raise ValueError("byte range exceeds the addressable block range")
        return start_block

    def _transmit(self, apdu):
        response, sw1, sw2 = self._connection.transmit(apdu)
        if (sw1, sw2) != self._SUCCESS_STATUS:
            raise RuntimeError(f"APDU failed: SW={sw1:02X}{sw2:02X}")
        return bytes(response)

    def read_mem(self, start_block, length):
        if length % self.BLOCK_SIZE:
            raise ValueError(f"length must be a multiple of {self.BLOCK_SIZE}")

        data = bytearray()
        for block in range(start_block, start_block + length // self.BLOCK_SIZE):
            apdu = [*self._READ_COMMAND, block, self.BLOCK_SIZE]
            chunk = self._transmit(apdu)
            if len(chunk) != self.BLOCK_SIZE:
                raise RuntimeError(
                    f"block {block:02X}: expected {self.BLOCK_SIZE} bytes, got {len(chunk)}"
                )
            data.extend(chunk)
        return bytes(data)

    def write_mem(self, start_block, data):
        data = bytes(data)
        if len(data) % self.BLOCK_SIZE:
            raise ValueError(f"data length must be a multiple of {self.BLOCK_SIZE}")

        for offset in range(0, len(data), self.BLOCK_SIZE):
            block = start_block + offset // self.BLOCK_SIZE
            chunk = data[offset : offset + self.BLOCK_SIZE]
            apdu = [*self._WRITE_COMMAND, block, self.BLOCK_SIZE, *chunk]
            self._transmit(apdu)

    def get_id(self):
        return self._transmit(list(self._GET_ID_COMMAND))


if __name__ == "__main__":
    import sys

    reader = get_reader(sys.argv[1] if len(sys.argv) > 1 else None)
    connection = reader.createConnection()
    connection.connect()
    tag = NFCTag(connection)
    print(f"NFC tag ID: {tag.get_id().hex()}")
    print(f"NFC tag memory (first 32 bytes): {tag.read_mem(0, 32).hex()}")
