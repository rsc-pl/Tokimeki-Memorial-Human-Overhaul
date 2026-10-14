"""Raw sector access for MODE2/2352 PlayStation disc images.

Every PS1 data sector is 2352 bytes:

    0x000  12  sync pattern (00 FF*10 00)
    0x00C   4  header (BCD minute/second/frame + mode byte)
    0x010   8  subheader (4 bytes, repeated twice)
    0x018 2048 user data            (Form 1)
    0x818   4  EDC (CRC32 over 0x010..0x817)
    0x81C 276  ECC (Reed-Solomon P + Q parity)

When we change user data in a Form 1 sector we must regenerate EDC/ECC,
otherwise real hardware (and strict emulators) will treat the sector as bad.
"""

from __future__ import annotations

from pathlib import Path

SECTOR_SIZE = 2352
DATA_OFFSET = 0x18
DATA_SIZE = 2048
SUBMODE_FORM2 = 0x20


def _build_tables():
    ecc_f = bytearray(256)
    ecc_b = bytearray(256)
    edc = [0] * 256
    for i in range(256):
        j = ((i << 1) ^ (0x11D if i & 0x80 else 0)) & 0xFF
        ecc_f[i] = j
        ecc_b[i ^ j] = i
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ (0xD8018001 if crc & 1 else 0)
        edc[i] = crc
    return bytes(ecc_f), bytes(ecc_b), edc


_ECC_F, _ECC_B, _EDC = _build_tables()


def compute_edc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = (crc >> 8) ^ _EDC[(crc ^ b) & 0xFF]
    return crc


def _ecc_block(src: bytes, major_count: int, minor_count: int,
               major_mult: int, minor_inc: int) -> bytes:
    size = major_count * minor_count
    out = bytearray(major_count * 2)
    for major in range(major_count):
        index = (major >> 1) * major_mult + (major & 1)
        a = b = 0
        for _ in range(minor_count):
            t = src[index]
            index += minor_inc
            if index >= size:
                index -= size
            a ^= t
            b ^= t
            a = _ECC_F[a]
        a = _ECC_B[_ECC_F[a] ^ b]
        out[major] = a
        out[major + major_count] = a ^ b
    return bytes(out)


def regenerate_form1(sector: bytearray) -> None:
    """Recompute EDC and ECC in place for a Mode 2 Form 1 sector."""
    sector[0x818:0x81C] = compute_edc(sector[0x10:0x818]).to_bytes(4, "little")
    # Mode 2 ECC is calculated as if the 4-byte header were zero.
    header = bytes(sector[0x0C:0x10])
    sector[0x0C:0x10] = b"\0\0\0\0"
    sector[0x81C:0x8C8] = _ecc_block(sector[0x0C:0x81C], 86, 24, 2, 86)   # P parity
    sector[0x8C8:0x930] = _ecc_block(sector[0x0C:0x8C8], 52, 43, 86, 88)  # Q parity
    sector[0x0C:0x10] = header


def is_form1(sector: bytes) -> bool:
    return sector[0x0F] == 2 and not (sector[0x12] & SUBMODE_FORM2)


class Track:
    """A MODE2/2352 .bin track file, addressed by logical sector (LBA)."""

    def __init__(self, path: Path, writable: bool = False):
        self.path = Path(path)
        self._f = open(self.path, "r+b" if writable else "rb")
        self.sector_count = self.path.stat().st_size // SECTOR_SIZE

    def close(self) -> None:
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def read_sector(self, lba: int) -> bytes:
        self._f.seek(lba * SECTOR_SIZE)
        sector = self._f.read(SECTOR_SIZE)
        if len(sector) != SECTOR_SIZE:
            raise ValueError(f"LBA {lba} is past the end of {self.path.name}")
        return sector

    def write_sector(self, lba: int, sector: bytes) -> None:
        assert len(sector) == SECTOR_SIZE
        self._f.seek(lba * SECTOR_SIZE)
        self._f.write(sector)

    def read_data(self, lba: int) -> bytes:
        sector = self.read_sector(lba)
        if sector[0x10:0x14] != sector[0x14:0x18]:
            # Quirk of this disc: the first sector of the /CDROM directory has a
            # mangled subheader and its records start at 0x10 instead of 0x18.
            # The game never reads it (it uses hard-coded LBAs), but our
            # directory walker does.
            return sector[0x10:0x10 + DATA_SIZE]
        return sector[DATA_OFFSET:DATA_OFFSET + DATA_SIZE]

    def read_file(self, lba: int, size: int) -> bytes:
        count = (size + DATA_SIZE - 1) // DATA_SIZE
        return b"".join(self.read_data(lba + i) for i in range(count))[:size]

    def write_file(self, file_lba: int, old: bytes, new: bytes) -> int:
        """Rewrite only the sectors of a file whose contents changed."""
        assert len(old) == len(new)
        touched = 0
        for pos in range(0, len(new), DATA_SIZE):
            if old[pos:pos + DATA_SIZE] != new[pos:pos + DATA_SIZE]:
                touched += self.write_file_bytes(file_lba, pos, new[pos:pos + DATA_SIZE])
        return touched

    def write_file_bytes(self, file_lba: int, offset: int, data: bytes) -> int:
        """Overwrite bytes inside a file, fixing EDC/ECC. Returns sectors touched."""
        touched = 0
        pos = 0
        while pos < len(data):
            lba = file_lba + (offset + pos) // DATA_SIZE
            in_sector = (offset + pos) % DATA_SIZE
            chunk = data[pos:pos + DATA_SIZE - in_sector]
            sector = bytearray(self.read_sector(lba))
            if not is_form1(sector):
                raise ValueError(f"LBA {lba} is not a Mode 2 Form 1 sector")
            start = DATA_OFFSET + in_sector
            sector[start:start + len(chunk)] = chunk
            regenerate_form1(sector)
            self.write_sector(lba, bytes(sector))
            pos += len(chunk)
            touched += 1
        return touched
