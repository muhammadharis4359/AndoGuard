"""Pure-Python Dalvik Executable (DEX) container and header inspector."""

import struct
from dataclasses import dataclass

from andoguard.errors import InvalidTargetError

DEX_MAGICS = {
    b"dex\n035\x00": "035",
    b"dex\n036\x00": "036",
    b"dex\n037\x00": "037",
    b"dex\n038\x00": "038",
    b"dex\n039\x00": "039",
    b"dex\n040\x00": "040",
    b"dex\n041\x00": "041",
}


@dataclass
class DexHeader:
    """Header fields parsed from a DEX binary."""

    magic: bytes
    version: str
    checksum: int
    signature: bytes
    file_size: int
    header_size: int
    endian_tag: int
    link_size: int
    link_off: int
    map_off: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int


def is_dex_file(data: bytes) -> bool:
    """Check if binary starts with valid DEX magic bytes."""
    return len(data) >= 8 and data[:8] in DEX_MAGICS


def parse_dex_header(data: bytes) -> DexHeader:
    """Parse DEX header bytes into structured fields."""
    if len(data) < 112:
        raise InvalidTargetError(
            "dex", "File too small to contain a valid DEX header (min 112 bytes)."
        )

    magic = data[:8]
    if magic not in DEX_MAGICS:
        raise InvalidTargetError("dex", f"Unrecognized DEX magic: {magic!r}")

    version = DEX_MAGICS[magic]
    checksum = struct.unpack_from("<I", data, 8)[0]
    signature = data[12:32]
    (
        file_size,
        header_size,
        endian_tag,
        link_size,
        link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        field_ids_size,
        field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    ) = struct.unpack_from("<20I", data, 32)

    return DexHeader(
        magic=magic,
        version=version,
        checksum=checksum,
        signature=signature,
        file_size=file_size,
        header_size=header_size,
        endian_tag=endian_tag,
        link_size=link_size,
        link_off=link_off,
        map_off=map_off,
        string_ids_size=string_ids_size,
        string_ids_off=string_ids_off,
        type_ids_size=type_ids_size,
        type_ids_off=type_ids_off,
        proto_ids_size=proto_ids_size,
        proto_ids_off=proto_ids_off,
        field_ids_size=field_ids_size,
        field_ids_off=field_ids_off,
        method_ids_size=method_ids_size,
        method_ids_off=method_ids_off,
        class_defs_size=class_defs_size,
        class_defs_off=class_defs_off,
        data_size=data_size,
        data_off=data_off,
    )


def extract_dex_strings(data: bytes, limit: int | None = 1000) -> list[str]:
    """Extract raw strings from DEX string_ids pool."""
    header = parse_dex_header(data)
    strings: list[str] = []
    max_count = min(header.string_ids_size, limit) if limit else header.string_ids_size

    for i in range(max_count):
        off_pos = header.string_ids_off + i * 4
        if off_pos + 4 > len(data):
            break
        str_data_off = struct.unpack_from("<I", data, off_pos)[0]
        if str_data_off >= len(data):
            continue

        # Read LEB128 string length
        pos = str_data_off
        length = 0
        shift = 0
        while pos < len(data):
            b = data[pos]
            pos += 1
            length |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7

        # Extract null-terminated MUTF-8 string
        end_pos = data.find(b"\x00", pos)
        if end_pos != -1:
            raw_str = data[pos:end_pos]
            try:
                decoded = raw_str.decode("utf-8", errors="replace")
                if decoded.isprintable():
                    strings.append(decoded)
            except Exception:
                pass

    return strings
