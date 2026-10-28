"""Android Resource Table (resources.arsc) parser.

Provides pure-Python extraction of string and asset resources from compiled resources.arsc.
"""

import struct

from andoguard.formats.axml import RES_STRING_POOL_TYPE, RES_TABLE_TYPE, StringPool
from andoguard.models import ResourceEntry

RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202


class ArscParser:
    """Pure-Python parser for Android resources.arsc files."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.resources: list[ResourceEntry] = []
        self._parse()

    def _parse(self) -> None:
        if len(self.data) < 12:
            return

        chunk_type, header_size, chunk_size, package_count = struct.unpack_from(
            "<HHI I", self.data, 0
        )
        if chunk_type != RES_TABLE_TYPE:
            return

        offset = header_size
        global_strings: StringPool | None = None

        while offset + 8 <= len(self.data):
            c_type, c_hsize, c_size = struct.unpack_from("<HHI", self.data, offset)
            if c_size < 8 or offset + c_size > len(self.data):
                break

            if c_type == RES_STRING_POOL_TYPE:
                global_strings = StringPool(self.data, offset)
            elif c_type == RES_TABLE_PACKAGE_TYPE:
                self._parse_package(offset, c_size, global_strings)

            offset += c_size

    def _parse_package(
        self, pkg_offset: int, pkg_size: int, global_strings: StringPool | None
    ) -> None:
        pkg_id = struct.unpack_from("<I", self.data, pkg_offset + 8)[0]
        pkg_name_raw = self.data[pkg_offset + 12 : pkg_offset + 12 + 256]
        pkg_name = pkg_name_raw.decode("utf-16le", errors="ignore").split("\x00")[0]

        type_strings_offset = struct.unpack_from("<I", self.data, pkg_offset + 268)[0]
        key_strings_offset = struct.unpack_from("<I", self.data, pkg_offset + 276)[0]

        type_strings: StringPool | None = None
        key_strings: StringPool | None = None

        if type_strings_offset > 0:
            type_strings = StringPool(self.data, pkg_offset + type_strings_offset)
        if key_strings_offset > 0:
            key_strings = StringPool(self.data, pkg_offset + key_strings_offset)

        sub_offset = pkg_offset + max(
            288,
            key_strings_offset
            + (
                struct.unpack_from(
                    "<I", self.data, pkg_offset + key_strings_offset + 4
                )[0]
                if key_strings_offset > 0
                else 0
            ),
        )

        while sub_offset + 8 <= pkg_offset + pkg_size:
            sub_type, sub_hsize, sub_size = struct.unpack_from(
                "<HHI", self.data, sub_offset
            )
            if sub_size < 8:
                break

            if sub_type == RES_TABLE_TYPE_TYPE and type_strings and key_strings:
                t_id, _, entry_count, entries_start = struct.unpack_from(
                    "<BB H II", self.data, sub_offset + 8
                )[:4]
                type_name = type_strings.get_string(t_id - 1)

                entry_offsets = [
                    struct.unpack_from("<I", self.data, sub_offset + sub_hsize + i * 4)[
                        0
                    ]
                    for i in range(entry_count)
                ]

                for entry_idx, ent_off in enumerate(entry_offsets):
                    if ent_off == 0xFFFFFFFF:
                        continue
                    cur_ent = sub_offset + entries_start + ent_off
                    if cur_ent + 8 > len(self.data):
                        continue

                    e_size, e_flags, key_idx = struct.unpack_from(
                        "<HHI", self.data, cur_ent
                    )
                    res_name = key_strings.get_string(key_idx)
                    res_id_int = (pkg_id << 24) | (t_id << 16) | entry_idx
                    res_id_hex = f"0x{res_id_int:08x}"

                    val_str = None
                    # Simple value chunk
                    if not (e_flags & 0x0001) and cur_ent + 16 <= len(self.data):
                        v_size, _, v_data_type, v_data = struct.unpack_from(
                            "<HBBI", self.data, cur_ent + 8
                        )
                        if (
                            v_data_type == 0x03
                            and global_strings
                            and v_data < len(global_strings.strings)
                        ):
                            val_str = global_strings.get_string(v_data)
                        elif v_data_type in (0x11, 0x12):  # int / boolean
                            val_str = str(v_data)
                        elif v_data_type == 0x01:  # reference
                            val_str = f"@0x{v_data:08x}"

                    self.resources.append(
                        ResourceEntry(
                            res_id=res_id_hex,
                            res_type=type_name or "unknown",
                            name=res_name or f"res_{entry_idx}",
                            value=val_str,
                            config=pkg_name,
                        )
                    )

            sub_offset += sub_size


def parse_arsc_resources(data: bytes) -> list[ResourceEntry]:
    """Parse resources.arsc bytes into ResourceEntry list."""
    try:
        parser = ArscParser(data)
        return parser.resources
    except Exception:
        return []
