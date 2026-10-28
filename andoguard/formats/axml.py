"""Android Binary XML (AXML) parser and decoder.

Provides pure-Python decoding of compiled binary XML files (such as AndroidManifest.xml)
into standard XML strings and xml.etree.ElementTree structures.
"""

import struct
import xml.etree.ElementTree as ET

# AXML chunk types
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003

# XML chunk types
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

UTF8_FLAG = 1 << 8


class StringPool:
    """Decodes Android string pool chunks."""

    def __init__(self, data: bytes, offset: int) -> None:
        self.strings: list[str] = []
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if chunk_type != RES_STRING_POOL_TYPE:
            return

        string_count, style_count, flags, strings_start, styles_start = (
            struct.unpack_from("<IIIII", data, offset + 8)
        )
        is_utf8 = bool(flags & UTF8_FLAG)

        offsets_start = offset + header_size
        string_offsets = [
            struct.unpack_from("<I", data, offsets_start + i * 4)[0]
            for i in range(string_count)
        ]

        pool_strings_start = offset + strings_start

        for str_off in string_offsets:
            cur_pos = pool_strings_start + str_off
            if cur_pos >= len(data):
                self.strings.append("")
                continue

            try:
                if is_utf8:
                    # UTF-8 encoded string pool
                    # Skip length bytes
                    u16len = data[cur_pos]
                    cur_pos += 1
                    if u16len & 0x80:
                        cur_pos += 1
                    u8len = data[cur_pos]
                    cur_pos += 1
                    if u8len & 0x80:
                        cur_pos += 1
                    str_bytes = data[cur_pos : cur_pos + u8len]
                    self.strings.append(str_bytes.decode("utf-8", errors="replace"))
                else:
                    # UTF-16LE encoded string pool
                    u16len = struct.unpack_from("<H", data, cur_pos)[0]
                    cur_pos += 2
                    if u16len & 0x8000:
                        cur_pos += 2
                    byte_len = u16len * 2
                    str_bytes = data[cur_pos : cur_pos + byte_len]
                    self.strings.append(str_bytes.decode("utf-16le", errors="replace"))
            except Exception:
                self.strings.append("")

    def get_string(self, index: int) -> str:
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return ""


def is_axml(data: bytes) -> bool:
    """Return True if the data appears to be Android Binary XML."""
    if len(data) < 8:
        return False
    chunk_type = struct.unpack_from("<H", data, 0)[0]
    return bool(chunk_type == RES_XML_TYPE)


def parse_axml_to_element(data: bytes) -> ET.Element | None:
    """Parse binary or plain XML data into an ElementTree Element."""
    if not data:
        return None

    # Check if already plain text XML
    stripped = data.lstrip()
    if stripped.startswith(b"<"):
        try:
            return ET.fromstring(data.decode("utf-8", errors="replace"))
        except Exception:
            return None

    if not is_axml(data):
        return None

    try:
        offset = 8  # Skip root XML chunk header (type=0x0003, header_size, chunk_size)
        string_pool: StringPool | None = None
        namespaces: dict[str, str] = {}  # prefix -> uri
        element_stack: list[ET.Element] = []
        root_element: ET.Element | None = None

        while offset + 8 <= len(data):
            chunk_type, header_size, chunk_size = struct.unpack_from(
                "<HHI", data, offset
            )
            if chunk_size < 8:
                break

            chunk_data = data[offset : offset + chunk_size]

            if chunk_type == RES_STRING_POOL_TYPE:
                string_pool = StringPool(data, offset)
            elif chunk_type == RES_XML_START_NAMESPACE_TYPE:
                if string_pool:
                    prefix_idx, uri_idx = struct.unpack_from("<II", chunk_data, 16)
                    prefix = string_pool.get_string(prefix_idx)
                    uri = string_pool.get_string(uri_idx)
                    namespaces[uri] = prefix
            elif chunk_type == RES_XML_START_ELEMENT_TYPE:
                if string_pool:
                    ns_idx, name_idx, attr_start, attr_size, attr_count = (
                        struct.unpack_from("<IIHHH", chunk_data, 16)
                    )
                    tag_name = string_pool.get_string(name_idx)

                    attribs: dict[str, str] = {}
                    # Attributes follow header
                    for i in range(attr_count):
                        attr_offset = attr_start + i * attr_size
                        if attr_offset + 20 <= len(chunk_data):
                            ans_idx, aname_idx, val_idx, val_type, val_data = (
                                struct.unpack_from("<IIIBBHI", chunk_data, attr_offset)
                            )[:5]
                            attr_name = string_pool.get_string(aname_idx)
                            attr_val = (
                                string_pool.get_string(val_idx)
                                if val_idx != 0xFFFFFFFF
                                else str(val_data)
                            )
                            # Handle standard android namespace
                            attr_ns = (
                                string_pool.get_string(ans_idx)
                                if ans_idx != 0xFFFFFFFF
                                else ""
                            )
                            if (
                                "android" in attr_ns.lower()
                                or namespaces.get(attr_ns) == "android"
                            ):
                                attribs[f"android:{attr_name}"] = attr_val
                            else:
                                attribs[attr_name] = attr_val

                    elem = ET.Element(tag_name, attrib=attribs)
                    if not root_element:
                        root_element = elem
                    if element_stack:
                        element_stack[-1].append(elem)
                    element_stack.append(elem)

            elif chunk_type == RES_XML_END_ELEMENT_TYPE:
                if element_stack:
                    element_stack.pop()

            offset += chunk_size

        return root_element
    except Exception:
        return None


def axml_to_string(data: bytes) -> str:
    """Convert binary or plain XML data to formatted XML string."""
    elem = parse_axml_to_element(data)
    if elem is None:
        return ""
    try:
        ET.indent(elem, space="  ")
        return ET.tostring(elem, encoding="unicode")
    except Exception:
        return ET.tostring(elem, encoding="unicode")
