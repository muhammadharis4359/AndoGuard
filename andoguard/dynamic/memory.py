"""Process memory search, region dumping, and hexdump formatting."""

def format_hexdump(data: bytes, base_address: int = 0) -> str:
    """Format raw byte array into canonical hex dump view."""
    lines: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{base_address + i:08x}:  {hex_bytes:<48}  |{ascii_chars}|")
    return "\n".join(lines)


def generate_memory_search_script(pattern: str, is_hex: bool = False) -> str:
    """Generate Frida script to scan readable memory ranges for pattern."""
    if is_hex:
        pat_expr = f'"{pattern}"'
    else:
        # Convert ASCII string to hex pattern (e.g. "password" -> "70 61 73 73 77 6f 72 64")
        hex_pat = " ".join(f"{ord(c):02x}" for c in pattern)
        pat_expr = f'"{hex_pat}"'

    return f"""// AndoGuard Memory Search: {pattern}
var pattern = {pat_expr};
console.log("[*] Scanning readable memory ranges for: " + pattern);

var ranges = Process.enumerateRanges('r--');
var matchesCount = 0;

ranges.forEach(function(range) {{
    try {{
        Memory.scan(range.base, range.size, pattern, {{
            onMatch: function(address, size) {{
                matchesCount++;
                send({{
                    event_type: "mem_match",
                    address: address.toString(),
                    size: size,
                    range_base: range.base.toString(),
                    range_protection: range.protection
                }});
                if (matchesCount >= 50) return 'stop';
            }},
            onError: function(reason) {{}},
            onComplete: function() {{}}
        }});
    }} catch(err) {{}}
}});

send({{ event_type: "mem_scan_complete", matches: matchesCount }});
"""


def generate_memory_dump_script(address: str, length: int) -> str:
    """Generate Frida script to read and dump memory region."""
    return f"""// AndoGuard Memory Region Dump: {address} ({length} bytes)
try {{
    var targetPtr = ptr("{address}");
    var buffer = targetPtr.readByteArray({length});
    send({{
        event_type: "mem_dump",
        address: "{address}",
        length: {length}
    }}, buffer);
}} catch(err) {{
    send({{ event_type: "error", message: err.toString() }});
}}
"""
