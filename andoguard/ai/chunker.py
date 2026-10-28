"""Context chunking and token estimation for decompiled source and metadata."""

import re

# Boundary markers for Smali / Java / Kotlin decompiled code
_METHOD_BOUNDARY_RE = re.compile(
    r"(?:^[ \t]*(?:public|private|protected|static|final|abstract|synchronized|native)[ \t]+[\w<>\[\], ]+[ \t]+\w+[ \t]*\(|"
    r"^[ \t]*\.method[ \t]+|"
    r"^[ \t]*(?:fun|val|var|class|interface|object)[ \t]+\w+)",
    re.MULTILINE,
)


def estimate_tokens(text: str) -> int:
    """Estimate token count using 4 characters per token heuristic."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def chunk_code(
    source: str,
    max_chars: int = 4000,
    overlap: int = 200,
) -> list[str]:
    """Split decompiled source code into contextual chunks at method/class boundaries.

    Ensures large classes are chunked without splitting mid-statement.
    """
    if len(source) <= max_chars:
        return [source]

    chunks: list[str] = []
    lines = source.splitlines(keepends=True)

    current_chunk: list[str] = []
    current_length = 0

    for line in lines:
        line_len = len(line)
        # Check if line looks like a method or class header
        is_boundary = bool(_METHOD_BOUNDARY_RE.match(line))
        should_split = (current_length + line_len > max_chars) or (
            is_boundary and current_length >= int(max_chars * 0.75)
        )

        if should_split:
            if current_chunk:
                chunk_str = "".join(current_chunk)
                chunks.append(chunk_str)

                # Overlap context: retain trailing lines up to overlap budget
                overlap_lines: list[str] = []
                overlap_len = 0
                for prev_line in reversed(current_chunk):
                    if overlap_len + len(prev_line) > overlap:
                        break
                    overlap_lines.insert(0, prev_line)
                    overlap_len += len(prev_line)

                current_chunk = overlap_lines + [line]
                current_length = overlap_len + line_len
            else:
                # Single line exceeds max_chars; hard slice
                chunks.append(line[:max_chars])
                current_chunk = [line[max_chars:]]
                current_length = len(current_chunk[0])
        else:
            current_chunk.append(line)
            current_length += line_len

    if current_chunk:
        chunks.append("".join(current_chunk))

    return chunks
