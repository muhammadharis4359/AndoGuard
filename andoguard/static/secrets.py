"""Secret and credential detection with Shannon entropy and provenance tracking."""

import re

from andoguard.models import SecretFinding, StringItem
from andoguard.static.entropy import calculate_shannon_entropy

KNOWN_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,40})\b")),
    ("JWT Token", re.compile(r"\b(ey[A-Za-z0-9_-]{12,}\.ey[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{10,})\b")),
    ("Slack Token", re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b")),
    ("Private Key Header", re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
    ("Generic Auth / Secret Header", re.compile(r"(?i)(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret)[\s:=]+([a-zA-Z0-9_\-\.]{16,64})")),
]


def scan_strings_for_secrets(
    string_items: list[StringItem], min_entropy: float = 3.8
) -> list[SecretFinding]:
    """Scan extracted string items for credentials, tokens, and high-entropy secrets."""
    findings: list[SecretFinding] = []
    seen: set[str] = set()

    for item in string_items:
        val = item.value.strip()
        if not val or val in seen:
            continue

        matched_pattern = False
        # Check against known regex patterns
        for label, pat in KNOWN_SECRET_PATTERNS:
            match = pat.search(val)
            if match:
                extracted = match.group(1) if match.groups() else match.group(0)
                ent = calculate_shannon_entropy(extracted)
                findings.append(
                    SecretFinding(
                        secret_type=label,
                        value=extracted,
                        entropy=ent,
                        source_file=item.source,
                        provenance=f"Regex match: {label}",
                    )
                )
                seen.add(val)
                matched_pattern = True
                break

        if matched_pattern:
            continue

        # Check Shannon entropy for potential high-entropy keys/secrets
        # Exclude common strings with spaces, paths, or urls unless entropy is very high
        if len(val) >= 20 and " " not in val and not val.startswith("http"):
            ent = calculate_shannon_entropy(val)
            if ent >= min_entropy:
                findings.append(
                    SecretFinding(
                        secret_type="High-Entropy String",
                        value=val,
                        entropy=ent,
                        source_file=item.source,
                        provenance=f"Shannon entropy: {ent:.2f} >= {min_entropy}",
                    )
                )
                seen.add(val)

    # Sort findings by entropy descending
    findings.sort(key=lambda x: x.entropy, reverse=True)
    return findings
