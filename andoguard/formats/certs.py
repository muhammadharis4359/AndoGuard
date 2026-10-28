"""APK signature verification and X.509 certificate parsing."""

import struct
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7

from andoguard.models import CertificateInfo, SignatureReport

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


def cert_to_info(cert: x509.Certificate) -> CertificateInfo:
    """Convert cryptography x509.Certificate to CertificateInfo model."""
    sha256_fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    sha1_fp = cert.fingerprint(hashes.SHA1()).hex().upper()
    md5_fp = cert.fingerprint(hashes.MD5()).hex().upper()

    try:
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
    except AttributeError:
        not_before = cert.not_valid_before.isoformat()
        not_after = cert.not_valid_after.isoformat()

    is_self = cert.issuer == cert.subject
    algo_name = getattr(cert.signature_algorithm_oid, "_name", "Unknown")

    return CertificateInfo(
        sha1_fingerprint=sha1_fp,
        sha256_fingerprint=sha256_fp,
        md5_fingerprint=md5_fp,
        issuer=cert.issuer.rfc4514_string(),
        subject=cert.subject.rfc4514_string(),
        valid_from=not_before,
        valid_to=not_after,
        serial_number=hex(cert.serial_number),
        signature_algorithm=algo_name,
        is_self_signed=is_self,
    )


def extract_certificates_from_apk(apk_path: Path) -> SignatureReport:
    """Extract APK signature schemes (v1, v2, v3) and X.509 certificate metadata."""
    if not apk_path.exists():
        return SignatureReport(is_signed=False)

    certs: list[CertificateInfo] = []
    v1_sig = False
    v2_sig = False
    v3_sig = False

    # Check v1 signature in META-INF
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                upper_name = name.upper()
                if upper_name.startswith("META-INF/") and (
                    upper_name.endswith(".RSA")
                    or upper_name.endswith(".DSA")
                    or upper_name.endswith(".EC")
                ):
                    v1_sig = True
                    cert_bytes = zf.read(name)
                    # Try loading as PKCS#7
                    try:
                        pkcs7_certs = pkcs7.load_der_pkcs7_certificates(cert_bytes)
                        for c in pkcs7_certs:
                            certs.append(cert_to_info(c))
                    except Exception:
                        # Try loading as raw DER certificate
                        try:
                            c = x509.load_der_x509_certificate(cert_bytes)
                            certs.append(cert_to_info(c))
                        except Exception:
                            pass
    except Exception:
        pass

    # Check v2/v3 signatures in APK Signing Block
    try:
        with open(apk_path, "rb") as f:
            f.seek(0, 2)
            file_len = f.tell()
            # Read last 64KB to locate End of Central Directory
            search_len = min(65536, file_len)
            f.seek(file_len - search_len)
            tail = f.read(search_len)
            eocd_idx = tail.rfind(b"\x50\x4b\x05\x06")
            if eocd_idx != -1:
                eocd_offset = (file_len - search_len) + eocd_idx
                f.seek(eocd_offset + 16)
                cd_offset = struct.unpack("<I", f.read(4))[0]

                # Check 24 bytes before Central Directory for APK Signing Block magic
                if cd_offset >= 24:
                    f.seek(cd_offset - 24)
                    block_size_low, block_size_high = struct.unpack("<II", f.read(8))
                    magic = f.read(16)
                    if magic == APK_SIG_BLOCK_MAGIC:
                        total_size = block_size_low
                        block_start = cd_offset - total_size - 8
                        if block_start >= 0:
                            f.seek(block_start + 8)
                            pairs_bytes = f.read(total_size - 24)
                            # Parse ID-value pairs in signing block
                            p_off = 0
                            while p_off + 12 <= len(pairs_bytes):
                                p_len = struct.unpack_from("<Q", pairs_bytes, p_off)[0]
                                p_id = struct.unpack_from("<I", pairs_bytes, p_off + 8)[
                                    0
                                ]
                                if p_id == 0x7109871A:
                                    v2_sig = True
                                elif p_id == 0xF05368C0:
                                    v3_sig = True
                                p_off += 8 + p_len
    except Exception:
        pass

    is_signed = v1_sig or v2_sig or v3_sig or len(certs) > 0
    return SignatureReport(
        is_signed=is_signed,
        v1_signature=v1_sig,
        v2_signature=v2_sig,
        v3_signature=v3_sig,
        certificates=certs,
    )
