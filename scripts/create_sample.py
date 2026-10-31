import datetime
import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def build_dex(strings: list[str]) -> bytes:
    str_data_bytes = bytearray()
    str_data_offsets = []
    for s in strings:
        str_data_offsets.append(len(str_data_bytes))
        b = s.encode("utf-8")
        str_data_bytes.append(len(b))
        str_data_bytes.extend(b)
        str_data_bytes.append(0)

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)
    string_ids_bytes = bytearray()

    data_off = string_ids_off + string_ids_size * 4
    for off in str_data_offsets:
        string_ids_bytes.extend(struct.pack("<I", data_off + off))

    map_off = data_off + len(str_data_bytes)
    map_list = (
        struct.pack("<I", 4)
        + struct.pack("<HHII", 0, 0, 1, 0)
        + struct.pack("<HHII", 1, 0, string_ids_size, string_ids_off)
        + struct.pack("<HHII", 0x2002, 0, string_ids_size, data_off)
        + struct.pack("<HHII", 0x1000, 0, 1, map_off)
    )

    total_size = map_off + len(map_list)
    body = struct.pack(
        "<20I",
        total_size,
        header_size,
        0x12345678,
        0,
        0,
        map_off,
        string_ids_size,
        string_ids_off,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        len(str_data_bytes) + len(map_list),
        data_off,
    )
    full_payload = body + string_ids_bytes + str_data_bytes + map_list
    sha1 = hashlib.sha1(full_payload).digest()
    adler = zlib.adler32(sha1 + full_payload)
    return b"dex\n035\x00" + struct.pack("<I", adler) + sha1 + full_payload

def generate_cert() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "InsecureBank Release Signer"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Insecure Financial Corp"),
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
    ])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x7F9A1B2C3D4E5F6A)
        .not_valid_before(now - datetime.timedelta(days=30))
        .not_valid_after(now + datetime.timedelta(days=730))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)

def make_elf64() -> bytes:
    magic = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        magic, 3, 0xB7, 1, 0x1000, 0, 64, 0, 64, 0, 0, 64, 0, 0
    )
    return header + b"Java_com_andoguard_insecurebank_CryptoManager_nativeDecryptToken\x00"

def main() -> None:
    manifest = b"""<manifest xmlns:android='http://schemas.android.com/apk/res/android'
    package='com.andoguard.insecurebank'
    android:versionCode='201'
    android:versionName='2.1.0'>

    <uses-sdk android:minSdkVersion='24' android:targetSdkVersion='33'/>

    <uses-permission android:name='android.permission.INTERNET'/>
    <uses-permission android:name='android.permission.ACCESS_FINE_LOCATION'/>
    <uses-permission android:name='android.permission.SEND_SMS'/>
    <uses-permission android:name='android.permission.READ_SMS'/>
    <uses-permission android:name='android.permission.RECORD_AUDIO'/>
    <uses-permission android:name='android.permission.READ_CONTACTS'/>
    <uses-permission android:name='android.permission.USE_BIOMETRIC'/>

    <permission android:name='com.andoguard.insecurebank.permission.ADMIN_TRANSFER'
        android:protectionLevel='normal'/>

    <application
        android:name='.InsecureBankApplication'
        android:label='Insecure Bank Mobile'
        android:debuggable='true'
        android:allowBackup='true'
        android:usesCleartextTraffic='true'>

        <activity android:name='.MainActivity' android:exported='true'>
            <intent-filter>
                <action android:name='android.intent.action.MAIN'/>
                <category android:name='android.intent.category.LAUNCHER'/>
            </intent-filter>
        </activity>

        <activity android:name='.TransferActivity' android:exported='true'/>
        <activity android:name='.DebugConsoleActivity' android:exported='true'/>
        <activity android:name='.LoginActivity' android:exported='false'/>

        <service android:name='.TelemetryService' android:exported='true'/>
        <service android:name='.SyncService' android:exported='false'/>

        <receiver android:name='.SmsReceiver' android:exported='true'>
            <intent-filter>
                <action android:name='android.provider.Telephony.SMS_RECEIVED'/>
            </intent-filter>
        </receiver>

        <provider android:name='.AccountContentProvider'
            android:authorities='com.andoguard.insecurebank.provider'
            android:exported='true'/>
    </application>
</manifest>"""

    strings = [
        "com.andoguard.insecurebank.MainActivity",
        "com.andoguard.insecurebank.TransferActivity",
        "com.andoguard.insecurebank.AuthManager",
        "com.andoguard.insecurebank.CryptoManager",
        "AKIAIOSFODNN7EXAMPLE",
        "AIzaSyD-InsecureBankGoogleApiKey9876543210",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImJhbmsiOiJpbnNlY3VyZSJ9.abcdef1234567890",
        "DES/ECB/PKCS5Padding",
        "AES/ECB/NoPadding",
        "MD5",
        "SHA-1",
        "http://api.insecurebank.com/v1/transfer",
        "TrustAllCertificates",
        "admin_master_secret_key_8492049182390192",
        "db_password_super_secret_998127391"
    ]

    dex_bytes = build_dex(strings)
    cert_bytes = generate_cert()
    elf_bytes = make_elf64()

    samples_dir = Path("samples")
    samples_dir.mkdir(exist_ok=True)
    apk_path = samples_dir / "insecure_bank.apk"

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("lib/arm64-v8a/libbankcrypto.so", elf_bytes)
        zf.writestr("lib/x86_64/libbankcrypto.so", elf_bytes)
        zf.writestr("assets/config.json", b'{"api_url": "http://api.insecurebank.com", "env": "staging", "debug": true}')
        zf.writestr("META-INF/CERT.RSA", cert_bytes)

    print(f"Generated {apk_path} successfully: {apk_path.stat().st_size} bytes")

if __name__ == "__main__":
    main()
