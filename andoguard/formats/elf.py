"""Pure-Python ELF binary parser for native Android shared libraries (.so)."""

import struct
from pathlib import Path

from andoguard.models import ElfInfo

# ELF Header constants
ELF_MAGIC = b"\x7fELF"
EI_CLASS = 4
EI_DATA = 5

ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATA2LSB = 1  # Little endian
ELFDATA2MSB = 2  # Big endian

MACHINE_NAMES = {
    0x03: "x86",
    0x28: "ARM",
    0x3E: "x86_64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}

DT_NEEDED = 1


def is_elf_file(data: bytes) -> bool:
    """Check if header matches ELF magic bytes."""
    return data[:4] == ELF_MAGIC


def parse_elf_bytes(data: bytes, file_name: str = "native.so") -> ElfInfo:
    """Parse ELF binary from byte buffer."""
    if len(data) < 52 or not is_elf_file(data):
        return ElfInfo(path=file_name, arch="unknown", bits=32, endianness="unknown")

    ei_class = data[EI_CLASS]
    ei_data = data[EI_DATA]

    bits = 64 if ei_class == ELFCLASS64 else 32
    endian_fmt = "<" if ei_data == ELFDATA2LSB else ">"
    endian_name = "little" if ei_data == ELFDATA2LSB else "big"

    # Unpack e_machine, e_shoff, e_shentsize, e_shnum, e_shstrndx
    if bits == 32:
        if len(data) < 52:
            return ElfInfo(path=file_name, arch="unknown", bits=32, endianness=endian_name)
        _, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            f"{endian_fmt}16sHHIIIIIHHHHHH", data, 0
        )
    else:
        if len(data) < 64:
            return ElfInfo(path=file_name, arch="unknown", bits=64, endianness=endian_name)
        _, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            f"{endian_fmt}16sHHIQQQIHHHHHH", data, 0
        )

    arch = MACHINE_NAMES.get(e_machine, f"machine-0x{e_machine:x}")

    # Read section headers
    sections: list[dict[str, int]] = []
    for i in range(e_shnum):
        offset = e_shoff + i * e_shentsize
        if offset + e_shentsize > len(data):
            break
        if bits == 32:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                f"{endian_fmt}10I", data, offset
            )
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                f"{endian_fmt}2I2Q4Q", data, offset
            )
        sections.append({
            "name_idx": sh_name,
            "type": sh_type,
            "offset": sh_offset,
            "size": sh_size,
            "link": sh_link,
            "entsize": sh_entsize,
        })

    # Read section name string table
    shstrtab = b""
    if 0 <= e_shstrndx < len(sections):
        sh_sec = sections[e_shstrndx]
        shstrtab = data[sh_sec["offset"] : sh_sec["offset"] + sh_sec["size"]]

    def get_string(strtab: bytes, idx: int) -> str:
        if idx >= len(strtab):
            return ""
        end = strtab.find(b"\x00", idx)
        if end == -1:
            end = len(strtab)
        return strtab[idx:end].decode("utf-8", errors="replace")

    # Map section names
    dynsym_sec = None
    dynstr_sec = None
    dynamic_sec = None
    for s in sections:
        name = get_string(shstrtab, s["name_idx"])
        s["name"] = name  # type: ignore[assignment]
        if name == ".dynsym":
            dynsym_sec = s
        elif name == ".dynstr":
            dynstr_sec = s
        elif name == ".dynamic":
            dynamic_sec = s

    # Read dynstr table
    dynstr = b""
    if dynstr_sec:
        dynstr = data[dynstr_sec["offset"] : dynstr_sec["offset"] + dynstr_sec["size"]]

    # Read DT_NEEDED dependencies from .dynamic
    needed_libs: list[str] = []
    if dynamic_sec:
        dyn_off = dynamic_sec["offset"]
        dyn_sz = dynamic_sec["size"]
        step = 8 if bits == 32 else 16
        for cur_off in range(dyn_off, min(dyn_off + dyn_sz, len(data)), step):
            if bits == 32:
                d_tag, d_val = struct.unpack_from(f"{endian_fmt}2i", data, cur_off)
            else:
                d_tag, d_val = struct.unpack_from(f"{endian_fmt}2q", data, cur_off)
            if d_tag == 0:  # DT_NULL
                break
            if d_tag == DT_NEEDED:
                lib_name = get_string(dynstr, d_val)
                if lib_name:
                    needed_libs.append(lib_name)

    # Read symbols from .dynsym
    jni_exports: list[str] = []
    total_symbols = 0

    if dynsym_sec:
        sym_off = dynsym_sec["offset"]
        sym_sz = dynsym_sec["size"]
        entsize = dynsym_sec["entsize"] or (16 if bits == 32 else 24)
        sym_count = sym_sz // entsize if entsize else 0
        total_symbols = sym_count

        for i in range(sym_count):
            cur = sym_off + i * entsize
            if cur + entsize > len(data):
                break
            if bits == 32:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                    f"{endian_fmt}3IBBH", data, cur
                )
            else:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                    f"{endian_fmt}IBBH2Q", data, cur
                )

            s_name = get_string(dynstr, st_name)
            if s_name:
                if s_name.startswith("Java_") or s_name in ("JNI_OnLoad", "JNI_OnUnload"):
                    jni_exports.append(s_name)

    return ElfInfo(
        path=file_name,
        arch=arch,
        bits=bits,
        endianness=endian_name,
        needed_libs=needed_libs,
        jni_exports=jni_exports,
        symbols_count=total_symbols,
    )


def parse_elf_file(file_path: Path) -> ElfInfo:
    """Parse ELF binary from filesystem path."""
    with open(file_path, "rb") as f:
        data = f.read()
    return parse_elf_bytes(data, file_name=file_path.name)
