#!/usr/bin/env python3
"""
Post-process a ZisK guest ELF to convert SHT_INIT_ARRAY / SHT_PREINIT_ARRAY /
SHT_FINI_ARRAY section types to SHT_PROGBITS.

ZisK's elf_extraction.rs (zisk-core) only loads SHT_PROGBITS (1) and
SHT_NOBITS (8) sections.  Standard C++ toolchains emit constructor tables
in SHT_INIT_ARRAY (14) sections, which ZisK silently skips — leaving every
C++ global object in its zero-initialised (uninitialised) state.

This script patches the section-header type field in-place so the ZisK
emulator correctly initialises the constructor/destructor tables in RAM
before calling _start.
"""

import struct
import sys

SHT_PROGBITS    = 1
SHT_INIT_ARRAY  = 14
SHT_FINI_ARRAY  = 15
SHT_PREINIT_ARRAY = 16

CONVERT_TYPES = {SHT_INIT_ARRAY, SHT_FINI_ARRAY, SHT_PREINIT_ARRAY}


def patch_elf(path: str) -> int:
    with open(path, "r+b") as f:
        data = bytearray(f.read())

    # Verify ELF magic
    if data[:4] != b"\x7fELF":
        print(f"Error: {path} is not an ELF file", file=sys.stderr)
        return 1

    ei_class = data[4]
    if ei_class != 2:
        print(f"Error: expected ELF64 (class=2), got class={ei_class}", file=sys.stderr)
        return 1

    # ELF64 header fields
    e_shoff     = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum     = struct.unpack_from("<H", data, 60)[0]

    patched = 0
    for i in range(e_shnum):
        sh_off  = e_shoff + i * e_shentsize
        sh_type = struct.unpack_from("<I", data, sh_off + 4)[0]
        if sh_type in CONVERT_TYPES:
            struct.pack_into("<I", data, sh_off + 4, SHT_PROGBITS)
            patched += 1
            print(f"  section {i}: type {sh_type} → SHT_PROGBITS")

    with open(path, "wb") as f:
        f.write(data)

    print(f"Patched {patched} section(s) in {path}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <elf-file>", file=sys.stderr)
        sys.exit(1)
    sys.exit(patch_elf(sys.argv[1]))
