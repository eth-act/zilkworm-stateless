/*
 * Copyright 2026 The Zilkworm Authors
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Linker script for ZisK zkVM bare-metal C++ guest (rv64ima).
 *
 * ZisK memory map (from 0xpolygonhermez/zisk core/src/mem.rs):
 *
 *   INPUT_ADDR        0x4000_0000  128 MiB  Memory-mapped input (read by guest)
 *   ROM_ADDR          0x8000_0000  128 MiB  ELF .text / .rodata loaded here
 *   FLOAT_LIB_ROM     0x87F0_0000    1 MiB  Float library (avoid overlap)
 *   RAM / SYS_ADDR    0xa000_0000  512 MiB  All guest-writable RAM
 *     Registers       0xa000_0000    256 B  x0-x31 (BIOS internal)
 *     UART            0xa000_0200      1 B  Write byte → stdout
 *     OUTPUT_ADDR     0xa001_0000   64 KiB  Public output (64 × u32 slots)
 *     AVAILABLE_MEM   0xa003_0000  ~512 MiB Guest data / bss / heap
 *   END_OF_RAM        0xC000_0000
 *
 * LOAD segment layout (explicit PHDRS so FLAGS are exact):
 *
 *   phdr_text  (FLAGS 5 = R+E)
 *       .text.init, .text, .rodata, .rodata1
 *       All sections are read-only in ROM → no W bit on this segment.
 *
 *   phdr_data  (FLAGS 6 = R+W, LMA in ROM, VMA in RAM)
 *       .preinit_array, .init_array, .fini_array, .ctors, .dtors,
 *       .data, .sdata
 *       These have SHF_WRITE so they MUST be in an R+W segment.
 *       LMA is in ROM (binary image); VMA is in RAM (runtime address).
 *       _start copies this region from ROM → RAM before calling main().
 *
 *   phdr_bss   (FLAGS 6 = R+W, no file image)
 *       .sbss, .bss — zero-initialised by _start.
 *
 * Rationale for moving init_array to the data segment:
 *   INIT_ARRAY / PREINIT_ARRAY / FINI_ARRAY section types carry SHF_WRITE
 *   in the ELF specification.  ZisK's Riscv2zisk converter rejects writable
 *   sections whose VMA falls outside the RAM window [0xa000_0000, 0xc000_0000).
 *   By placing these sections in the RAM (data) segment, their VMA is in RAM
 *   and the ROM segment stays clean (R+E only).
 */

OUTPUT_FORMAT("elf64-littleriscv", "elf64-littleriscv", "elf64-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
    /* ROM: code + read-only data.  Cap at 0x87F0_0000 to avoid float lib. */
    ROM (rx)  : ORIGIN = 0x80000000, LENGTH = 0x07F00000   /* 127 MiB */

    /* RAM: writable data, bss, stack, heap.  Starts at AVAILABLE_MEM_ADDR. */
    RAM (rwx) : ORIGIN = 0xa0030000, LENGTH = 0x1FFD0000   /* ~512 MiB */
}

/* Explicit program headers — FLAGS override the per-section SHF flags. */
PHDRS {
    phdr_text  PT_LOAD FLAGS(5);   /* R + E  — read-only / executable ROM  */
    phdr_data  PT_LOAD FLAGS(6);   /* R + W  — data segment (LMA ROM, VMA RAM) */
    phdr_bss   PT_LOAD FLAGS(6);   /* R + W  — BSS (no file image)         */
}

SECTIONS {
    /* ─── Entry point (ROM, R+E) ────────────────────────────────────────── */
    .text.init 0x80000000 : {
        KEEP(*(.text.init .text.init.*))
        . = ALIGN(8);
    } > ROM :phdr_text

    /* ─── Code (ROM, R+E) ───────────────────────────────────────────────── */
    .text : {
        *(.text.unlikely .text.*_unlikely .text.unlikely.*)
        *(.text.exit .text.exit.*)
        *(.text.startup .text.startup.*)
        *(.text.hot .text.hot.*)
        *(SORT(.text.sorted.*))
        *(.text .stub .text.* .gnu.linkonce.t.*)
        *(.gnu.warning)
        . = ALIGN(8);
    } > ROM :phdr_text

    .init : { KEEP(*(SORT_NONE(.init))) . = ALIGN(8); } > ROM :phdr_text
    .fini : { KEEP(*(SORT_NONE(.fini))) . = ALIGN(8); } > ROM :phdr_text
    .plt  : { *(.plt) *(.iplt) . = ALIGN(8); } > ROM :phdr_text

    PROVIDE(__etext = .);
    PROVIDE(_etext  = .);
    PROVIDE(etext   = .);

    /* ─── Read-only data (ROM, R+E) ─────────────────────────────────────── */
    /* ZisK Mem::add_read_section() requires 8-byte-aligned section starts.
     * Append ALIGN(8) after each block so the next section starts aligned.
     *
     * .gcc_except_table and .eh_frame are discarded below (unused in a
     * bare-metal zkVM guest compiled with -fno-exceptions).                 */
    .rodata : {
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.srodata.cst16) *(.srodata.cst8) *(.srodata.cst4) *(.srodata.cst2)
        *(.srodata .srodata.*)
        /* Fold .rodata1 in here so no separate empty section is created.
         * An empty .rodata1 output section can inherit WA flags from context
         * and would then fail ZisK's "no writable section outside RAM" check. */
        *(.rodata1)
        . = ALIGN(8);
    } > ROM :phdr_text

    /* 8-byte tail pad: Riscv2zisk fetches instructions in 8-byte chunks;
     * without this pad, a fetch at the last 4-byte instruction crosses the
     * segment boundary and the ZisK emulator panics with "section not found". */
    .rom_pad : { QUAD(0); } > ROM :phdr_text

    /* ─── Writable data (VMA and LMA both in RAM) — phdr_data ──────────── */
    /*
     * ZisK's ELF loader maps each LOAD segment directly to its VMA — it does
     * NOT use a separate ROM LMA for initialised data.  Using AT > ROM would
     * place the data's LMA in the ROM segment which is unmapped in the ZisK
     * emulator, causing a "section not found" panic in the data-copy loop in
     * _start.
     *
     * By keeping VMA == LMA (both in RAM), the ZisK ELF loader places the
     * file image directly at the RAM address, and _start's copy check
     * (beq __data_load, __data_start → skip) fires immediately.
     */

    /*
     * C++ constructor / destructor tables.
     *
     * IMPORTANT: ZisK's ELF extractor (elf_extraction.rs) only handles
     * SHT_PROGBITS (1) and SHT_NOBITS (8) sections.  Standard GNU ld
     * assigns type SHT_INIT_ARRAY (14) / SHT_PREINIT_ARRAY (16) /
     * SHT_FINI_ARRAY (15) when the output section is named ".init_array" /
     * ".preinit_array" / ".fini_array".  ZisK silently skips these, leaving
     * the constructor tables zero — every global C++ object is then corrupt.
     *
     * Fix: use custom output-section names (".z_preinit", ".z_init",
     * ".z_fini") so GNU ld defaults them to SHT_PROGBITS and ZisK loads
     * them correctly.  The linker-provided symbols __preinit_array_start /
     * __init_array_start / __init_array_end etc. are defined here; the
     * __start() runtime iterates those symbols directly so no change to
     * zisk_runtime.cpp is needed.
     */

    /*
     * C++ constructor/destructor tables.
     *
     * ZisK's elf_extraction.rs only processes SHT_PROGBITS and SHT_NOBITS.
     * Standard GCC emits these sections as SHT_INIT_ARRAY (14) which ZisK
     * silently skips.  After linking we run fix_elf_sections.py (invoked via
     * the CMakeLists custom command) which patches these section types to
     * SHT_PROGBITS so ZisK initialises them correctly via add_zisk_init_data.
     *
     * Memory: VMA in RAM (ZisK maps them there), LMA also in RAM (== VMA)
     * so _start's data-copy loop sees LMA == VMA and skips the copy.
     */

    .preinit_array : {
        PROVIDE_HIDDEN(__preinit_array_start = .);
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN(__preinit_array_end = .);
        . = ALIGN(8);
    } > RAM :phdr_data

    .init_array : {
        PROVIDE_HIDDEN(__init_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP(*(.init_array EXCLUDE_FILE(*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o) .ctors))
        PROVIDE_HIDDEN(__init_array_end = .);
        . = ALIGN(8);
    } > RAM :phdr_data

    .fini_array : {
        PROVIDE_HIDDEN(__fini_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP(*(.fini_array EXCLUDE_FILE(*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o) .dtors))
        PROVIDE_HIDDEN(__fini_array_end = .);
        . = ALIGN(8);
    } > RAM :phdr_data

    .ctors : {
        KEEP(*crtbegin.o(.ctors))  KEEP(*crtbegin?.o(.ctors))
        KEEP(*(EXCLUDE_FILE(*crtend.o *crtend?.o) .ctors))
        KEEP(*(SORT(.ctors.*)))    KEEP(*(.ctors))
        . = ALIGN(8);
    } > RAM :phdr_data

    .dtors : {
        KEEP(*crtbegin.o(.dtors))  KEEP(*crtbegin?.o(.dtors))
        KEEP(*(EXCLUDE_FILE(*crtend.o *crtend?.o) .dtors))
        KEEP(*(SORT(.dtors.*)))    KEEP(*(.dtors))
        . = ALIGN(8);
    } > RAM :phdr_data

    /* Initialised data. */
    .data : {
        PROVIDE_HIDDEN(__data_start = .);
        __DATA_BEGIN__ = .;
        *(.data .data.* .gnu.linkonce.d.*)
        SORT(CONSTRUCTORS)
        *(.data1)
        . = ALIGN(8);
    } > RAM :phdr_data

    .sdata : {
        __SDATA_BEGIN__ = .;
        *(.sdata .sdata.* .gnu.linkonce.s.*)
        *(.got.plt) *(.igot.plt) *(.got) *(.igot)
        . = ALIGN(8);
    } > RAM :phdr_data

    PROVIDE_HIDDEN(__data_end  = .);
    /* LMA == VMA (no AT > ROM), so __data_load == __data_start and
     * the data-copy loop in _start is skipped automatically. */
    PROVIDE_HIDDEN(__data_load = __data_start);

    /* ─── BSS (zero-initialised, no file image) — phdr_bss ─────────────── */
    . = ALIGN(8);
    __bss_start = .;

    .sbss : {
        *(.dynsbss) *(.sbss .sbss.* .gnu.linkonce.sb.*) *(.scommon)
    } > RAM :phdr_bss

    .bss : {
        *(.dynbss) *(.bss .bss.* .gnu.linkonce.b.*) *(COMMON)
        . = ALIGN(8);
    } > RAM :phdr_bss

    . = ALIGN(8);
    __BSS_END__ = .;

    /* RISC-V GP: mid-point of small-data region for ±2 KiB GP-relative reach. */
    __global_pointer$ = MIN(__SDATA_BEGIN__ + 0x800,
                            MAX(__DATA_BEGIN__ + 0x800, __BSS_END__ - 0x800));

    _end = .; PROVIDE(end = .);

    /* ─── Stack (256 KiB above BSS, grows downward) ─────────────────────── */
    . = ALIGN(16);
    . += 0x40000;
    _init_stack_top = .;

    /* ─── Heap (zkvm-standards static-library-and-linker-script) ────────── */
    /* Above the stack so heap growth can never clobber stack frames (the
       previous _end-based heap base overlapped the stack region). */
    . = ALIGN(16);
    _heap_start = .;
    _heap_end   = ORIGIN(RAM) + LENGTH(RAM);

    /* ─── Debug sections (zero VMA, not loaded) ─────────────────────────── */
    .stab          0 : { *(.stab) }
    .stabstr       0 : { *(.stabstr) }
    .debug         0 : { *(.debug) }
    .debug_info    0 : { *(.debug_info .gnu.linkonce.wi.*) }
    .debug_abbrev  0 : { *(.debug_abbrev) }
    .debug_line    0 : { *(.debug_line .debug_line.* .debug_line_end) }
    .debug_frame   0 : { *(.debug_frame) }
    .debug_str     0 : { *(.debug_str) }
    .debug_loc     0 : { *(.debug_loc) }
    .debug_ranges  0 : { *(.debug_ranges) }
    .debug_addr    0 : { *(.debug_addr) }
    .debug_line_str   0 : { *(.debug_line_str) }
    .debug_loclists   0 : { *(.debug_loclists) }
    .debug_rnglists   0 : { *(.debug_rnglists) }
    .debug_macro   0 : { *(.debug_macro) }
    .debug_names   0 : { *(.debug_names) }
    .gnu.attributes 0 : { KEEP(*(.gnu.attributes)) }

    /DISCARD/ : {
        *(.note.GNU-stack)
        *(.gnu_debuglink)
        *(.gnu.lto_*)
        *(.interp)
        /* C++ exception-handling tables — never used in a bare-metal zkVM
         * guest compiled with -fno-exceptions.  Discarding them removes
         * 4-byte-aligned sections that would otherwise cause ZisK's
         * Mem::add_read_section() alignment panic.                         */
        *(.gcc_except_table .gcc_except_table.*)
        *(.eh_frame .eh_frame.* .eh_frame_hdr)
        *(.gnu_extab .gnu_extab*)
        *(.exception_ranges .exception_ranges*)
    }
}
