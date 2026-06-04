/*
 * Copyright 2026 The Zilkworm Authors
 * SPDX-License-Identifier: Apache-2.0
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
 * Layout strategy:
 *   - .text.init  → ROM at 0x8000_0000 (ZisK entry must be here)
 *   - .text, .rodata, ctor tables → ROM (read-only segments)
 *   - .data → VMA in RAM (0xa003_0000+), LMA in ROM (copy done by _start)
 *   - .bss  → VMA in RAM, zeroed by _start
 *   - Stack → 256 KiB above end of BSS (grows downward from _init_stack_top)
 *   - Heap  → from _end upward (managed by _sbrk in zisk_runtime.cpp)
 */

OUTPUT_FORMAT("elf64-littleriscv", "elf64-littleriscv", "elf64-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
    /* ROM: code + read-only data.  Cap at 0x87F0_0000 to stay clear of float lib. */
    ROM (rx)  : ORIGIN = 0x80000000, LENGTH = 0x07F00000   /* 127 MiB */

    /* RAM: writable data, bss, stack, heap.  Starts at AVAILABLE_MEM_ADDR. */
    RAM (rwx) : ORIGIN = 0xa0030000, LENGTH = 0x1FFD0000   /* ~512 MiB */
}

SECTIONS {
    /* ─── Entry point ──────────────────────────────────────────────────────
     * Must be at exactly ROM_ADDR (0x8000_0000).  ZisK begins execution
     * at this address.  Keep .text.init separate so the entry vector is
     * always the very first word of the ROM segment.
     */
    .text.init 0x80000000 : {
        KEEP(*(.text.init .text.init.*))
    } > ROM

    /* ─── Remaining code ───────────────────────────────────────────────── */
    .text : {
        *(.text.unlikely .text.*_unlikely .text.unlikely.*)
        *(.text.exit .text.exit.*)
        *(.text.startup .text.startup.*)
        *(.text.hot .text.hot.*)
        *(SORT(.text.sorted.*))
        *(.text .stub .text.* .gnu.linkonce.t.*)
        *(.gnu.warning)
    } > ROM

    .init : { KEEP(*(SORT_NONE(.init))) } > ROM
    .fini : { KEEP(*(SORT_NONE(.fini))) } > ROM
    .plt  : { *(.plt) *(.iplt) } > ROM

    PROVIDE(__etext = .);
    PROVIDE(_etext  = .);
    PROVIDE(etext   = .);

    /* ─── Read-only data ───────────────────────────────────────────────── */
    .rodata : {
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.srodata.cst16) *(.srodata.cst8) *(.srodata.cst4) *(.srodata.cst2)
        *(.srodata .srodata.*)
    } > ROM

    .rodata1 : { *(.rodata1) } > ROM

    /* ─── C++ global constructor / destructor tables ───────────────────── */
    /* Placed in ROM so _start can iterate them before .data is copied.    */
    .preinit_array : {
        PROVIDE_HIDDEN(__preinit_array_start = .);
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN(__preinit_array_end = .);
    } > ROM

    .init_array : {
        PROVIDE_HIDDEN(__init_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP(*(.init_array EXCLUDE_FILE(*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o) .ctors))
        PROVIDE_HIDDEN(__init_array_end = .);
    } > ROM

    .fini_array : {
        PROVIDE_HIDDEN(__fini_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP(*(.fini_array EXCLUDE_FILE(*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o) .dtors))
        PROVIDE_HIDDEN(__fini_array_end = .);
    } > ROM

    .ctors : {
        KEEP(*crtbegin.o(.ctors))  KEEP(*crtbegin?.o(.ctors))
        KEEP(*(EXCLUDE_FILE(*crtend.o *crtend?.o) .ctors))
        KEEP(*(SORT(.ctors.*)))    KEEP(*(.ctors))
    } > ROM

    .dtors : {
        KEEP(*crtbegin.o(.dtors))  KEEP(*crtbegin?.o(.dtors))
        KEEP(*(EXCLUDE_FILE(*crtend.o *crtend?.o) .dtors))
        KEEP(*(SORT(.dtors.*)))    KEEP(*(.dtors))
    } > ROM

    /* ─── Writable data (LMA in ROM, VMA in RAM) ───────────────────────── */
    /* _start copies bytes from __data_load (ROM) to [__data_start, __data_end) (RAM). */
    .data : {
        PROVIDE_HIDDEN(__data_start = .);
        __DATA_BEGIN__ = .;
        *(.data .data.* .gnu.linkonce.d.*)
        SORT(CONSTRUCTORS)
        *(.data1)
    } > RAM AT > ROM

    .sdata : {
        __SDATA_BEGIN__ = .;
        *(.sdata .sdata.* .gnu.linkonce.s.*)
        *(.got.plt) *(.igot.plt) *(.got) *(.igot)
    } > RAM AT > ROM

    PROVIDE_HIDDEN(__data_end  = .);
    PROVIDE_HIDDEN(__data_load = LOADADDR(.data));   /* ROM source for _start copy */

    /* ─── Zero-initialised data ────────────────────────────────────────── */
    . = ALIGN(8);
    __bss_start = .;

    .sbss : {
        *(.dynsbss)
        *(.sbss .sbss.* .gnu.linkonce.sb.*)
        *(.scommon)
    } > RAM

    .bss : {
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
        . = ALIGN(8);
    } > RAM

    . = ALIGN(8);
    __BSS_END__ = .;

    /* RISC-V global pointer: mid-point of small-data region for ±2 KiB reach. */
    __global_pointer$ = MIN(__SDATA_BEGIN__ + 0x800,
                            MAX(__DATA_BEGIN__ + 0x800, __BSS_END__ - 0x800));

    _end = .; PROVIDE(end = .);

    /* ─── Stack ────────────────────────────────────────────────────────── */
    /* 256 KiB guard above BSS.  _start loads sp from _init_stack_top and
     * the stack grows downward.  The heap (_sbrk) begins at _end. */
    . = ALIGN(16);
    . += 0x40000;   /* 256 KiB */
    _init_stack_top = .;

    /* ─── Debug sections (zero VMA, not loaded) ────────────────────────── */
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
    }
}
