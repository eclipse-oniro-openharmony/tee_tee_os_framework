/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Describe the link file for 64bits TA
 * Create: 2019-12-03
 */

OUTPUT_FORMAT("elf32-littlearm", "elf32-littlearm", "elf32-littlearm")
OUTPUT_ARCH(arm)

PHDRS
{
    text    PT_LOAD                                         FLAGS (5);
    smee    0x65656d73   AT(smee_start)                     FLAGS (6);
    data    PT_LOAD                                         FLAGS (6);
    relro   0x6474e552                                      FLAGS (4);
    stack   PT_GNU_STACK                                    FLAGS (6);
}

SECTIONS
{
    . = 0x00000000;
    . = ALIGN(0x1000);
    .text : {
        *(.text)           /* .text sections (code) */
        *(.text*)           /* .text sections (code) */
        *(.glue_7)         /* glue arm to thumb code */
        *(.glue_7t)        /* glue thumb to arm code */
     } : text

    . = ALIGN(8);
    .init_array     :
    {
        /* PROVIDE_HIDDEN will cause no __init_array_start and __init_array_end symbol */
        __init_array_start = .;
        KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP (*(.init_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .ctors))
        __init_array_end = .;
    } : text
    .fini_array     :
    {
        PROVIDE_HIDDEN (__fini_array_start = .);
        KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP (*(.fini_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .dtors))
        PROVIDE_HIDDEN (__fini_array_end = .);
    } : text

    . = ALIGN(0x1000);
    ro_data_start = .;
    .rodata(ro_data_start) : AT(ro_data_start) {
        *(.rodata)
        *(.rodata*)
        . = ALIGN(16);
        PROVIDE (__start___llvm_prf_names = .);
        *(__llvm_prf_names)
        PROVIDE (__stop___llvm_prf_names = .);
    } : text

    PROVIDE (__etext = .);
    PROVIDE (_etext = .);
    PROVIDE (etext = .);

    . = ALIGN(0x1000);
    PROVIDE_HIDDEN (smee_start = .);
    .smee : ALIGN(0x1000)
    {
        *(sram_protection_section)
        *(smee* .smee* .*smee)
    } : smee

    . = ALIGN(0x1000);
    data_start = .;
    .data(data_start) : AT(data_start) {
        *(.data)
        *(.data*)
        PROVIDE (__start___llvm_prf_cnts = .);
        *(__llvm_prf_cnts)
        PROVIDE (__stop___llvm_prf_cnts = .);
        PROVIDE (__start___llvm_prf_data = .);
        *(__llvm_prf_data)
        PROVIDE (__stop___llvm_prf_data = .);
        PROVIDE (__start___llvm_prf_vnds = .);
        *(__llvm_prf_vnds);
        PROVIDE (__stop___llvm_prf_vnds = .);
    } : data

    .bss : {
        TA_BSS_START = .;
        *(.bss)
        *(.bss.*)
        TA_BSS_END = .;
    } : data

    .rel.text : {
        *(.rel.text)
    } : data : relro

    .rel.data : {
        *(.rel.data)
    } : data : relro
}
