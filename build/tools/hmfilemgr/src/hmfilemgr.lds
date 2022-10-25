/*
 * Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
 */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_FORMAT(aarch64)
ENTRY(_hm_start)
PHDRS
{
    phdr    PT_PHDR PHDRS   AT (0x400000)   FLAGS (4);
    rodata  PT_LOAD FILEHDR PHDRS           FLAGS (4);
    text    PT_LOAD                         FLAGS (1);
    data    PT_LOAD                         FLAGS (6);
}
SECTIONS
{
    . = 0x400000 + SIZEOF_HEADERS;
    .rodata     : { *(.rodata .rodata.*) } : rodata
    . = ALIGN(0x1000);
    .text       : { *(.text .text.*) } : text
    .init_array     :
    {
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP (*(.init_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .ctors))
        PROVIDE_HIDDEN (__init_array_end = .);
    }
    .fini_array     :
    {
        PROVIDE_HIDDEN (__fini_array_start = .);
        KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP (*(.fini_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .dtors))
        PROVIDE_HIDDEN (__fini_array_end = .);
    }
    . = ALIGN(0x1000);
    .data       : { *(.data .data.*) } : data
    .bss        : { *(.bss  .bss.* ) } : data
}
