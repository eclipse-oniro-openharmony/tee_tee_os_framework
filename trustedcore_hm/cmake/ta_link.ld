/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Describe the link file for 32 bits TA
 * Create: 2019-12-03
 */

OUTPUT_FORMAT("elf32-littlearm", "elf32-littlearm", "elf32-littlearm")
OUTPUT_ARCH(arm)

SECTIONS
{
    . = 0x00000000;

    . = ALIGN(0x1000);
    .text : {
        *(.text)           /* .text sections (code) */
        *(.text*)           /* .text sections (code) */
        *(.glue_7)         /* glue arm to thumb code */
        *(.glue_7t)        /* glue thumb to arm code */
     }

    . = ALIGN(8);
    .init_array     :
    {
        /* PROVIDE_HIDDEN will cause no __init_array_start and __init_array_end symbol */
        __init_array_start = .;
        KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP (*(.init_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .ctors))
        __init_array_end = .;
    }
    .fini_array     :
    {
        PROVIDE_HIDDEN (__fini_array_start = .);
        KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP (*(.fini_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .dtors))
        PROVIDE_HIDDEN (__fini_array_end = .);
    }

    . = ALIGN(0x1000);
    ro_data_start = .;
    .rodata(ro_data_start) : AT(ro_data_start) {
        *(.rodata)
        *(.rodata*)
    }

    . = ALIGN(0x1000);
    data_start = .;
    .data(data_start) : AT(data_start) {
        *(.data)
        *(.data*)
        *(.init_array*)
    }

    .bss : {
        TA_BSS_START = .;
        *(.bss)
        *(.bss.*)
        TA_BSS_END = .;
    }

    .rel.text : {
        *(.rel.text)
    }

    .rel.data : {
        *(.rel.data)
    }
}
