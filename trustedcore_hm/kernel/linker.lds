

#include <config.h>

ENTRY(_start)

#ifndef CONFIG_KERNEL_ASLR
KERNEL_BASE = KERNEL_IMG_BASE + KERNEL_LOAD_OFFSET;
#endif

PHDRS
{
    text                PT_LOAD                 FLAGS (5);
    rodata              PT_LOAD                 FLAGS (4);
    data                PT_LOAD                 FLAGS (6);
    dynamic             PT_DYNAMIC              FLAGS (6);
    boot_text           PT_LOAD                 FLAGS (5);
    boot_rodata         PT_LOAD                 FLAGS (4);
    boot_data           PT_LOAD                 FLAGS (6);
    stack               PT_GNU_STACK            FLAGS (6);
    relro               0x6474e552              FLAGS (4);
}

SECTIONS
{
#ifndef CONFIG_KERNEL_ASLR
    . = KERNEL_BASE;
#endif

    .text :
    {
        *(.vectors)

        /* Fastpath code */
        *(.vectors.fastpath_call)
        *(.vectors.fastpath_reply_recv)
        *(.vectors.text)

        /* Anything else that should be in the vectors page. */
        *(.vectors.*)

        /* Hopefully all that fits into 4K! */

        /* Standard kernel */
        *(.text)
#ifdef CONFIG_FAST_DUMPSTACK
        __syminfo_get_start = .;
        *(.syminfo)
        __syminfo_get_end = .;
#endif
    } : text

#ifdef CONFIG_AARCH32_SUSPEND_RESUME
    . = ALIGN(0x2000);
    g_pmsr_start = .;
    .pmsr : AT(g_pmsr_start) {
        *(.pmsr)
    }
#endif

    . = ALIGN(4K);
    .rodata :
    {
        *(.rodata)
        *(.rodata.*)
    } : rodata
    .got :
    {
        *(.got.plt)
        *(.igot.plt)
        *(.got)
        *(.igot)
    } : rodata
    .dynamic :
    {
        *(.dynamic)
    } : rodata : dynamic
    . = DATA_SEGMENT_ALIGN (4K, 4K);
    . = ALIGN(4K);

    .datarelro :
    {
        *(.data.rel.ro)
        *(.data.rel.ro.*)
    } : data : relro

    . = DATA_SEGMENT_RELRO_END (0, .);
    . = ALIGN(4K);

    .data :
    {
        *(.data)
    } : data

    .bss :
    {
        *(.bss)

        /* large data such as the globals frame and global PD */
        *(.bss.aligned)
    } : data

    . = DATA_SEGMENT_END (.);

    . = ALIGN(4K);
    ki_boot_start = .;

    .boot.text . :
    {
        *(.boot.text)
    } : boot_text

    . = ALIGN(4K);
    .boot.rodata . :
    {
        *(.boot.rodata)
    } : boot_rodata

    . = ALIGN(4K);
    .boot.data . :
    {
        *(.boot.data)
    } : boot_data

    . = ALIGN(4K);
    ki_boot_end = .;

    ki_end = .;

    /DISCARD/ :
    {
        *(.note.gnu.build-id)
        *(.comment)
#ifndef CONFIG_KERNEL_ASLR
        *(.rela.*)
        *(.rel.*)
#endif
        *(.dynsym)
        *(.dynstr)
    }
}
