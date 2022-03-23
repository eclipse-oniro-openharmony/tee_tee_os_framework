#include <autoconf.h>
#include <mmu.h>

IMAGE_BASE_ADDR = (CONFIG_KERNEL_IMG_BASE + BOOT_OFFSET);

PHDRS
{
    interp              PT_INTERP               FLAGS (4);
    text                PT_LOAD                 FLAGS (5);
    rodata              PT_LOAD                 FLAGS (4);
    data                PT_LOAD                 FLAGS (6);
    dynamic             PT_DYNAMIC              FLAGS (6);
    stack               PT_GNU_STACK            FLAGS (6);
    relro               0x6474e552              FLAGS (4);
}

SECTIONS
{
    . = IMAGE_BASE_ADDR;
    _image_base_addr = .;
    .text :
    {
        *(.text.efi.header)
        *(.text.start)
        *(.text.*)
        *(.text)
    } : text

    .rela.dyn :
    {
        *(.rela.init)
        *(.rela.text .rela.text.*)
        *(.rela.rodata .rela.rodata.*)
        *(.rela.data .rela.data.*)
        *(.rela.got)
        *(.rela.bss .rela.bss.*)
    }

    .rodata :
    {
        *(.rodata .rodata.*)
    }

    . = DATA_SEGMENT_ALIGN (4K, 4K);
    .dynamic :
    {
        *(.dynamic)
    } : data : dynamic

    .got :
    {
        *(.got.plt)
        *(.igot.plt)
        *(.got)
        *(.igot)
    } : data

    . = DATA_SEGMENT_RELRO_END (0, .);

    .bss :
    {
        . = ALIGN(8);
        __data_end = .;
        *(.bss .bss.*)
    } : data
    __bss_end = .;
    . = ALIGN(8);

    .stack :
    {
        _abortstack_bottom = .;
        . = . + 4K;
        . = ALIGN(16K);
        _abortstack_top = .;
    } : data

    .data :
    {
        *(.data .data.*)
        . = ALIGN(16);
        _archive_start = .;
        *(.archive_ar)
        _archive_end = .;
    } : data

   _end = .;

    . = DATA_SEGMENT_END (.);

    __init_size = __data_end - IMAGE_BASE_ADDR;
    __init_mem_usage = _end - IMAGE_BASE_ADDR;
    __unzip_size = UNZIP_SIZE;
    /DISCARD/ :
    {
        *(.note.gnu.build-id)
        *(.comment)
    }
}
