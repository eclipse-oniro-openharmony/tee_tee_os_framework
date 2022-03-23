/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: function used to get load elf info
 * Create: 2021-07-13
 */
#include "get_elf_info.h"
#include <stdio.h>
#include <elf.h>
#include <tee_log.h>

int32_t get_elf_class(const char *ehdr, uint32_t ehdr_size)
{
    if ((ehdr == NULL) || (ehdr_size < EI_NIDENT)) {
        tloge("elf header or size:%u is invalid\n", ehdr_size);
        return -1;
    }

    if (ehdr[EI_MAG0] != (char)0x7f ||
        ehdr[EI_MAG1] != 'E' ||
        ehdr[EI_MAG2] != 'L' ||
        ehdr[EI_MAG3] != 'F') {
            tloge("invalid elf format, magic mismatch\n");
            return -1;
    }

    return (int32_t)ehdr[EI_CLASS];
}

int32_t get_elf_type(const char *ehdr, uint32_t ehdr_size, int32_t elf_class)
{
    if (ehdr == NULL) {
        tloge("invalid ehdr\n");
        return -1;
    }

    if (elf_class == ELFCLASS32) {
        if (ehdr_size < sizeof(Elf32_Ehdr)) {
            tloge("invalid ehdr size:%u\n", ehdr_size);
            return -1;
        }

        return ((Elf32_Ehdr *)ehdr)->e_type;
    }

    if (elf_class == ELFCLASS64) {
        if (ehdr_size < sizeof(Elf64_Ehdr)) {
            tloge("invalid 64 ehdr size:%u\n", ehdr_size);
            return -1;
        }

        return ((Elf64_Ehdr *)ehdr)->e_type;
    }

    return -1;
}
