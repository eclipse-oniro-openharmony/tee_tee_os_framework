/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: Procedure for reading ramfs data (for AArch64)
 * Create: 2018-05-08
 */
#include "get_ramfs_data.h"

#define __str_append(str) #str
#define str_append(str)   __str_append(str)

void *get_ramfs_data(size_t *ramfs_size)
{
    if (!ramfs_size)
        return NULL;
#ifdef CONFIG_ARCH_AARCH64
    __asm__ __volatile__(" .pushsection .rodata.get_ramfs_data, \"a\", @progbits\n"
        "    .balign    4096\n"
        "    .global    g_ramfs_data\n"
        "g_ramfs_data:\n"
        "    .incbin \"" str_append(BOOTFS_IMG) "\"\n"
        "    .global    g_ramfs_size\n"
        "g_ramfs_size:\n"
        "    .word    . - g_ramfs_data\n"
        "    .popsection\n");
#else
    __asm__ __volatile__(" .pushsection .rodata.get_ramfs_data, \"a\"\n"
        "	.balign	4096\n"
        "	.global	g_ramfs_data\n"
        "g_ramfs_data:\n"
        "	.incbin \"" str_append(BOOTFS_IMG) "\"\n"
        "	.global	g_ramfs_size\n"
        "g_ramfs_size:\n"
        "	.word	. - g_ramfs_data\n"
        "	.popsection\n");
#endif
    *ramfs_size = g_ramfs_size;
    return g_ramfs_data;
}
