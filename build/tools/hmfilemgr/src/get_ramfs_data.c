/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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
