/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declare get load elf info
 * Create: 2021-07-13
 */
#ifndef LIBSPAWN_COMMON_INCLUDE_GET_ELF_INFO_H
#define LIBSPAWN_COMMON_INCLUDE_GET_ELF_INFO_H

#include <stdio.h>
#include <elf.h>

#define ELF_NOT_SUPPORT (-1)
#define ELF_NATIVE      0
#define ELF_TALDR       1
#define ELF_TARUNNER    2
#define ELF_TARUNNER_A32 3

#define EH_SIZE sizeof(Elf64_Ehdr)

int32_t get_elf_class(const char *ehdr, uint32_t ehdr_size);
int32_t get_elf_type(const char *ehdr, uint32_t ehdr_size, int32_t elf_class);

#endif
