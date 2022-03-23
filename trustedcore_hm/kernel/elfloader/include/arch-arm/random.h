/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader random API declares
 * Create: 2020-12
 */
#ifndef ELFLOADER_RANDOM_H
#define ELFLOADER_RANDOM_H
#include <stdint.h>

#define TEEOS_SHAREDMEM_LENGTH           0x1000
#define TEEOS_SHAREDMEM_OFFSET_COLORLOCK 0x0A00
#define TEEOS_SHAREDMEM_MODULE_SIZE_512  512
#define RD_RETRY_LIMIT                   10

#define rand_read32(addr) (*(volatile uint32_t *)(uintptr_t)(addr))

#define TEEOS_RANDOM_SEED_SIZE           sizeof(uint64_t)

uint64_t rand_get(uint32_t seed);
void rand_clear(void);

#endif
