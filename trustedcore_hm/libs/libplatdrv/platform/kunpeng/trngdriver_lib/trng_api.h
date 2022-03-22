/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: kunpeng920 TRNG define
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
 */
#ifndef PLATDRV_TRNG_API_H
#define PLATDRV_TRNG_API_H

#include <plat_cfg.h>
#include <stdint.h>

#define TRNG_OUTREGISTER_NUM  0x04
#define WORD_SIZE 4
#define MAX_OFFSET 3

#define trng_write32(addr, val)  ((*(volatile uint32_t *)(uintptr_t)(addr)) = (val))
#define trng_read32(addr)        (*(volatile uint32_t *)(uintptr_t)(addr))

int32_t trng_get_random(uint8_t *trng_addr, uint32_t length);
uint32_t read_rng_value(uint32_t offset);
uint32_t read_entropy_value(uint32_t offset);
#endif
