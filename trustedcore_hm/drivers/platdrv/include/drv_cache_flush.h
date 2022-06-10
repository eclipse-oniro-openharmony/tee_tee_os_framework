/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: flush cache operation defined in platdrv pal-dma.c
 * Create: 2019-11-08
 */
#ifndef PLATDRV_DRV_CACHE_FLUSH_H
#define PLATDRV_DRV_CACHE_FLUSH_H
#include <stdint.h>

/* recommended APIs, because of 64bit input args */
void dma_flush_range(uint64_t start, uint64_t end);
void dma_inv_range(uint64_t start, uint64_t end);
void dma_clean_range(uint64_t start, uint64_t end);
void dma_map_area(uint64_t start, uint64_t size, int32_t dir);
void dma_unmap_area(uint64_t start, uint64_t size, int32_t dir);


void v7_dma_inv_range(unsigned long start, unsigned long end);
void v7_dma_flush_range(unsigned long start, unsigned long end);

#endif /* PLATDRV_DRV_CACHE_FLUSH_H */
