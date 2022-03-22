/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: drv map paddr defined in pal.c
 * Create: 2019-11-08
 */
#ifndef PLATDRV_TASK_MAP_H
#define PLATDRV_TASK_MAP_H
#include <stdint.h>
#include <mem_page_ops.h>

int32_t drv_map_paddr_to_task(paddr_t phy_addr, uint32_t size, uint32_t *virt_addr,
                              uint32_t secure_mode, uint32_t cache_mode);

int32_t drv_map_paddr_to_task_handle(paddr_t phy_addr, uint32_t size, uint64_t *virt_addr, uint32_t secure_mode,
                                     uint32_t cache_mode);

int32_t drv_unmap_from_task_handle(uint64_t virt_addr, uint32_t size);


int32_t drv_unmap_from_task(uint32_t virt_addr, uint32_t size);


#endif /* PLATDRV_TASK_MAP_H */
