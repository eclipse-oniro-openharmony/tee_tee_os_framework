/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mtk driver framework header file
 * Author: HeYanhong heyanhong2@huawei.com
 * Create: 2020-08-19
 */
#ifndef DRV_PAL_DRV_FWK_H
#define DRV_PAL_DRV_FWK_H

#include <stddef.h>
#include "drv_defs.h"

#define MSEE_MAP_READABLE            (1U << 0) /* read access attribute */
#define MSEE_MAP_WRITABLE            (1U << 1) /* write access attribute */
#define MSEE_MAP_EXECUTABLE          (1U << 2) /* program execution attribute */
#define MSEE_MAP_UNCACHED            (1U << 3) /* uncached memory access attribute */
#define MSEE_MAP_IO                  (1U << 4) /* device memory attribute */
/* non-secure attribute, used only to map client task buffers using msee_map_user */
#define MSEE_MAP_ALLOW_NONSECURE     (1U << 7)
#define MSEE_MAP_HARDWARE            (MSEE_MAP_READABLE | MSEE_MAP_WRITABLE | MSEE_MAP_IO)
#define MSEE_MAP_USER_DEFAULT        (MSEE_MAP_READABLE | MSEE_MAP_WRITABLE | MSEE_MAP_ALLOW_NONSECURE)
void msee_clean_dcache_range(uintptr_t addr, size_t size);
void msee_clean_invalidate_dcache_range(uintptr_t addr, size_t size);
uint32_t msee_map_user(void **to, const void *from, size_t size, uint32_t flags);
uint32_t msee_unmap_user(const void *to, uint32_t size);

uint32_t msee_mmap_region(uint64_t pa, void **va, size_t size, uint32_t flags);
uint32_t msee_unmmap_region(const void *va, size_t size);
void *msee_malloc(size_t size);
void msee_free(void *buf);

/* Interrupt API of driver framework */
#define MSEE_INTR_MODE_MASK_TRIGGER      (1U<<0)
#define MSEE_INTR_MODE_TRIGGER_LEVEL     MSEE_INTR_MODE_MASK_TRIGGER
#define MSEE_INTR_MODE_TRIGGER_EDGE      0
#define MSEE_INTR_MODE_MASK_CONDITION    (1U<<1)
#define MSEE_INTR_MODE_CONDITION_FALLING MSEE_INTR_MODE_MASK_CONDITION
#define MSEE_INTR_MODE_CONDITION_LOW     MSEE_INTR_MODE_MASK_CONDITION
#define MSEE_INTR_MODE_CONDITION_RISING  0
#define MSEE_INTR_MODE_CONDITION_HIGH    0
#define MSEE_INTR_MODE_RAISING_EDGE      (MSEE_INTR_MODE_TRIGGER_EDGE | MSEE_INTR_MODE_CONDITION_RISING)
#define MSEE_INTR_MODE_FALLING_EDGE      (MSEE_INTR_MODE_TRIGGER_EDGE | MSEE_INTR_MODE_CONDITION_FALLING)
#define MSEE_INTR_MODE_LOW_LEVEL         (MSEE_INTR_MODE_TRIGGER_LEVEL | MSEE_INTR_MODE_CONDITION_LOW)
#define MSEE_INTR_MODE_HIGH_LEVEL        (MSEE_INTR_MODE_TRIGGER_LEVEL | MSEE_INTR_MODE_CONDITION_HIGH)

enum msee_irq_status {
    MSEE_IRQ_TIMEOUT = -1,
    MSEE_IRQ_FAIL = -2,
    MSEE_IRQ_MAX_ERROR = 0xFFFFFFFF,
};

typedef int32_t (*msee_irq_handler_t)(int32_t, void *);
uint32_t msee_request_irq(uint32_t irq, msee_irq_handler_t handler, size_t flags, uint32_t timeout_ms, void *data);
void msee_free_irq(uint32_t irq);
uint32_t msee_wait_for_irq_complete(uint32_t irq);

/* Time API of driver framework */
struct msee_time {
    uint32_t s;
    uint32_t ms;
};

typedef struct msee_time msee_time_t;
void msee_get_system_time(struct msee_time *time);

/* SMC Call API */
int32_t msee_smc_call(uint32_t smc_nr, uint32_t args0, uint32_t args1,
                      uint32_t args2, uint32_t *smc_ret);

#endif

