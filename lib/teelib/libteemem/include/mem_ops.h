/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: memory operation that not be exported
 * Create: 2019-11-08
 */
#ifndef LIBTEEMEM_MEM_OPS_H
#define LIBTEEMEM_MEM_OPS_H
#include <stdint.h>
#include <mem_page_ops.h>
#include <mem_mode.h> /* cache_mode_type */

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

/* old macro definition, should delete */
#define OS_MEM_DEFAULT_PTNUM  2
#define OS_MEM_DEFAULT_FSC_PT 0
#define OS_MID_SYS 0x0
#define OS_MID_TSK 0x8
#define OS_MID_MSG 0xd
#define OS_MID_TIMER 0x2e

enum os_mem_align_e {
    MEM_ADDR_ALIGN_004  = 4,    /* 4 Bytes */
    MEM_ADDR_ALIGN_008  = 8,    /* 8 Bytes */
    MEM_ADDR_ALIGN_016  = 16,   /* 16 Bytes */
    MEM_ADDR_ALIGN_032  = 32,   /* 32 Bytes */
    MEM_ADDR_ALIGN_064  = 64,   /* 64 Bytes */
    MEM_ADDR_ALIGN_128  = 128,  /* 128 Bytes */
    MEM_ADDR_ALIGN_256  = 256,  /* 256 Bytes */
    MEM_ADDR_ALIGN_1024 = 1024, /* 1024 Bytes */
    MEM_ADDR_ALIGN_4096 = 4096, /* 4096 Bytes */
    MEM_ADDR_BUTT               /* invalid */
};

struct mem_type {
    secure_mode_type secure_mode;
    cache_mode_type cache_mode;
};

/* get physical memory address of input virtual address */
paddr_t virt_mem_to_phys(uintptr_t v_addr);

/* map non_secure memory to TEE, can set cache_mode and secure_mode */
int32_t task_map_phy_mem_type(uint32_t task_id, paddr_t phy_addr, uint32_t size, uint64_t *virt_addr,
                              struct mem_type *mode_type);

int32_t task_map_phy_mem_type_ex(uint32_t task_id, paddr_t phy_addr, uint32_t size, uint64_t *virt_addr,
                                 const struct mem_type *mode_type, map_type type);
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif /* LIBTEEMEM_MEM_OPS_H */
