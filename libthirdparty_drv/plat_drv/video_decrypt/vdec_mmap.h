/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: added for hm-teeos
 * Author: hanxuanwei
 * Create: 2018-05-21
 */

#ifndef VDEC_MMAP
#define VDEC_MMAP

// drm secure mem
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660)
#define DRM_SECURE_ADDR_BASE 0x60000000UL
#define DRM_SECURE_MEM_SIZE 0x20000000UL

#else
#include "secmem.h"

#endif

typedef struct mem_map_para {
    paddr_t phy_addr;
    unsigned int size;
    unsigned int secure_mode;
    unsigned int cache_mode;
    unsigned int protect_id;
    unsigned int buff_id;
} MEM_Map_Para_S;

typedef struct mem_unmap_para {
    unsigned int vir_addr;
    unsigned int secure_mode;
    unsigned int size;
    unsigned int protect_id;
    unsigned int buff_id;
} MEM_UnMap_Para_S;

int SECURE_TEE_Mmap(struct mem_map_para *memPara, unsigned int *virtAddr);
int SECURE_TEE_Unmap(const struct mem_unmap_para *memPara);
int SECURE_ISSecureMemory(paddr_t addr, unsigned int size, unsigned int protectId);

#endif

