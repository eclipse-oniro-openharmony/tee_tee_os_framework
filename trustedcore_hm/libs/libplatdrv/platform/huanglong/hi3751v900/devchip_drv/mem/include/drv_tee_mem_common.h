/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Version: Initial Draft
 * Create: 2009-12-16
 */

#ifndef _DRV_TEE_MEM_COMMON_H
#define _DRV_TEE_MEM_COMMON_H

#include "hi_tee_drv_os_hal.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#define pr_err(fmt...)           hi_tee_drv_hal_printf(fmt)

#define IS_SECURE 1
#define NO_SECURE 0


typedef enum {
    SEC_MMZ = 0,
    NORMAL_MMZ,
    SEC_MMZ2,
}tee_mmz_tyep;

typedef enum {
    NORMAL_MMZ_TYPE = 0,
    SEC_MMZ_TYPE,
    SEC_MMZ2_TYPE,
    SEC_SMMU_TYPE,
    SEC_SMMU_MMZ_TYPE,
}tee_mem_type;

typedef struct {
    void* start_vir_addr;
    unsigned long start_phy_addr;
    unsigned long size;
} tee_mmz_buffer;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
