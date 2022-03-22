/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#ifndef __HI_TEE_MMZ_H__
#define __HI_TEE_MMZ_H__

#include <stddef.h>
#include <string.h>
#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


/*
\brief Allocate memory block.
\attention \n
N/A
\param[in]  size        The size of the memory block to be allocated.
\param[in]  mmz_name    The name of the memory pool for allocation, should be "SEC-MMZ" currently.
\param[in]  mmb_name    The name of the memory block.
\retval ::non-zero   Success, return the physical address of the block.
\retval ::zero       Fail to allocate memory block.
\see \n
N/A
*/
unsigned long long hi_tee_mmz_new(unsigned long long size, const char *mmz_name, const char *buf_name);

/**
\brief Free the memory block.
\attention \n
N/A
\param[in]  phys_addr    The physical address of the memory block.
\retval ::0   Success.
\retval ::non-zero Fail to free the memory block.
\see \n
N/A
*/
int hi_tee_mmz_delete(unsigned long long phys_addr);

/**
\brief judge if the mem is in sec mmz zone.
\attention \n
N/A
\param[in]  phys_addr    The phys address of the memory block.
\retval ::0   the mem is not in sec mmz zone
\retval ::1   the mem is in sec mmz zone.
\retval ::2   the mem is in sec mmz2 zone.
\retval ::-1   check failed.
\see \n
N/A
*/
int hi_tee_mmz_issmmz(unsigned long long phys_addr);

/**
\brief alloc sec mmz mem and map to cpu/ sec smmu
\attention \n
N/A
\param[in]  size    The size of the memory block to alloc
\param[in]  mmz_name    The name of the memory pool
\param[in]  buf_name    The name of the memory block
\param[out] handle    the handle of the memory block
\retval ::NULL   exec failed
\retval ::!NULL   the cpu address, exec successfully
\see \n
N/A
*/
void *hi_tee_mmz_alloc_and_mapall(unsigned long long size, const char *mmz_name,
                                  const char *buf_name, unsigned long long *handle);

/**
\brief free and unmap cpu/sec smmu.
\attention \n
N/A
\param[in]  virt    The cpu address of the memory block.
\param[in]  handle    The handle of the memory block.
\retval ::0   exec successfully
\retval ::-1   exec failed
\see \n
N/A
*/
int hi_tee_mmz_unmap_and_freeall(void *virt, unsigned long long handle);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __HI_TEE_MEM_H__ */

