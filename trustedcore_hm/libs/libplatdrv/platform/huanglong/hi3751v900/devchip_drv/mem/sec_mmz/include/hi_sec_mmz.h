/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#ifndef __HI_SEC_MMZ_H__
#define __HI_SEC_MMZ_H__

#include "hi_tee_drv_os_hal.h"
#include "hi_list.h"
#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


#ifdef CFG_HI_TEE_SEC_MMZ_SUPPORT
/**
\brief Allocate memory block.
CNcomment:\brief
\attention \n
N/A
\param[in]  zone_name   The name of the memory pool to allocate from.
\param[in]  buf_name        The name of the memory block.
\param[in]  size        The size of the memory block to be allocated.
\retval ::   Return the phisical address of the block if succeed, else return 0.
\see \n
N/A
*/
unsigned long drv_tee_mmz_new(const char *zone_name, const char *buf_name, int size);

/**
\brief Delete memory block.
CNcomment:\brief
\attention \n
N/A
\param[in]  phys_addr        The address of the memory block to be deleted.
\see \n
N/A
*/
unsigned long drv_tee_mmz_delete(unsigned long phys_addr);

/**
\brief Remap memory block.
CNcomment:\brief
\attention \n
N/A
\param[in]  phys_addr        The phys address of the memory block to be remaped.
\param[in]  cached         The cache attr of the buffer.
\retval ::Return the virtual address of the block.
\see \n
N/A
*/
void *drv_tee_mmz_map(unsigned long phys_addr, bool cached);

/**
\brief Unmap memory block.
CNcomment:\brief
\attention \n
N/A
\param[in]  virt_addr        The virtual address of the memory block to be unmaped.
\retval ::0        Success.
\retval ::-1       Calling this API fails.
\see \n
N/A
*/
int drv_tee_mmz_unmap(const void *virt_addr);

/**
\brief flush mmb data cache
CNcomment:
\attention \n
\param[in]  virt        The virt address of the memory block to be remaped.
\param[in]  size
N/A
*/
int hi_tee_drv_mem_flush(void *virt, size_t size);

/**
\brief judge the mem whther in sec mmz zone or not
CNcomment:\brief
\attention \n
N/A
\param[in]  phys_addr       The phys address of the memory block.
\retval ::0    not in sec mmz zone.
\retval ::1    in sec mmz zone.
\retval ::2    in sec mmz2 zone.
\see \n
N/A
*/
int drv_tee_mmz_is_sec(unsigned long phys_addr);

#else

unsigned long drv_tee_mmz_new(const char *zone_name, const char *buf_name, int size)
{
    return 0;
}

unsigned long drv_tee_mmz_delete(unsigned long phys_addr)
{
    return 0;
}

void *drv_tee_mmz_map(unsigned long phys_addr, bool cached)
{
    return NULL;
}

int drv_tee_mmz_unmap(const void *virt_addr)
{
    return 0;
}

int drv_tee_mem_flush(void *virt, size_t size)
{
    return 0;
}

int drv_tee_mmz_is_sec(unsigned long phys_addr)
{
    return 0;
}


#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
