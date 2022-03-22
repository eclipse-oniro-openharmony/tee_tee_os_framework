/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: 平台相关功能头文件
 * Author: o00302765
 * Create: 2019-10-22
 */

#ifndef __HI_SEC_COMMON_H__
#define __HI_SEC_COMMON_H__

#include <stdint.h>
#include "hi_typedef.h"
#include "hi_errdef.h"
#include "libhwsecurec/securec.h"

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

hi_void hi_printk(const char *fmt, ...);
hi_void hi_sdk_l0_write_reg(hi_uint32 addr, hi_uint32 *var);
hi_void hi_sdk_l0_read_reg(hi_uint32 addr, hi_uint32 *var);
hi_void hi_udelay(hi_uint32 nus);

uintptr_t hi_sec_get_phyaddr(hi_uchar8 *buf, hi_uint32 buflen, hi_uint32 dir);
hi_void hi_sec_release_phyaddr(uintptr_t phyaddr, hi_uint32 buflen, hi_uint32 dir);
hi_void *hi_sec_alloc_phyaddr(hi_uint32 size, uintptr_t *phyaddr);
hi_void hi_sec_free_phyaddr(hi_uint32 size, hi_void *buf, uintptr_t phyaddr);
hi_void hi_sec_dsb(hi_void);

hi_void *hi_sec_dma_malloc(hi_uint32 size);
hi_void hi_sec_dma_free(hi_void *addr);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_SEC_COMMON_H__ */
