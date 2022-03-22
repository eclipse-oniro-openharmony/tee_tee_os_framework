/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: define types
 *              platform-dependent types is defined in pal_types_plat.h
 *              platform-independent types is defined in pal_types.h
 * Create     : 2018/08/10
 */

#ifndef __PAL_TYPES_PLAT_H__
#define __PAL_TYPES_PLAT_H__

#ifndef _SRE_TYPEDEF_H
typedef signed char             s8;
typedef unsigned char           u8;
typedef short                   s16;
typedef unsigned short          u16;
typedef int                     s32;
typedef unsigned int            u32;
typedef long long               s64;
typedef unsigned long long      u64;
#endif /* _SRE_TYPEDEF_H */

typedef unsigned int            BOOL;

typedef s32                     err_bsp_t;

#ifndef INIT_TEXT
#define INIT_TEXT
#endif /* INIT_TEXT */

/* master add support 36bit address */
#define PAL_MASTER_ADDR_WIDTH   36
/* typedef u64 _pal_master_addr_t; */
typedef void                   *_pal_master_addr_t;

/* for plaintext copy */
typedef struct {
	u32                     plaintext_en;
} _symm_param_extend_s;

#endif /*__PAL_TYPES_PLAT_H__*/
