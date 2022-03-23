/**
 * @file   : pal_types.h
 * @brief  : define types
 *           platform-dependent types is defined in pal_types_plat.h
 *           platform-independent types is defined in pal_types.h
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2018/08/10
 */
#ifndef __PAL_TYPES_H__
#define __PAL_TYPES_H__
#include "pal_types_plat.h"

typedef void *pal_obj_t;

typedef u8                           *pal_cpu_addr_t;
typedef _pal_master_addr_t            pal_master_addr_t;
typedef _symm_param_extend_s          symm_param_extend_s;

#define PAL_FALSE   (0)
#define PAL_TRUE    (1)

#define PAL_ADDR2PTR(addr)    ((pal_cpu_addr_t)PTR(addr))
#define PAL_PTR2MASTER(p)     ((pal_master_addr_t)INTEGER(p))

#endif /* __PAL_TYPES_H__ */

