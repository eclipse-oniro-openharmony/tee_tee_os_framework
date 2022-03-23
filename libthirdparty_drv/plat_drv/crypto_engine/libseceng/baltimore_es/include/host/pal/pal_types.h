/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: define types for pal
 * Author     : l00370476, liuchong13@huawei.com
 * Create     : 2018/08/10
 */
#ifndef __PAL_TYPES_H__
#define __PAL_TYPES_H__
#include "pal_types_plat.h"

typedef void *pal_handle_t;
typedef err_bsp_t (*pal_callback_t)(pal_handle_t arg);

typedef u8                 *pal_cpu_addr_t;
typedef _pal_master_addr_t pal_master_addr_t;
typedef union _pal_addr_u {
	pal_cpu_addr_t cpu_addr;
	pal_master_addr_t master_addr;
} pal_addr_t;

#define PAL_FALSE   0
#define PAL_TRUE    1

#define PAL_ADDR2PTR(addr)    ((pal_cpu_addr_t)PTR(addr))
#define PAL_PTR2MASTER(p)     ((pal_master_addr_t)INTEGER(p))

#endif /* __PAL_TYPES_H__ */

