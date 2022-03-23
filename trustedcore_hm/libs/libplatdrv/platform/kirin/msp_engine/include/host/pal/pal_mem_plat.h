/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.
 * Description: define types
 * Create     : 2018/08/10
 */
#ifndef __PAL_MEM_PLAT_H__
#define __PAL_MEM_PLAT_H__
#include <pal_types.h>
#include <pal_errno.h>
err_bsp_t pal_ddr_mgr_init(void);

/* return size of symm workspace */
u32 pal_get_symm_workspace(u32 id, u64 *va, u64 *pa);

#endif /* __PAL_MEM_PLAT_H__ */
