/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: interface for bm.
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/10/10
 */
#ifndef __HAL_ENGCTRL_BM_H__
#define __HAL_ENGCTRL_BM_H__
#include <common_define.h>
#include <common_engctrl.h>

u32 hal_engctrl_get_lcs(void);

/* control km key readable */
u32 hal_get_kmdbg(void);

/* control pke key readable */
u32 hal_engctrl_get_umdbg(void);

/* check sm3/4 supported */
u32 hal_get_smx_support(void);

#endif
