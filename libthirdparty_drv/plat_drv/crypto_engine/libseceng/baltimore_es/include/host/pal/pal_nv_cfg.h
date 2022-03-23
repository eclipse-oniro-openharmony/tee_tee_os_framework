/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: interface of reading efuse
 * Author     : l00370476, liuchong13@huawei.com
 * Create     : 2018/08/13
 */
#ifndef __PAL_NV_CFG_H__
#define __PAL_NV_CFG_H__
#include <common_define.h>
#include <common_engctrl.h>
#include <pal_nv_cfg_plat.h>

err_bsp_t pal_smx_check_support(u32 smx);
void pal_smx_cfg_support(u32 psmx);

#endif /* __PAL_NV_CFG_H__ */
