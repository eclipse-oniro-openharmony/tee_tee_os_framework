/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: nv
 * Author     : SecurityEngine
 * Create     : 2018/08/15
 */
#include <pal_nv_cfg.h>
#include <common_utils.h>

/* set the module to which the file belongs
 * each .C file needs to be configured
 */
#define BSP_THIS_MODULE               BSP_MODULE_SYS

/**
 * @brief      : check if SMX is supported
 * @param[in]  : smx_e  : sm2/sm3/sm4
 */
err_bsp_t pal_smx_check_support(u32 smx)
{
	UNUSED(smx);
	return BSP_RET_OK;
}

