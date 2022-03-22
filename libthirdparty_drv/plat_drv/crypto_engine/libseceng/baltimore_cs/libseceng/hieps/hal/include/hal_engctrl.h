/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: engine control for hardware adapter
 * Author     : m00475438
 * Create     : 2019/08/17
 */
#ifndef __HAL_ENGCTRL_H__
#define __HAL_ENGCTRL_H__
#include <common_define.h>
#include <common_engctrl.h>

err_bsp_t hal_seceng_init(void);

err_bsp_t hal_seceng_selftest(void);

/**
 * @brief      : interface for check smx support by ip
 * @param[in]  : smx ::enum gm_smx
 * @return     : BSP_RET_OK is support, other is unsupport
 */
err_bsp_t hal_seceng_smx_support(u32 smx);

err_bsp_t hal_engctrl_init(void);

/**
 * @brief      : get lcs by engine control
 */
u32 hal_engctrl_get_lcs(void);

/**
 * @brief      : ip clock control
 * @param[in]  : mid    module id
 * @param[in]  : ip_idx ip index
 * @param[in]  : onoff  ::SEC_ON is enable; other is disable
 */
err_bsp_t hal_engctrl_cfg_clock(u32 mid, u32 ip_idx, u32 onoff);

#endif /* end of __HAL_ENGCTRL_H__ */
