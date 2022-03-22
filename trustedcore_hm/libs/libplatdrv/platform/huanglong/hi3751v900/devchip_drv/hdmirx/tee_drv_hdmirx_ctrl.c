/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Implementation of ctrl functions
 * Author: Hisilicon multimedia interface software group
 * Create: 2020/03/09
 */
#include "tee_drv_hdmirx_ctrl.h"
#include "tee_hal_hdmirx_ctrl.h"
#include "tee_hal_hdmirx_comm.h"

hi_bool tee_drv_hdmirx_get_licence(hi_void)
{
    return (hi_bool)tee_hal_hdmirx_ctrl_get_licence();
}

hi_void tee_drv_hdmirx_ctrl_init(hi_void)
{
    hdmirx_hal_reg_init();
}

hi_void tee_drv_hdmirx_crg_init(hi_void)
{
    tee_hal_hdmirx_ctrl_crg_init();
}

hi_void tee_drv_hdmirx_crg_deinit(hi_void)
{
    tee_hal_hdmirx_ctrl_crg_deinit();
}

