/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: tee drv npu function impl
 * Author: SDK
 * Create: 2020-03-02
 * History:
 */

#include "hi_type_dev.h"
#include "tee_drv_npu_func.h"
#include "tee_drv_npu_define.h"
#include "tee_drv_npu_utils.h"
#include "tee_drv_ioctl_npu.h"
#include "tee_drv_os_hal.h"
#include "tee_drv_npu_pm.h"
#include "tee_drv_npu_test_hwts.h"

static tee_npu_mgmt *g_tee_npu_mgmt_ptr = HI_NULL;

#define NPU_REGS_BASE         0x00C00000

static tee_npu_mgmt g_tee_npu_mgmt = {
    .io_base = NPU_REGS_BASE,
    .npu_ioctl_entry      = HI_NULL,
};

static npu_ioctl_entry g_npu_func_entry_map[] = {
    { NPU_TEE_IOCTL_GLB_INIT, tee_drv_npu_init },
    { NPU_TEE_IOCTL_GLB_DEINIT, tee_drv_npu_deinit },
    { NPU_TEE_IOCTL_TEST_HWTS, tee_drv_npu_test_hwts },
};

tee_npu_mgmt *get_npu_mgmt(hi_void)
{
    if (g_tee_npu_mgmt_ptr == HI_NULL) {
        if (npu_drv_mod_init() != HI_SUCCESS) {
            hi_log_err("npu_drv_mod_init failed!\n");
        }
        g_tee_npu_mgmt_ptr = &g_tee_npu_mgmt;
    }

    return g_tee_npu_mgmt_ptr;
}

hi_s32 npu_drv_mod_init(hi_void)
{
    TEE_NPU_ENTER();

    if (g_tee_npu_mgmt_ptr != HI_NULL) {
        hi_log_dbg("tee npu already init!\n");
        goto out;
    }

    npu_drv_power_on();

    /* init the npu ioctl entry */
    g_tee_npu_mgmt.npu_ioctl_entry = g_npu_func_entry_map;

    g_tee_npu_mgmt_ptr = &g_tee_npu_mgmt;

out:
    TEE_NPU_EXIT();

    return HI_SUCCESS;
}

hi_s32 npu_drv_mod_exit(hi_void)
{
    TEE_NPU_ENTER();

    hisi_npu_power_off();
    g_tee_npu_mgmt_ptr = HI_NULL;

    TEE_NPU_EXIT();

    return HI_SUCCESS;
}


hi_s32 tee_drv_npu_init(hi_void *argp)
{
    NPU_NULL_POINTER_RETURN(argp);

    return npu_drv_mod_init();
}

hi_s32 tee_drv_npu_deinit(hi_void *argp)
{
    NPU_NULL_POINTER_RETURN(argp);

    return npu_drv_mod_exit();
}

hi_s32 tee_drv_npu_test_hwts(hi_void *argp)
{
    NPU_NULL_POINTER_RETURN(argp);

    tee_drv_npu_test_hwts_impl();

    return 0;
}

