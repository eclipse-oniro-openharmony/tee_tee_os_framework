/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: This file defines the hieps module driver.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */

#include <sre_task.h>
#include <sre_syscalls_id_ext.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <sre_hwi.h>
#include <secure_gic_common.h>
#include <drv_module.h>
#include <drv_pal.h>
#include <hmdrv_stub.h>
#include <sre_errno.h>
#include <sre_typedef.h>
#include <pthread.h>
#include <securec.h>
#include <hieps_common.h>
#include <hieps_errno.h>
#include <hieps_cdrm_cmd.h>
#include <hieps_power.h>
#ifdef FEATURE_DFT_ENABLE
#include <msptest_interface.h>
#endif
#include "hieps_smc.h"
#include "drv_param_type.h"
#include <register_ops.h>
#include <pal_mem_plat.h>

struct hieps_dev_data_t g_hieps_data;
/* The flag to indicat whether hieps module is ready. */
uint32_t g_hieps_module_ready_flag;

/* Store hieps status. */
static uint32_t g_hieps_status = HIEPS_STATUS_DOWN;

/*
 * @brief      : hieps_set_status : set hieps status.
 *
 * @param[in]  : status : the status to set.
 */
void hieps_set_status(uint32_t status)
{
    if (status == HIEPS_ON) {
        g_hieps_status = HIEPS_STATUS_UP;
    } else if (status == HIEPS_OFF) {
        g_hieps_status = HIEPS_STATUS_DOWN;
    } else {
        tloge("hieps: Invalid status param! status=0x%x\n", status);
        g_hieps_status = HIEPS_STATUS_DOWN;
    }
}

/*
 * @brief      : hieps_get_status : get hieps status.
 *
 * @return     : hieps status.
 */
uint32_t hieps_get_status(void)
{
    return g_hieps_status;
}

/*
 * @brief      : is_support_hieps : To check whether support hieps.
 *
 * @return     : HIEPS_SUPPORT: support, HIEPS_UNSUPPORT : donot support.
 */
uint32_t is_support_hieps(void)
{
    return HIEPS_SUPPORT;
}

/*
 * @brief      : hieps_clear_ready_flag : Clear the ready flag for hieps.
 */
static void hieps_clear_ready_flag(void)
{
    g_hieps_module_ready_flag = ~HIEPS_MODULE_READY;
}

/*
 * @brief      : hieps_set_ready_flag : Set the ready flag for hieps.
 */
static void hieps_set_ready_flag(void)
{
    g_hieps_module_ready_flag = HIEPS_MODULE_READY;
}

/*
 * @brief      : hieps_get_module_ready_flag : get the hieps ready flag.
 *
 * @return     : the status of hieps module: ready or not ready.
 */
uint32_t hieps_get_module_ready_flag(void)
{
    return g_hieps_module_ready_flag;
}

/**
 * @brief      : hieps_system_init : Initialize hieps system data.
 *
 * @return     : HIEPS_OK: initialize successfully, others: initialize failed.
 */
static int32_t hieps_system_init(void)
{
    int32_t ret;

    /* Create a security engine lock. */
    ret = pthread_mutex_init(&g_hieps_data.seceng_lock, NULL);
    if (ret != SRE_OK) {
        tloge("hieps:Create seceng_lock mutex failed!ret=%x\n", ret);
        return ret;
    }

    /* Create a power management lock. */
    ret = pthread_mutex_init(&g_hieps_data.power_lock, NULL);
    if (ret != SRE_OK) {
        tloge("hieps:Create hieps_power_lock mutex failed!ret=%x\n", ret);
        return ret;
    }

    /* Create a hieps smc lock. */
    ret = pthread_mutex_init(&g_hieps_data.smc_lock, NULL);
    if (ret != SRE_OK) {
        tloge("hieps:Create hieps_smc_lock mutex failed!ret=%x\n", ret);
        return ret;
    }

    ret = pal_ddr_mgr_init();
    if (ret != BSP_RET_OK) {
        tloge("pal_ddr_mgr_init fail, ret=%x\n", ret);
        return ret;
    } else {
        ret = HIEPS_OK;
    }

    return ret;
}

/*
 * @brief      : hieps_init : initialize hieps module.
 *
 * @return     : HIEPS_OK: initialize successfully, others: initialize failed.
 */
static int32_t hieps_init(void)
{
    int32_t ret;

    /* Clear hieps modul ready flag before inition. */
    hieps_clear_ready_flag();

    (void)memset_s((void *)&g_hieps_data, sizeof(struct hieps_dev_data_t),
                   0, sizeof(struct hieps_dev_data_t));

    ret = hieps_system_init();
    if (ret != HIEPS_OK) {
        tloge("hieps:Intialize hieps data failed!ret=%x\n", ret);
        return ret;
    }

    /* Set hieps module ready flag after inition successfully. */
    hieps_set_ready_flag();
    tloge("hieps init OK!\n");

    return ret;
}

/*
 * @brief      : hieps_suspend : hieps suspend process.
 *
 * @return     : HIEPS_OK: suspend successfully, HIEPS_ERROR: suspend failed.
 */
static int32_t hieps_suspend(void)
{
    tloge("hieps suspend!\n");
    uint32_t power_status;
    uint32_t ret;

    power_status = hieps_get_power_status();
    if (power_status != HIEPS_POWEROFF_STATUS) {
        hieps_set_tcu_power_status(HIEPS_OFF);

        /* Clear result flag. */
        write32(HIEPS_POWER_RESULT_ADDR, HIEPS_POWER_FAILED);
        ret = hieps_smc_send_process(HIEPS_POWER_OFF_CMD, 0, HIEPS_CMD_END, 0);
        if (ret != HIEPS_OK) {
            tloge("hieps:suspend send smc failed! ret = 0x%x\n", ret);
            return ret;
        }

        ret = read32(HIEPS_POWER_RESULT_ADDR);
        if (ret != HIEPS_POWER_SUCCESS) {
            tloge("hieps: suspend power off failed! ret:0x%x\n", ret);
            return HIEPS_ERROR;
        }
    }
    hieps_clear_ready_flag();
    hieps_clear_power_status();
    hieps_set_status(HIEPS_OFF);

    return HIEPS_OK;
}

/*
 * @brief      : hieps_resume : hieps resume process.
 *
 * @return     : HIEPS_OK: resume successfully, HIEPS_ERROR: resume failed.
 */
static int32_t hieps_resume(void)
{
    int32_t ret = HIEPS_OK;

    /* Set hieps module ready flag after resume successfully. */
    hieps_set_ready_flag();
    tloge("hieps resume!\n");

    return ret;
}

/*
 * @brief      : hieps_syscall : support syscall for hieps module.
 *
 * @param[in]  : swi_id: hieps module id.
 * @param[in]  : params : parameter registers.
 * @param[in]  : permissions: access permission.
 *
 * @return     : 0: successful, -1: failed.
 */
int32_t hieps_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
#ifdef FEATURE_DFT_ENABLE
    uint32_t uwRet = 0;

    if (!params || !params->args) {
        tloge("%s invalid input\n", __func__);
        return -1;
    }
    /* According to ARM AAPCS arguments from 5-> in a function call
     * are stored on the stack, which in this case is pointer by
     * user sp. Our own TrustedCore also push FP and LR on the stack
     * just before SWI, so skip them
     */
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_EPS_CDRM, permissions, HIEPS_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[1], args[2]);
        if (args[4] > 0) {
            ACCESS_CHECK_A64(args[3], args[4]);
        } else {
            tloge("hieps:syscall err!\n");
            return -1;
        }
        ACCESS_READ_RIGHT_CHECK(args[1], args[2]);
        ACCESS_WRITE_RIGHT_CHECK(args[1], args[2]);
        ACCESS_READ_RIGHT_CHECK(args[3], args[4]);
        ACCESS_WRITE_RIGHT_CHECK(args[3], args[4]);

        uwRet = tee_call_hieps_drivers(
                (uint32_t)args[0],
                (char *)(uintptr_t)args[1],
                (uint32_t)args[2],
                (const char *)(uintptr_t)args[3],
                (uint32_t)args[4]);
        args[0] = uwRet;
        SYSCALL_END

        default :
            return -1;
    }
    return 0;
#else
    (void)swi_id;
    (void)params;
    (void)permissions;
    return -1;
#endif
}

/* declare hieps module */
DECLARE_TC_DRV(
    hieps_driver,       /* name */
    0,                  /* reserved1 */
    0,                  /* reserved2 */
    0,                  /* reserved3 */
    TC_DRV_MODULE_INIT, /* priority */
    hieps_init,         /* init */
    NULL,               /* handle */
    hieps_syscall,      /* syscall */
    hieps_suspend,      /* suspend */
    hieps_resume        /* resume */
);
