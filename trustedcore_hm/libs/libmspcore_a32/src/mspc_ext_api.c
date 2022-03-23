/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Driver for msp core extend api.
 * Author : w00371137
 * Create: 2020/02/29
 */

#include "mspc_ext_api.h"
#include "msp_service_status.h"
#include "sre_syscalls_ext.h"
#include "time.h"
#include "timer_export.h"
#include "hisi_mspc.h"

#define UNUSED(x) ((void)(x))

#define MSPC_OK              0x5A5A
#define MSPC_ERROR           0xA5A5

#define SECFLASH_ERR_STATUS_SW       0x6900
#define SECFLASH_ERR_OPERATION_SW    0x6920
#define SECFLASH_ERR_TDS_SW          0x69F0
#define SECFLASH_ERR_MASK            0xFFF0

/* TEE mspc wait ready timeout. */
#define MSPC_ERR_UNREADY             0xA4010002
/* TEE mspc wait apdu timeout. */
#define MSPC_ERR_TIMEOUT             0xA4020002
/* TEE mspc receive reset when wait apdu. */
#define MSPC_ERR_RESET               0xA4020016
/* ATF wait IPC timeout when power on mspc. */
#define MSPC_ERR_POWER_TIMEOUT       0xA3040016
/* ATF send IPC failed when power on mspc. */
#define MSPC_ERR_POWER_FAILED        0xA3020030

static const uint32_t g_mspc_hardware_error[] = {
    MSPC_ERR_UNREADY, MSPC_ERR_TIMEOUT, MSPC_ERR_RESET,
    MSPC_ERR_POWER_TIMEOUT, MSPC_ERR_POWER_FAILED,
};

#define MSPC_WAIT_FAC_MODE_ENTER_DELAY_MS    10 /* ms */
#define MSPC_FAC_MODE_ENTER_TIMEOUT          200 /* 200 * 10ms = 2s */

/*
 * @brief      : TEE_EXT_MSPIsAvailable : Check whether msp core is exist.
 *
 * @param[in]  : status : The status of msp core.
 *               MSPC_EXIST_MAGIC :   msp core is exist.
 *               MSPC_NOT_AVAILABLE_MAGIC : msp core is absence.
 *
 * @return     : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_MSPIsAvailable(uint32_t *status)
{
    if (!status) {
        tloge("%s: Invalid param!\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

#ifdef CONFIG_HISI_MSPC
    *status = MSPC_EXIST_MAGIC;
#else

    *status = MSPC_NOT_AVAILABLE_MAGIC;
#endif

    return TEE_SUCCESS;
}

/*
 * @brief      : TEE_EXT_MSPServiceIsAvailable : Check whether msp service is available.
 *
 * @param[in]  : serviceID: the ID of the service which is supported in MSP.
                 isAvailable: The available status of msp services.
 *               MSP_SERVICE_IS_AVAILABLE_MAGIC:   msp service is available.
 *               MSP_SERVICE_IS_UNAVAILABLE_MAGIC: msp service is unavailable.
 *
 * @return     : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_MSPServiceIsAvailable(uint32_t serviceID, uint32_t *isAvailable)
{
    TEE_Result result;
    uint32_t hw_status = MSP_HW_UNAVAILABLE;
    uint8_t sa_status = MSP_SERVICE_NOT_SUPPORTED;

    if ((serviceID & MSP_SERVICE_MASK) != MSP_SERVICE || isAvailable == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    result = mspcore_get_hw_status(&hw_status);
    if (result != TEE_SUCCESS) {
        tloge("get msp core hardware status failed\n");
        return result;
    }

    if (hw_status == MSP_HW_UNAVAILABLE) {
        tloge("get msp core hardware is unavailable\n");
        *isAvailable = MSP_SERVICE_IS_UNAVAILABLE_MAGIC;
        return TEE_SUCCESS;
    }

    mspcore_get_service_status(serviceID, &sa_status);
    if (sa_status == MSP_SERVICE_IS_SUPPORTED) {
        *isAvailable = MSP_SERVICE_IS_AVAILABLE_MAGIC;
    } else {
        *isAvailable = MSP_SERVICE_IS_UNAVAILABLE_MAGIC;
    }

    return TEE_SUCCESS;
}

#ifdef CONFIG_HISI_MSPC
static TEE_Result mspc_wait_enter_fac_mode(void)
{
    int32_t ret;
    int32_t timeout = MSPC_FAC_MODE_ENTER_TIMEOUT;

    ret = __hisi_mspc_fac_mode_enter();
    while (ret != MSPC_OK) {
        if (timeout <= 0) {
            tloge("%s:timeout!\n", __func__);
            return TEE_ERROR_TIMEOUT;
        }
        SRE_DelayMs(MSPC_WAIT_FAC_MODE_ENTER_DELAY_MS);
        timeout--;
        ret = __hisi_mspc_fac_mode_enter();
    }

    return TEE_SUCCESS;
}
#endif

/*
 * @brief     : GP Extend TEE API do factory recovery operation about msc device.
 * @param[in] : flags, indicate the operation type, now is not used,fixed as 0xffffffff.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_MspcRecovery(uint32_t flags)
{
#ifdef CONFIG_HISI_MSPC
    int32_t ret;
    TEE_Result result;

    result = mspc_wait_enter_fac_mode();
    if (result != TEE_SUCCESS) {
        tloge("%s wait fac mode failed:result=%x\n", __func__, result);
        return result;
    }
    ret = __hisi_mspc_recovery(flags);
    if (ret != MSPC_OK) {
        tloge("%s call driver failed:ret=%x\n", __func__, (uint32_t)ret);
        (void)__hisi_mspc_fac_mode_exit();
        return TEE_ERROR_COMMUNICATION;
    }

    ret = __hisi_mspc_fac_mode_exit();
    if (ret != MSPC_OK) {
        tloge("%s exit fac mode failed:ret=%x\n", __func__, (uint32_t)ret);
        return (TEE_Result)ret;
    }
#endif
    UNUSED(flags);
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_MspcPowerOn(uint32_t voteId)
{
    int32_t ret;

    ret = __hisi_mspc_power_on(voteId);
    if (ret != MSPC_OK) {
        tloge("%s call driver failed:ret=%x\n", __func__, ret);
        return TEE_ERROR_COMMUNICATION;
    }
    tloge("%s voteId:%u success", __func__, voteId);
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_MspcPowerOff(uint32_t voteId)
{
    int32_t ret;

    ret = __hisi_mspc_power_off(voteId);
    if (ret != MSPC_OK) {
        tloge("%s call driver failed:ret=%x\n", __func__, ret);
        return TEE_ERROR_COMMUNICATION;
    }
    tloge("%s voteId:%u success", __func__, voteId);
    return TEE_SUCCESS;
}

bool TEE_EXT_IsMspcHardwareErrno(uint32_t errno)
{
    uint32_t i;
    uint32_t maskStatus = errno & SECFLASH_ERR_MASK;

    for (i = 0; i < ARRAY_SIZE(g_mspc_hardware_error); i++)
        if (errno == g_mspc_hardware_error[i])
            return true;

    if (maskStatus == SECFLASH_ERR_OPERATION_SW || maskStatus == SECFLASH_ERR_STATUS_SW || maskStatus ==
        SECFLASH_ERR_TDS_SW)
        return true;
    return false;
}
