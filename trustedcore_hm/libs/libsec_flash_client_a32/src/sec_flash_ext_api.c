/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Secure flash msg communication management.
 * Create: 2019-10-15
 * Notes:
 * History: 2019-10-15 lvtaolong create sf_xxx functions.
 *          2019-10-15 lvtaolong add TEE_EXT_SecFlashxxx functions.
 */
#include "sec_flash_ext_api.h"
#include <stdarg.h>
#include "string.h"
#include "sre_sys.h"
#include "securec.h"
#include "ta_framework.h"
#include "tee_trusted_storage_api.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "tee_service_public.h"
#include "sec_flash_public.h"
#include "sre_syscalls_ext.h"
#include "mem_ops_ext.h"
#include "hisi_mspc.h"
#include "tee_inner_uuid.h"

#if defined(CONFIG_HISI_SECFLASH) || defined(HISI_MSP_SECFLASH)

/*
 * @brief     : GP Extend TEE API judge whether device is available in secflash implementation .
 * @param[out]: status_info, the pointer to a int variable to save device status.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_SecFlashIsAvailable(uint32_t *status_info)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint32_t *status_info_local = NULL;
    uint32_t buf_len = sizeof(uint32_t);

    if (!status_info) {
        tloge("%s invalid params\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    status_info_local = tee_alloc_sharemem_aux(&g_sec_flash_uuid, buf_len);
    if (!status_info_local) {
        tloge("%s AllocSharedMem fail\n", __func__);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    msg.args_data.arg0 = (uintptr_t)status_info_local;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_EXT_IS_AVAILABLE_CMD, &msg,
        SEC_FLASH_MSG_EXT_IS_AVAILABLE_CMD, &rsp);
    ret = rsp.ret;
    tloge("TEE_EXT_SecFlashIsAvailable ret = %x", ret);
    if (ret == TEE_SUCCESS) {
        if (memmove_s(status_info, buf_len, status_info_local, buf_len) != EOK) {
            tloge("%s memmove_s fail\n", __func__);
            ret = TEE_ERROR_SECURITY;
        }
    }
    if (*status_info != SECFLASH_IS_ABSENCE_MAGIC && *status_info != SECFLASH_NXP_EXIST_MAGIC &&
        *status_info != SECFLASH_ST_EXIST_MAGIC) {
        tloge("%s status_info(0x%x) check fail\n", __func__, *status_info);
        ret = TEE_ERROR_BAD_STATE;
    }
    (void)__SRE_MemFreeShared(status_info_local, buf_len);
    return ret;
}
#else
/* if secure flash feature is diable, stub these TEE_EXT_xxx functions */
TEE_Result TEE_EXT_SecFlashIsAvailable(uint32_t *status_info)
{
    if (!status_info) {
        tloge("%s invalid params\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *status_info = SECFLASH_IS_ABSENCE_MAGIC;
    return TEE_SUCCESS;
}
#endif

#ifdef CONFIG_HISI_SECFLASH
/*
 * @brief     : GP Extend TEE API do factory recovery operation about secflash device.
 * @param[in] : flags, indicate the operation type, now is not used,fixed as 0xffffffff.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_SecFlashFactoryRecovery(uint32_t flags)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;

    msg.args_data.arg0 = flags;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_EXT_FACTORY_RECOVERY_CMD, &msg,
        SEC_FLASH_MSG_EXT_FACTORY_RECOVERY_CMD, &rsp);
    ret = rsp.ret;
    tloge("TEE_EXT_SecFlashFactoryRecovery ret = %x", ret);
    return ret;
}

/*
 * @brief     : GP Extend TEE API make device entering power saving mode in secflash implementation .
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_SecFlashPowerSaving(void)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;

    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_EXT_POWER_SAVING_CMD, &msg,
        SEC_FLASH_MSG_EXT_POWER_SAVING_CMD, &rsp);
    ret = rsp.ret;
    tloge("TEE_EXT_SecFlashPowerSaving ret = %x", ret);
    return ret;
}

/*
 * @brief     : GP Extend TEE API make device software reset in secflash implementation .
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_SecFlashReset(uint32_t reset_type)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;

    if (reset_type != SECFLASH_RESET_TYPE_SOFT && reset_type != SECFLASH_RESET_TYPE_HARD) {
        tloge("%s invalid params\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg.args_data.arg0 = reset_type;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_EXT_RESET_CMD, &msg, SEC_FLASH_MSG_EXT_RESET_CMD, &rsp);
    ret = rsp.ret;
    tloge("TEE_EXT_SecFlashReset ret = %x", ret);
    return ret;
}

/*
 * @brief     : GP Extend TEE API get binding key in secflash implementation .
 * @param[out]: key_buf, the pointer to a buffer which derived binding key save.
 * @param[in] : buf_len, The length of key buffer, unit in bytes
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_SecFlashGetBindingKey(uint8_t *key_buf, uint32_t buf_len)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *keybuf_local = NULL;

    if (!key_buf || buf_len != SF_BINDING_KEY_LEN_IN_BYTES) {
        tloge("%s invalid params\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    keybuf_local = tee_alloc_sharemem_aux(&g_sec_flash_uuid, buf_len);
    if (!keybuf_local) {
        tloge("%s AllocSharedMem fail\n", __func__);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    msg.args_data.arg0 = (uintptr_t)keybuf_local;
    msg.args_data.arg1 = buf_len;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_EXT_BINDING_KEY_CMD, &msg,
        SEC_FLASH_MSG_EXT_BINDING_KEY_CMD, &rsp);
    ret = rsp.ret;
    tloge("TEE_EXT_SecFlashGetBindingKey ret = %x", ret);
    if (ret == TEE_SUCCESS) {
        if (memmove_s(key_buf, buf_len, keybuf_local, buf_len) != EOK) {
            tloge("%s memmove_s fail\n", __func__);
            ret = TEE_ERROR_SECURITY;
        }
    }

    (void)memset_s((void *)keybuf_local, buf_len, 0, buf_len); /* clear key buffer */
    (void)__SRE_MemFreeShared(keybuf_local, buf_len);
    return ret;
}

/*
 * @brief     : GP Extend TEE API lock the write function for secureflash in secflash implementation, it only work in
 *              factory test, not result on secure storage service .
 * @param[in] : is_set_operation:true:set operation; false:get operation.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_SecFlashWriteLockEnable(bool is_set_operation)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;

    msg.args_data.arg0 = is_set_operation;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_EXT_WRITE_LOCK_CMD, &msg,
        SEC_FLASH_MSG_EXT_WRITE_LOCK_CMD, &rsp);
    ret = rsp.ret;
    tloge("TEE_EXT_SecFlashWriteLockEnable ret = %x", ret);
    return ret;
}
#else /* CONFIG_SECFLASH */
TEE_Result TEE_EXT_SecFlashFactoryRecovery(uint32_t flags)
{
    (void)flags;
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_SecFlashPowerSaving(void)
{
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_SecFlashReset(uint32_t reset_type)
{
    (void)reset_type;
    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_SecFlashGetBindingKey(uint8_t *key_buf, uint32_t buf_len)
{
    (void)key_buf;
    (void)buf_len;
    return TEE_SUCCESS;
}

#ifdef HISI_MSP_SECFLASH
#define MSPC_OK                                  0x5A5A
#define SECFLASH_ENTER_MSPC_FAC_MODE_DELAY_MS    100  /* ms */
#define SECFLASH_ENTER_MSPC_FAC_MODE_TIMEOUT     5000 /* ms */
#define SECFLASH_ENTER_MSPC_FAC_MODE_RETRY_CNT   \
    (SECFLASH_ENTER_MSPC_FAC_MODE_TIMEOUT / SECFLASH_ENTER_MSPC_FAC_MODE_DELAY_MS)

static TEE_Result secflash_enter_mspc_fac_mode(void)
{
    int32_t ret;
    uint32_t retry = 0;

    ret = __hisi_mspc_fac_mode_enter();
    while (ret != MSPC_OK) {
        retry++;
        if (retry > SECFLASH_ENTER_MSPC_FAC_MODE_RETRY_CNT) {
            tloge("%s:timeout", __func__);
            return TEE_ERROR_TIMEOUT;
        }
        SRE_DelayMs(SECFLASH_ENTER_MSPC_FAC_MODE_DELAY_MS);
        ret = __hisi_mspc_fac_mode_enter();
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_SecFlashWriteLockEnable(bool is_set_operation)
{
    TEE_Result result;
    int32_t ret;
    uint32_t status_info = 0;

    result = TEE_EXT_SecFlashIsAvailable(&status_info);
    if (result != TEE_SUCCESS) {
        tloge("%s call secflash is available fail: ret=%x\n", __func__, result);
        return result;
    }
    if (status_info == SECFLASH_IS_ABSENCE_MAGIC) {
        tloge("%s secflash is absence, return OK directly\n", __func__);
        return TEE_SUCCESS;
    }

    result = secflash_enter_mspc_fac_mode();
    if (result != TEE_SUCCESS) {
        tloge("%s wait fac mode err\n", __func__);
        return result;
    }

    ret = __hisi_mspc_secflash_writelock(is_set_operation);
    if (ret != MSPC_OK) {
        tloge("%s call driver failed:ret=%x\n", __func__, (uint32_t)ret);
        (void)__hisi_mspc_fac_mode_exit();
        return TEE_ERROR_COMMUNICATION;
    }

    ret = __hisi_mspc_fac_mode_exit();
    if (ret != MSPC_OK) {
        tloge("%s exit fac mode failed:ret=%x\n", __func__, (uint32_t)ret);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}
#else
TEE_Result TEE_EXT_SecFlashWriteLockEnable(bool is_set_operation)
{
    (void)is_set_operation;
    return TEE_SUCCESS;
}
#endif /* HISI_MSP_SECFLASH */
#endif /* CONFIG_HISI_SECFLASH */
