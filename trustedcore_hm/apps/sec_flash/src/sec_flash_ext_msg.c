/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * Description: Secure flash msg ext API communication management.
 * Create: 2019-10-15
 */

#include "sec_flash_ext_msg.h"
#include "securec.h"
#include "tee_log.h"
#include "ta_framework.h"
#include "sre_access_control.h"
#include "string.h"
#include "sre_syscall.h"
#include "tee_commom_public_service.h"
#ifndef HISI_MSP_SECFLASH
#include "secflash_service_init.h"
#endif
#include "sec_flash_public.h"
#include "secflash_scp03_comm.h"
#include "secureflash_interface.h"

/* The current accessing TEE_UUID. */
static TEE_UUID g_cur_uuid;

/*
 * @brief     : Check the msg and rsp validity. Obtain current TEE_UUID.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
static TEE_Result secflash_ext_call_prepare(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;

#ifndef HISI_MSP_SECFLASH
    secflash_service_init();
#endif
    if (!rsp) {
        tloge("%s, invalid parameters!\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (!msg) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        tloge("%s, invalid parameters!\n", __func__);
        return rsp->ret;
    }

    ret = tee_common_get_uuid_by_sender(sender, &g_cur_uuid, sizeof(TEE_UUID));
    if (ret != TEE_SUCCESS) {
        tloge("%d, error ret = 0x%x\n", __func__, ret);
        rsp->ret = ret;
        return ret;
    }

    return TEE_SUCCESS;
}

/*
 * @brief     : Unpack incoming msg. Call secflash_device_is_available. Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_ext_call_is_available(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    int res;
    TEE_Result ret;
    uint32_t *status_info = NULL;
    uint32_t len;

    ret = secflash_ext_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s, call_prepare failed\n", __func__);
        return;
    }
    secflash_ext_set_current_uuid(&g_cur_uuid);
    len = sizeof(uint32_t);
    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0, len, (uint32_t *)&status_info);
    if (res != 0) {
        tloge("%s, map failed, %d\n", __func__, res);
        ret = TEE_ERROR_GENERIC;
        goto error_ret_handle;
    }

    ret = secflash_device_is_available(status_info);
    if (ret != TEE_SUCCESS) {
        tloge("%s, secflash_device_is_available failed, %x\n", __func__, ret);
        goto unmap_restore;
    }

unmap_restore:
    tee_unmap_from_task((uint32_t)(uintptr_t)status_info, len);
error_ret_handle:
    rsp->ret = ret;
    secflash_ext_set_current_uuid(NULL);
}

/*
 * @brief     : Unpack incoming msg. Call secflash_factory_recovery. Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_ext_call_factory_recovery(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;
    uint32_t flags;

    ret = secflash_ext_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s, call_prepare failed\n", __func__);
        return;
    }
    secflash_ext_set_current_uuid(&g_cur_uuid);
    ret = secflash_ext_check_uuid(SECURE_STORAGE_TA_CALLER);
    if (ret != TEE_SUCCESS) {
        tloge("%s, secflash_ext_check_uuid failed, %x\n", __func__, ret);
        goto error_ret_handle;
    }
    flags = (uint32_t)msg->args_data.arg0;
    ret = secflash_factory_recovery(flags);
    if (ret != TEE_SUCCESS) {
        tloge("%s, secflash_factory_recovery failed, %x\n", __func__, ret);
        goto error_ret_handle;
    }

error_ret_handle:
    rsp->ret = ret;
    secflash_ext_set_current_uuid(NULL);
}

/*
 * @brief     : Unpack incoming msg. Call secflash_power_saving Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_ext_call_power_saving(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;

    ret = secflash_ext_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s, call_prepare failed\n", __func__);
        return;
    }
    secflash_ext_set_current_uuid(&g_cur_uuid);
    ret = secflash_power_saving();
    if (ret != TEE_SUCCESS) {
        tloge("%s, secflash_power_saving failed, %x\n", __func__, ret);
        goto error_ret_handle;
    }

error_ret_handle:
    rsp->ret = ret;
    secflash_ext_set_current_uuid(NULL);
}

/*
 * @brief     : Unpack incoming msg. Call secflash_reset Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_ext_call_device_reset(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;
    uint32_t reset_type;

    ret = secflash_ext_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s, call_prepare failed\n", __func__);
        return;
    }
    secflash_ext_set_current_uuid(&g_cur_uuid);
    reset_type = msg->args_data.arg0;
    ret = secflash_reset(reset_type);
    if (ret != TEE_SUCCESS) {
        tloge("%s, secflash_reset type:%d failed, %x\n", __func__, reset_type, ret);
        goto error_ret_handle;
    }

error_ret_handle:
    rsp->ret = ret;
    secflash_ext_set_current_uuid(NULL);
}

/*
 * @brief     : Unpack incoming msg. Call secflash_derive_binding_key Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_ext_call_derive_binding_key(const tee_service_ipc_msg *msg,
                                          uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    int res;
    TEE_Result ret;
    uint8_t *local_keybuff = NULL;
    uint32_t curr_batch_id;
    uint32_t buf_len;

    ret = secflash_ext_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s, call_prepare failed\n", __func__);
        return;
    }

    secflash_ext_set_current_uuid(&g_cur_uuid);
    ret = secflash_ext_check_uuid(WEAVER_TA_CALLER);
    if (ret != TEE_SUCCESS) {
        tloge("%s, secflash_ext_check_uuid failed, %x\n", __func__, ret);
        goto error_ret_handle;
    }
    curr_batch_id = secflash_get_batch_id();
    buf_len = msg->args_data.arg1;
    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0, buf_len, (uint32_t *)&local_keybuff);
    if (res != 0) {
        tloge("%s, map failed, %d\n", __func__, res);
        ret = TEE_ERROR_GENERIC;
        goto error_ret_handle;
    }
    /* key type fixed: weaver binding key */
    ret = secflash_derive_binding_key(SECFLASH_KVN_BINDING_KEY3, curr_batch_id,
                                      (struct secflash_keyset *)local_keybuff);
    if (ret != TEE_SUCCESS) {
        tloge("%s, secflash_derive_binding_key failed, %x\n", __func__, ret);
        goto unmap_restore;
    }

unmap_restore:
    tee_unmap_from_task((uint32_t)(uintptr_t)local_keybuff, buf_len);
error_ret_handle:
    rsp->ret = ret;
    secflash_ext_set_current_uuid(NULL);
}

/*
 * @brief     : Unpack incoming msg. Call secflash_enable_write_lock Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_ext_call_writelock_cfg(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;
    bool is_set_operation = false;

    ret = secflash_ext_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s, call_prepare failed\n", __func__);
        return;
    }
    secflash_ext_set_current_uuid(&g_cur_uuid);
    ret = secflash_ext_check_uuid(SECURE_STORAGE_TA_CALLER);
    if (ret != TEE_SUCCESS) {
        tloge("%s, secflash_ext_check_uuid failed, %x\n", __func__, ret);
        goto error_ret_handle;
    }
    is_set_operation = msg->args_data.arg0;
    ret = secflash_config_writelock_flag(is_set_operation, true);
    if (ret != TEE_SUCCESS) {
            tloge("%s, secflash_config_writelock_flag operation=%d, failed, %x\n", __func__, is_set_operation, ret);
            goto error_ret_handle;
    }

error_ret_handle:
    rsp->ret = ret;
    secflash_ext_set_current_uuid(NULL);
}
