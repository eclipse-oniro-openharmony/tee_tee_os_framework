/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: samgr msg communication management.
 * Author: x00225909
 * Create: 2020-07-02
 * Notes:
 * History: 2020-07-02 x00225909 create
 */
#include "samgr_msg.h"
#include <hm_msg_type.h>
#include "msg_ops.h"
#include "msp_tee_se_ext_api.h"
#include "product_uuid.h"
#include "samgr_common.h"
#include "securec.h"
#include "sre_syscall.h"
#include "tee_commom_public_service.h"
#include "tee_inner_uuid.h"
#include "tee_log.h"

static const TEE_UUID g_samgr_uuid_whitelist[] = {
    TEE_SERVICE_ROT,
    TEE_SERVICE_ART,
    TEE_SERVICE_BIO,
    TEE_SERVICE_SEC_FLASH,
    TEE_SERVICE_WEAVER,
    TEE_SERVICE_STRONGBOX,
    TEE_SERVICE_FILE_ENCRY,
#ifdef DEF_ENG
    TEE_COMMON_TEST_TA1,
    TEE_COMMON_TEST_TA2,
#endif
};

/*
 * @brief     : check the caller's uuid.
 * @param[in] : sender, The sender of this call.
 * @return    : TEE_SUCCESS: successful; others: failed.
 */
static TEE_Result check_uuid(uint32_t sender)
{
    TEE_UUID uuid = {0};
    uint32_t ret;
    uint32_t i;
    uint32_t cnt = sizeof(g_samgr_uuid_whitelist) / sizeof(TEE_UUID);

    ret = (uint32_t)tee_common_get_uuid_by_sender(sender, &uuid, sizeof(TEE_UUID));
    if (ret != TEE_SUCCESS) {
        tloge("%s, tee_common_get_uuid_by_sender failed, %x\n", __func__, ret);
        return TEE_ERROR_GENERIC;
    }

    if (cnt == 0) {
        return TEE_ERROR_ACCESS_DENIED;
    }

    for (i = 0; i < cnt; i++) {
        if (memcmp(&g_samgr_uuid_whitelist[i], &uuid, sizeof(TEE_UUID)) == 0) {
            return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_ACCESS_DENIED;
}

/*
 * @brief     : load sa.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void samgr_load_sa(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    uint32_t ret;
    int res;
    uint8_t *sa_image_data = NULL;
    uint32_t sa_image_size;
    uint8_t *sa_aid = NULL;
    uint32_t sa_aid_len;

    ret = check_uuid(sender);
    if (ret != TEE_SUCCESS) {
        tloge("%s, check_uuid failed, %x\n", __func__, ret);
        rsp->ret = ret;
        return;
    }

    sa_image_size = (uint32_t)msg->args_data.arg1;

    if (sa_image_size != 0) {
        res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0, sa_image_size,
                                (uint32_t *)&sa_image_data);
        if (res != TEE_SUCCESS) {
            tloge("%s, sa_image_data map value failed, %d\n", __func__, res);
            rsp->ret = TEE_ERROR_GENERIC;
            return;
        }
    }

    sa_aid_len = (uint32_t)msg->args_data.arg3;

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg2, sa_aid_len,
                            (uint32_t *)&sa_aid);
    if (res != TEE_SUCCESS) {
        tloge("%s, sa_aid map value failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        goto load_map_err;
    }

    rsp->ret = sa_mgr_load_sa(sa_image_data, sa_image_size, sa_aid, sa_aid_len);
    if (rsp->ret != TEE_SUCCESS)
        tloge("%s sa_mgr_load_sa failed, %x\n", __func__, rsp->ret);

load_map_err:
    if (sa_image_data != NULL)
        tee_unmap_from_task((uint32_t)(uintptr_t)sa_image_data, sa_image_size);

    if (sa_aid != NULL)
        tee_unmap_from_task((uint32_t)(uintptr_t)sa_aid, sa_aid_len);
}

/*
 * @brief     : install sa.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void samgr_install_sa(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    uint32_t ret;
    int res;
    struct sa_status *status = NULL;
    struct msp_install_sa_info *install_sa_info = NULL;

    ret = check_uuid(sender);
    if (ret != TEE_SUCCESS) {
        tloge("%s, check_uuid failed, %x\n", __func__, ret);
        rsp->ret = ret;
        return;
    }

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0,
                            sizeof(struct msp_install_sa_info), (uint32_t *)&install_sa_info);
    if (res != TEE_SUCCESS) {
        tloge("%s, install_sa_info map value failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg1,
                            sizeof(struct sa_status), (uint32_t *)&status);
    if (res != TEE_SUCCESS) {
        tloge("%s, status map value failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        goto install_map_err;
    }

    rsp->ret = sa_mgr_install_sa(install_sa_info, status);
    if (rsp->ret != TEE_SUCCESS)
        tloge("%s sa_mgr_install_sa failed, %x\n", __func__, rsp->ret);

install_map_err:
    if (install_sa_info != NULL)
        tee_unmap_from_task((uint32_t)(uintptr_t)install_sa_info, sizeof(struct msp_install_sa_info));

    if (status != NULL)
        tee_unmap_from_task((uint32_t)(uintptr_t)status, sizeof(struct sa_status));
}

/*
 * @brief     : get sa status.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void samgr_get_sa_status(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    uint32_t ret;
    int res;
    uint8_t *sa_aid = NULL;
    uint32_t sa_aid_len;
    struct sa_status_detail *status = NULL;

    ret = check_uuid(sender);
    if (ret != TEE_SUCCESS) {
        tloge("%s, check_uuid failed, %x\n", __func__, ret);
        rsp->ret = ret;
        return;
    }

    sa_aid_len = (uint32_t)msg->args_data.arg1;

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0, sa_aid_len,
                            (uint32_t *)&sa_aid);
    if (res != TEE_SUCCESS) {
        tloge("%s, sa_aid map value failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg2, sizeof(struct sa_status_detail),
                            (uint32_t *)&status);
    if (res != TEE_SUCCESS) {
        tloge("%s, status map value failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        goto getstatus_map_err;
    }

    rsp->ret = sa_mgr_get_sa_status(sa_aid, sa_aid_len, status);
    if (rsp->ret != TEE_SUCCESS)
        tloge("%s sa_mgr_get_sa_status failed, %x\n", __func__, rsp->ret);

getstatus_map_err:
    if (sa_aid != NULL)
        tee_unmap_from_task((uint32_t)(uintptr_t)sa_aid, sa_aid_len);

    if (status != NULL)
        tee_unmap_from_task((uint32_t)(uintptr_t)status, sizeof(struct sa_status_detail));
}

