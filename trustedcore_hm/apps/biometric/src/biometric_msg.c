/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: fingerprint agent
 * Author: gongyanan
 * Create: 2019-9-21
 */

#include "biometric_msg.h"
#include "biometric_task.h"
#include "biometric_public.h"
#include "msp_tee_se_ext_api.h"
#include "securec.h"
#include "sre_access_control.h"
#include "sre_syscall.h"
#include "string.h"
#include "ta_framework.h"
#include "tee_common.h"
#include "tee_config.h"
#include "tee_log.h"
#include "msg_ops.h"
#include "tee_service_public.h"
#include "tee_commom_public_service.h"

void bio_ext_sa_load(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    int32_t res;
    uint8_t *image = NULL;
    uint32_t image_size;

    image_size = (uint32_t)msg->args_data.arg1;
    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0,
                            image_size, (uint32_t *)&image);
    if (res != 0) {
        tloge("%s, msp bio failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    rsp->ret = bio_sa_load(image, image_size, sender);
    if (rsp->ret != TEE_SUCCESS) {
        tloge("%s failed, %x\n", __func__, rsp->ret);
    }

    if (image != NULL) {
        tee_unmap_from_task((uint32_t)(uintptr_t)image, image_size);
    }
}

void bio_ext_sa_install(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    int32_t res;
    struct msp_install_sa_info *sa_info = NULL;
    struct sa_status *status = NULL;
    uint32_t sa_info_len = sizeof(struct msp_install_sa_info);
    uint32_t sa_status_len = sizeof(struct sa_status);

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0,
                            sa_info_len, (uint32_t *)&sa_info);
    if (res != 0) {
        tloge("%s, msp bio failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg1,
                            sa_status_len, (uint32_t *)&status);
    if (res != 0) {
        tloge("%s, msp bio failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        goto ERR1;
    }

    rsp->ret = bio_sa_install(sa_info, status, sender);
    if (rsp->ret != TEE_SUCCESS) {
        tloge("%s failed, %x\n", __func__, rsp->ret);
    }

    if (status != NULL) {
        tee_unmap_from_task((uint32_t)(uintptr_t)status, sa_status_len);
    }
ERR1:
    if (sa_info != NULL) {
        tee_unmap_from_task((uint32_t)(uintptr_t)sa_info, sa_info_len);
    }
}

void bio_ext_sa_start(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    if (msg == NULL) {
        tloge("%s, msp bio failed\n", __func__);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    rsp->ret = bio_sa_start(sender);
    if (rsp->ret != TEE_SUCCESS) {
        tloge("%s failed, %x\n", __func__, rsp->ret);
    }
}

void bio_ext_send_command(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    char *apdu_buffer_local = NULL;
    uint32_t apdu_length = msg->args_data.arg1;
    char *out_buffer_local = NULL;
    uint32_t *out_length_local = NULL;
    uint32_t out_length;
    int32_t res;
    uint32_t size;

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0,
                            apdu_length, (uint32_t *)&apdu_buffer_local);
    if (res != 0) {
        tloge("%s, msp bio failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    size = sizeof(uint32_t);
    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg3,
                            size, (uint32_t *)&out_length_local);
    if (res != 0 || out_length_local == NULL) {
        tloge("%s, msp bio failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        goto ERR;
    }
    out_length = *out_length_local;

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg2,
                            out_length, (uint32_t *)&out_buffer_local);
    if (res != 0) {
        tloge("%s, msp bio failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        goto ERR;
    }

    rsp->ret = bio_send_command(apdu_buffer_local, apdu_length, out_buffer_local, &out_length, sender);
    if (rsp->ret != TEE_SUCCESS) {
        tloge("%s failed, %x\n", __func__, rsp->ret);
    }

    if (out_buffer_local != NULL) {
        tee_unmap_from_task((uint32_t)(uintptr_t)out_buffer_local, *out_length_local);
    }

    *out_length_local = out_length;
ERR:
    if (out_length_local != NULL) {
        tee_unmap_from_task((uint32_t)(uintptr_t)out_length_local, size);
    }
    if (apdu_buffer_local != NULL) {
        tee_unmap_from_task((uint32_t)(uintptr_t)apdu_buffer_local, apdu_length);
    }
}

void bio_ext_sa_close(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    if (msg == NULL) {
        tloge("%s, msp bio failed\n", __func__);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    rsp->ret = bio_sa_close(sender);
    if (rsp->ret != TEE_SUCCESS) {
        tloge("%s failed, %x\n", __func__, rsp->ret);
    }
}

void bio_ext_reinit(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    if (msg == NULL) {
        tloge("%s, msp bio failed\n", __func__);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    rsp->ret = bio_sa_reinit(sender);
    if (rsp->ret != TEE_SUCCESS) {
        tloge("%s failed, %x\n", __func__, rsp->ret);
    }
}

static tee_service_cmd g_biometric_cmd_tbl[] = {
    /* cmd,                     fn */
    {BIO_MSG_EXT_LOAD_CMD,      bio_ext_sa_load},
    {BIO_MSG_EXT_INSTALL_CMD,   bio_ext_sa_install},
    {BIO_MSG_EXT_START_CMD,     bio_ext_sa_start},
    {BIO_MSG_EXT_SEND_CMD,      bio_ext_send_command},
    {BIO_MSG_EXT_CLOSE_CMD,     bio_ext_sa_close},
    {BIO_MSG_EXT_REINIT_CMD,    bio_ext_reinit}
};

uint32_t tee_service_init(void)
{
    return TEE_SUCCESS;
}

void tee_service_handle(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp,
    uint32_t cmd)
{
    uint32_t i;
    uint32_t tbl_size = sizeof(g_biometric_cmd_tbl) / sizeof(g_biometric_cmd_tbl[0]);

    if (rsp == NULL)
        return;
    if (msg == NULL) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    for (i = 0; i < tbl_size; i++) {
        if (cmd == g_biometric_cmd_tbl[i].cmd) {
            if (g_biometric_cmd_tbl[i].fn != NULL)
                g_biometric_cmd_tbl[i].fn(msg, task_id, rsp);
            break;
        }
    }

    /* if the cmd is error, need ack?? */
    if (i == tbl_size) {
        rsp->ret = TEE_ERROR_INVALID_CMD;
        return;
    }

    return;
}

#ifdef CONFIG_DYNLINK
__attribute__((section(".magic")))
const char g_magic_string[] = "Dynamically linked.";
#endif

/*
TA's main func
*/
__attribute__((visibility ("default"))) void tee_task_entry(int init_build)
{
    tloge("start of bio service task----------------------------------------\n");
    tee_common_task_entry(init_build, BIO_TASK_NAME);
}
