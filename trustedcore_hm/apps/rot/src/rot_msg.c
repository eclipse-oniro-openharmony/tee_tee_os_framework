/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Root of Trust msg communication management.
 * Author: t00360454
 * Create: 2020-02-10
 * Notes:
 * History: 2020-02-10 t00360454 create
 */
#include "rot_msg.h"
#include <hm_msg_type.h>
#include <msg_ops.h>
#include "rot_task.h"
#include "rot_public.h"
#include "securec.h"
#include "tee_log.h"
#include "sre_syscall.h"
#include "tee_commom_public_service.h"

/*
 * @brief     : Unpack incoming message. Call rot_send_apdu_command. Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
static void rot_ext_send_command(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    int res;
    char *shared_capdu = NULL;
    char *shared_rapdu = NULL;
    uint32_t *shared_rapdu_len = NULL;
    uint32_t capdu_len;
    uint32_t rapdu_max_len;
    enum ROT_ERR_CODE ret;

    capdu_len = (uint32_t)msg->args_data.arg1;
    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0, capdu_len, (uint32_t *)&shared_capdu);
    if (res != 0) {
        tloge("rot, %s, shared_capdu failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        goto mem_unmap_capdu;
    }

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg3, sizeof(uint32_t),
                            (uint32_t *)&shared_rapdu_len);
    if (res != 0 || !shared_rapdu_len) {
        tloge("rot, %s, shared_rapdu_len failed, %d, %x\n", __func__, res, shared_rapdu_len);
        rsp->ret = TEE_ERROR_GENERIC;
        goto mem_unmap_rapdu_len;
    }

    rapdu_max_len = *shared_rapdu_len;
    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg2, rapdu_max_len, (uint32_t *)&shared_rapdu);
    if (res != 0) {
        tloge("rot, %s, shared_rapdu failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        goto mem_unmap_rapdu;
    }

    ret = rot_transmit_apdu_message(shared_capdu, capdu_len, shared_rapdu, shared_rapdu_len, sender);
    if (ret != ROT_SUCCESS) {
        tloge("rot, %s, transmit failed, %x\n", __func__, ret);
        rsp->ret = (uint32_t)ret;
    } else {
        rsp->ret = TEE_SUCCESS;
    }

mem_unmap_rapdu:
    if (shared_rapdu)
        tee_unmap_from_task((uint32_t)(uintptr_t)shared_rapdu, rapdu_max_len);
mem_unmap_rapdu_len:
    if (shared_rapdu_len)
        tee_unmap_from_task((uint32_t)(uintptr_t)shared_rapdu_len, sizeof(uint32_t));
mem_unmap_capdu:
    if (shared_capdu)
        tee_unmap_from_task((uint32_t)(uintptr_t)shared_capdu, capdu_len);

    tloge("rot, %s finished, %x\n", __func__, rsp->ret);
}

static tee_service_cmd g_rot_cmd_table[] = {
    {ROT_MSG_EXT_SEND_CMD, rot_ext_send_command},
};

uint32_t tee_service_init(void)
{
    return TEE_SUCCESS;
}

void tee_service_handle(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp, uint32_t cmd)
{
    uint32_t i;
    uint32_t num = ARRAY_SIZE(g_rot_cmd_table);

    if (!rsp)
        return;

    if (!msg) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    for (i = 0; i < num; i++) {
        if (cmd != g_rot_cmd_table[i].cmd)
            continue;

        if (g_rot_cmd_table[i].fn)
            g_rot_cmd_table[i].fn(msg, task_id, rsp);

        return;
    }

    /* the cmd not supported */
    rsp->ret = TEE_ERROR_INVALID_CMD;
}

#ifdef CONFIG_DYNLINK
__attribute__((section(".magic")))
const char g_magic_string[] = "Dynamically linked.";
#endif

/*
 * TA's main func
 */
__attribute__((visibility ("default"))) void tee_task_entry(int init_build)
{
    tloge("rot, start service task----------------------------------------\n");
    tee_common_task_entry(init_build, ROT_TASK_NAME);
}
