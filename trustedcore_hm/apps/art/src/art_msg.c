/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ART msg communication management.
 * Author: c00301810
 * Create: 2020-03-21
 * Notes:
 * History: 2020-03-21 c00301810 create
 */

#include "art_msg.h"
#include <hm_msg_type.h>
#include "art_comm.h"
#include "art_public.h"
#include "msg_ops.h"
#include "samgr_msg.h"
#include "securec.h"
#include "sre_syscall.h"
#include "tee_commom_public_service.h"
#include "tee_log.h"

#ifdef CONFIG_ART_TEE_WHITELIST
#ifdef DEF_ENG
#define TEE_TA_ART_TEST1                                   \
    {                                                      \
        0x9cb38838, 0x2766, 0x42be,                        \
        {                                                  \
            0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x61 \
        }                                                  \
    }
#define TEE_TA_ART_TEST2                                   \
    {                                                      \
        0x9cb38838, 0x2766, 0x42be,                        \
        {                                                  \
            0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x62 \
        }                                                  \
    }
#endif

static const TEE_UUID g_art_uuid_whitelist[] = {
#ifdef DEF_ENG
    TEE_TA_ART_TEST1,
    TEE_TA_ART_TEST2,
#endif
};
#endif

/*
 * @brief     : get the caller's uuid.
 *
 * @param[in] : sender,The sender of this call.
 * @param[out]: uuid, current uuid.
 *
 * @return    : TEE_SUCCESS: successful; others: failed.
 */
static TEE_Result get_uuid(uint32_t sender, TEE_UUID *uuid)
{
    uint32_t ret;

    ret = (uint32_t)tee_common_get_uuid_by_sender(sender, uuid, sizeof(TEE_UUID));
    if (ret != TEE_SUCCESS) {
        tloge("%s, tee_common_get_uuid_by_sender failed, %x\n", __func__, ret);
        return TEE_ERROR_GENERIC;
    }

#ifdef CONFIG_ART_TEE_WHITELIST
    uint32_t i;
    uint32_t cnt = sizeof(g_art_uuid_whitelist) / sizeof(TEE_UUID);

    if (cnt == 0) {
        return TEE_ERROR_ACCESS_DENIED;
    }

    for (i = 0; i < cnt; i++) {
        if (memcmp(&g_art_uuid_whitelist[i], uuid, sizeof(TEE_UUID)) == 0) {
            return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_ACCESS_DENIED;
#else
    return TEE_SUCCESS;
#endif
}

/*
 * @brief     : allocate slot.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
static void art_alloc_command(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    uint32_t ret;
    int res;
    TEE_UUID uuid;
    uint32_t *total_counters = NULL;

    ret = get_uuid(sender, &uuid);
    if (ret != TEE_SUCCESS) {
        tloge("%s, tee_common_get_uuid_by_sender failed, %x\n", __func__, ret);
        rsp->ret = ret;
        return;
    }

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0, sizeof(uint32_t),
                            (uint32_t *)&total_counters);
    if (res != TEE_SUCCESS) {
        tloge("%s, map value failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    rsp->ret = art_sa_alloc(&uuid, total_counters);
    if (rsp->ret != TEE_SUCCESS)
        tloge("%s art_sa_alloc failed, %x\n", __func__, rsp->ret);

    if (total_counters)
        tee_unmap_from_task((uint32_t)(uintptr_t)total_counters, sizeof(uint32_t));
}

/*
 * @brief     : operate slot counter.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[in] : ops, read or increase.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
static void art_operate_command(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp,
    uint32_t ops)
{
    uint32_t ret;
    int res;
    TEE_UUID uuid;
    uint32_t counter_id;
    uint32_t *counter_value = NULL;

    ret = get_uuid(sender, &uuid);
    if (ret != TEE_SUCCESS) {
        tloge("%s, tee_common_get_uuid_by_sender failed, %x\n", __func__, ret);
        rsp->ret = ret;
        return;
    }

    counter_id = (uint32_t)msg->args_data.arg0;
    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg1, sizeof(uint32_t),
        (uint32_t *)&counter_value);
    if (res != TEE_SUCCESS) {
        tloge("%s, map value failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    if (ops == ART_MSG_INCREASE_CMD)
        rsp->ret = art_sa_increase_counter(&uuid, counter_id, counter_value);
    else
        rsp->ret = art_sa_read_counter(&uuid, counter_id, counter_value);
    if (rsp->ret != ART_SUCCESS)
        tloge("%s art_sa_alloc failed, %x\n", __func__, rsp->ret);
    else
        rsp->ret = TEE_SUCCESS;

    if (counter_value)
        tee_unmap_from_task((uint32_t)(uintptr_t)counter_value, sizeof(uint32_t));
}

/*
 * @brief     : read slot counter.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
static void art_read_command(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    art_operate_command(msg, sender, rsp, ART_MSG_READ_CMD);
}

/*
 * @brief     : increase slot counter.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
static void art_increase_command(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    art_operate_command(msg, sender, rsp, ART_MSG_INCREASE_CMD);
}

static const tee_service_cmd g_art_cmd_table[] = {
    {ART_MSG_ALLOC_CMD, art_alloc_command},
    {ART_MSG_READ_CMD, art_read_command},
    {ART_MSG_INCREASE_CMD, art_increase_command},
    {SAMGR_MSG_EXT_LOAD_CMD, samgr_load_sa},
    {SAMGR_MSG_EXT_INSTALL_CMD, samgr_install_sa},
    {SAMGR_MSG_EXT_GETSTATUS_CMD, samgr_get_sa_status},
};

uint32_t tee_service_init(void)
{
    return TEE_SUCCESS;
}

/*
 * @brief     : art service handle,find command and call process function.
 * @param[in] : msg, Incoming message.
 * @param[in] : task_id, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void tee_service_handle(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp,
    uint32_t cmd)
{
    uint32_t i;
    uint32_t num = ARRAY_SIZE(g_art_cmd_table);

    if (!rsp)
        return;

    if (!msg) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    for (i = 0; i < num; i++) {
        if (cmd != g_art_cmd_table[i].cmd)
            continue;

        if (g_art_cmd_table[i].fn)
            g_art_cmd_table[i].fn(msg, task_id, rsp);

        return;
    }

    /* the cmd not supported */
    rsp->ret = TEE_ERROR_INVALID_CMD;
}

#ifdef CONFIG_DYNLINK
__attribute__((section(".magic")))
const char g_magic_string[] = "Dynamically linked.";
#endif

/* TA's main func */
__attribute__((visibility ("default"))) void tee_task_entry(int init_build)
{
    tloge("start of art service task\n");
    tee_common_task_entry(init_build, ART_TASK_NAME);
}
