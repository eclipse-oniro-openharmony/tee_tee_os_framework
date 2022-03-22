/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Secure flash msg communication management.
 * Author: tianjianliang
 * Create: 2019-08-19
 * Notes:
 * History: 2019-08-19 tianjianliang create
 *          2019-08-27 chengruhong add secflash_mm_call_xxx functions.
 *          2019-09-20 shenwei add secflash_scp03_init function to service_init
 */
#include <msg_ops.h>
#include "securec.h"
#include "tee_log.h"
#include "sre_access_control.h"
#include "string.h"
#include "tee_service_public.h"
#include "tee_commom_public_service.h"
#include "sec_flash_public.h"
#ifdef HISI_MSP_SECFLASH
#include "hisi_mspc.h"
#include "msp/secflash_sa_comm.h"
#include "tee_internal_se_api.h"
#include "sre_syscalls_ext.h"
#else
#include "secflash_service_init.h"
#include "secflash_mm.h"
#include "secflash_scp03_comm.h"
#include "sec_flash_ext_msg.h"
#endif

#define IS_NEGATIVE 1

/* The current accessing TEE_UUID. */
static TEE_UUID g_cur_uuid = {0};

/*
 * @brief     : Check the msg and rsp validity. Obtain current TEE_UUID.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
TEE_Result secflash_call_prepare(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;

#ifndef HISI_MSP_SECFLASH
    secflash_service_init();
#endif
    if (rsp == NULL) {
        tloge("%s, invalid parameters!\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (msg == NULL) {
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
 * @brief     : Unpack incoming message. Call secflash_mm_alloc. Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_mm_call_alloc(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;
    uint32_t size;
    uint32_t mem_type;
    uint32_t obj_id;
    struct object_info obj_info;

    ret = secflash_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return;
    }
#ifdef HISI_MSP_SECFLASH
    size = (uint32_t)msg->args_data.arg0;
    mem_type = (uint32_t)msg->args_data.arg1;
    obj_id = (uint32_t)msg->args_data.arg2;
    obj_info.mem_type = (uint8_t)mem_type;
    obj_info.obj_id = (uint8_t)obj_id;
    obj_info.uuid = &g_cur_uuid;

    ret = secflash_sa_alloc(obj_info, size);
    rsp->ret = ret;
#else /* Phoenix C20 */
    secflash_mm_set_current_uuid(&g_cur_uuid);
    size = (uint32_t)msg->args_data.arg0;
    mem_type = (uint32_t)msg->args_data.arg1;
    obj_id = (uint32_t)msg->args_data.arg2;
    obj_info.mem_type = mem_type;
    obj_info.obj_id = obj_id;

    ret = (TEE_Result)secflash_mm_alloc(obj_info, size);
    rsp->ret = ret;
    secflash_mm_set_current_uuid(NULL);
#endif
}

/*
 * @brief     : Unpack incoming message. Call secflash_mm_select. Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_mm_call_open(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;
    uint32_t mem_type;
    uint32_t obj_id;
    uint32_t size;
    struct object_info obj_info;

    ret = secflash_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return;
    }

#ifdef HISI_MSP_SECFLASH
    mem_type = (uint32_t)msg->args_data.arg0;
    obj_id = (uint32_t)msg->args_data.arg1;
    obj_info.mem_type = (uint8_t)mem_type;
    obj_info.obj_id = (uint8_t)obj_id;
    obj_info.uuid = &g_cur_uuid;

    ret = secflash_sa_select(obj_info, &size, sizeof(size));
    rsp->ret = ret;
    if (ret == TEE_SUCCESS)
        rsp->msg.args_data.arg0 = size;

#else /* Phoenix C20 */
    secflash_mm_set_current_uuid(&g_cur_uuid);
    mem_type = (uint32_t)msg->args_data.arg0;
    obj_id = (uint32_t)msg->args_data.arg1;
    obj_info.mem_type = mem_type;
    obj_info.obj_id = obj_id;

    ret = (TEE_Result)secflash_mm_select(obj_info, &size);

    rsp->ret = ret;
    if (ret == TEE_SUCCESS) {
        rsp->msg.args_data.arg0 = size;
    }

    secflash_mm_set_current_uuid(NULL);
#endif
}

/*
 * @brief     : Unpack incoming message. Call secflash_mm_read. Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_mm_call_read(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    int res;
    TEE_Result ret;
    uint32_t offset;
    uint32_t size;
    uint8_t *buffer = NULL;
    uint32_t count;
    struct object_info obj_info;

    ret = secflash_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return;
    }

#ifdef HISI_MSP_SECFLASH
    offset = (uint32_t)msg->args_data.arg0;
    size = (uint32_t)msg->args_data.arg1;
    obj_info.mem_type = (uint8_t)msg->args_data.arg2;
    obj_info.obj_id = (uint8_t)msg->args_data.arg4;
    obj_info.uuid = &g_cur_uuid;

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg3,
        size, (uint32_t *)&buffer);
    if (res != TEE_SUCCESS) {
        tloge("%s, map failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    ret = secflash_sa_read(obj_info, offset, size, buffer, &count);
    rsp->ret = ret;
    if (ret == TEE_SUCCESS)
        rsp->msg.args_data.arg0 = count;

    tee_unmap_from_task((uint32_t)(uintptr_t)buffer, size);
#else /* Phoenix C20 */
    secflash_mm_set_current_uuid(&g_cur_uuid);
    if (msg->args_data.arg3 == 0) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        secflash_mm_set_current_uuid(NULL);
        return;
    }

    offset = (uint32_t)msg->args_data.arg0;
    size = (uint32_t)msg->args_data.arg1;
    obj_info.mem_type = (uint32_t)msg->args_data.arg2;
    obj_info.obj_id = (uint32_t)msg->args_data.arg4;

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg3,
        size, (uint32_t *)&buffer);
    if (res != 0) {
        tloge("%s, map failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        secflash_mm_set_current_uuid(NULL);
        return;
    }

    ret = (TEE_Result)secflash_mm_read(obj_info, offset, size, buffer, &count);

    rsp->ret = ret;
    if (ret == TEE_SUCCESS)
        rsp->msg.args_data.arg0 = count;

    secflash_mm_set_current_uuid(NULL);
    tee_unmap_from_task((uint32_t)(uintptr_t)buffer, size);
#endif
}

/*
 * @brief     : Unpack incoming message. Call secflash_mm_write. Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_mm_call_write(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    int res;
    TEE_Result ret;
    uint32_t postion;
    uint32_t size;
    struct object_info obj_info;
    uint8_t *buffer = NULL;

    ret = secflash_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return;
    }

#ifdef HISI_MSP_SECFLASH
    postion = (uint32_t)msg->args_data.arg0;
    size = (uint32_t)msg->args_data.arg1;
    obj_info.mem_type = (uint8_t)msg->args_data.arg2;
    obj_info.obj_id = (uint8_t)msg->args_data.arg4;
    obj_info.uuid = &g_cur_uuid;

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg3,
        size, (uint32_t *)&buffer);
    if (res != TEE_SUCCESS) {
        tloge("%s, map failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        return;
    }

    ret = secflash_sa_write(obj_info, postion, size, buffer);
    tee_unmap_from_task((uint32_t)(uintptr_t)buffer, size);
    rsp->ret = ret;
#else /* Phoenix C20 */
    secflash_mm_set_current_uuid(&g_cur_uuid);
    if (msg->args_data.arg3 == 0) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        secflash_mm_set_current_uuid(NULL);
        return;
    }

    postion = (uint32_t)msg->args_data.arg0;
    size = (uint32_t)msg->args_data.arg1;
    obj_info.mem_type = (uint32_t)msg->args_data.arg2;
    obj_info.obj_id = (uint32_t)msg->args_data.arg4;

    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg3,
        size, (uint32_t *)&buffer);
    if (res != 0) {
        tloge("%s, map failed, %d\n", __func__, res);
        rsp->ret = TEE_ERROR_GENERIC;
        secflash_mm_set_current_uuid(NULL);
        return;
    }

    ret = (TEE_Result)secflash_mm_write(obj_info, postion, size, buffer);
    secflash_mm_set_current_uuid(NULL);
    tee_unmap_from_task((uint32_t)(uintptr_t)buffer, size);
    rsp->ret = ret;
#endif
}

/*
 * @brief     : Unpack incoming message. Call secflash_mm_set_offset. Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_mm_call_seek(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;
    uint32_t position;
    int32_t offset;
    uint32_t obj_id;
    uint32_t mem_type;
    TEE_Whence whence;
    struct object_info obj_info;

    ret = secflash_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return;
    }

#ifdef HISI_MSP_SECFLASH
    position = (uint32_t)msg->args_data.arg0;
    offset = (uint32_t)msg->args_data.arg2;
    if ((uint32_t)msg->args_data.arg1 == IS_NEGATIVE)
        offset = -offset;

    mem_type = (uint32_t)msg->args_data.arg3;
    whence = (TEE_Whence)msg->args_data.arg4;
    obj_id = (uint32_t)msg->args_data.arg5;
    obj_info.mem_type = (uint8_t)mem_type;
    obj_info.obj_id = (uint8_t)obj_id;
    obj_info.uuid = &g_cur_uuid;

    ret = secflash_sa_set_offset(obj_info, &position, offset, whence);
    rsp->ret = ret;
    if (ret == TEE_SUCCESS)
        rsp->msg.args_data.arg0 = position;

#else /* Phoenix C20 */
    secflash_mm_set_current_uuid(&g_cur_uuid);
    position = (uint32_t)msg->args_data.arg0;
    offset = (uint32_t)msg->args_data.arg2;
    if ((uint32_t)msg->args_data.arg1 == IS_NEGATIVE)
        offset = -offset;

    mem_type = (uint32_t)msg->args_data.arg3;
    whence = (TEE_Whence)msg->args_data.arg4;
    obj_id = (uint32_t)msg->args_data.arg5;
    obj_info.mem_type = mem_type;
    obj_info.obj_id = obj_id;

    ret = (TEE_Result)secflash_mm_set_offset(obj_info, &position, offset, whence);

    rsp->ret = ret;
    if (ret == TEE_SUCCESS)
        rsp->msg.args_data.arg0 = position;

    secflash_mm_set_current_uuid(NULL);
#endif
}

/*
 * @brief     : Unpack incoming message. Call secflash_mm_free. Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_mm_call_free(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;
    uint32_t obj_id;
    uint32_t mem_type;
    struct object_info obj_info;

    ret = secflash_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return;
    }

#ifdef HISI_MSP_SECFLASH
    mem_type = (uint32_t)msg->args_data.arg0;
    obj_id = (uint32_t)msg->args_data.arg1;
    obj_info.mem_type = (uint8_t)mem_type;
    obj_info.obj_id = (uint8_t)obj_id;
    obj_info.uuid = &g_cur_uuid;

    rsp->ret = secflash_sa_free(obj_info);
#else /* Phoenix C20 */
    secflash_mm_set_current_uuid(&g_cur_uuid);
    mem_type = (uint32_t)msg->args_data.arg0;
    obj_id = (uint32_t)msg->args_data.arg1;
    obj_info.mem_type = mem_type;
    obj_info.obj_id = obj_id;

    rsp->ret = (TEE_Result)secflash_mm_free(obj_info);
    secflash_mm_set_current_uuid(NULL);
#endif
}

/*
 * @brief     : Unpack incoming msg. Call secflash_mm_get_info. Pack response.
 * @param[in] : msg, Incoming message.
 * @param[in] : sender, The sender of this call.
 * @param[out]: rsp, Response message.
 * @return    : void.
 */
void secflash_mm_call_get_info(const tee_service_ipc_msg *msg, uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
    TEE_Result ret;
    uint32_t obj_id;
    uint32_t mem_type;
    uint32_t origin_pos;
    uint32_t pos;
    uint32_t len;
    struct object_info obj_info;

    ret = secflash_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS)
        return;

#ifdef HISI_MSP_SECFLASH
    mem_type = (uint32_t)msg->args_data.arg0;
    origin_pos = (uint32_t)msg->args_data.arg1;
    obj_id = (uint32_t)msg->args_data.arg2;
    obj_info.mem_type = (uint8_t)mem_type;
    obj_info.obj_id = (uint8_t)obj_id;
    obj_info.uuid = &g_cur_uuid;

    ret = secflash_sa_get_info(obj_info, origin_pos, &pos, &len);

    rsp->ret = ret;
    if (ret == TEE_SUCCESS) {
        rsp->msg.args_data.arg0 = pos;
        rsp->msg.args_data.arg1 = len;
    }
#else /* Phoenix C20 */
    secflash_mm_set_current_uuid(&g_cur_uuid);
    mem_type = (uint32_t)msg->args_data.arg0;
    origin_pos = (uint32_t)msg->args_data.arg1;
    obj_id = (uint32_t)msg->args_data.arg2;
    obj_info.mem_type = mem_type;
    obj_info.obj_id = obj_id;

    ret = (TEE_Result)secflash_mm_get_info(obj_info, origin_pos, &pos, &len);

    rsp->ret = ret;
    if (ret == TEE_SUCCESS) {
        rsp->msg.args_data.arg0 = pos;
        rsp->msg.args_data.arg1 = len;
    }
    secflash_mm_set_current_uuid(NULL);
#endif
}

#ifdef HISI_MSP_SECFLASH
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

    ret = secflash_call_prepare(msg, sender, rsp);
    if (ret != TEE_SUCCESS) {
        tloge("%s, call_prepare failed\n", __func__);
        return;
    }

    len = sizeof(uint32_t);
    res = tee_map_from_task(sender, (uint32_t)(uintptr_t)msg->args_data.arg0, len, (uint32_t *)&status_info);
    if (res != 0) {
        tloge("%s, map failed, %d\n", __func__, res);
        ret = TEE_ERROR_GENERIC;
        goto error_ret_handle;
    }

    ret = __hisi_mspc_check_secflash(status_info);
    if (ret != TEE_SUCCESS) {
        tloge("%s call driver failed:ret=%x\n", __func__, ret);
        goto unmap_restore;
    }

unmap_restore:
    tee_unmap_from_task((uint32_t)(uintptr_t)status_info, len);
error_ret_handle:
    rsp->ret = ret;
}
#endif

static tee_service_cmd g_sec_flash_cmd_tbl[] = {
    /* cmd,                        need_ack             fn */
    { SEC_FLASH_MSG_MM_CREATE_CMD,              secflash_mm_call_alloc },
    { SEC_FLASH_MSG_MM_DELETE_CMD,              secflash_mm_call_free },
    { SEC_FLASH_MSG_MM_OPEN_CMD,                secflash_mm_call_open },
    { SEC_FLASH_MSG_MM_SEEK_CMD,                secflash_mm_call_seek },
    { SEC_FLASH_MSG_MM_READ_CMD,                secflash_mm_call_read },
    { SEC_FLASH_MSG_MM_WRITE_CMD,               secflash_mm_call_write },
    { SEC_FLASH_MSG_MM_GET_INFO_CMD,            secflash_mm_call_get_info },
#ifndef HISI_MSP_SECFLASH /* Phoenix C20 */
    { SEC_FLASH_MSG_EXT_FACTORY_RECOVERY_CMD,   secflash_ext_call_factory_recovery },
    { SEC_FLASH_MSG_EXT_POWER_SAVING_CMD,       secflash_ext_call_power_saving },
    { SEC_FLASH_MSG_EXT_RESET_CMD,              secflash_ext_call_device_reset },
    { SEC_FLASH_MSG_EXT_BINDING_KEY_CMD,        secflash_ext_call_derive_binding_key },
    { SEC_FLASH_MSG_EXT_WRITE_LOCK_CMD,         secflash_ext_call_writelock_cfg },
#endif
    { SEC_FLASH_MSG_EXT_IS_AVAILABLE_CMD,       secflash_ext_call_is_available },
};
static uint32_t g_sec_flash_cmd_num = sizeof(g_sec_flash_cmd_tbl) / sizeof(g_sec_flash_cmd_tbl[0]);

uint32_t tee_service_init(void)
{
#ifndef HISI_MSP_SECFLASH
    /* Phoenix C20 */
    secflash_service_reset_init_flag();
#endif
    return TEE_SUCCESS;
}

void tee_service_handle(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp,
    uint32_t cmd)
{
    uint32_t i;

    if (rsp == NULL)
        return;
    if (msg == NULL) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        return;
    }

    for (i = 0; i < g_sec_flash_cmd_num; i++) {
        if (cmd != g_sec_flash_cmd_tbl[i].cmd)
            continue;
        if (g_sec_flash_cmd_tbl[i].fn != NULL)
            g_sec_flash_cmd_tbl[i].fn(msg, task_id, rsp);
    }

    return;
}

#ifdef CONFIG_DYNLINK
__attribute__((section(".magic")))
const char magic_string[20] = "Dynamically linked.";
#endif

/*
TA's main func
*/
__attribute__((visibility ("default"))) void tee_task_entry(int init_build)
{
    tloge("start of sec flash task----------------------------------------\n");
    tee_common_task_entry(init_build, SEC_FLASH_TASK_NAME);
}
