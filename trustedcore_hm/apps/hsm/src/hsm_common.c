/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm key managerment source file
* Author: huawei
* Create: 2020/1/18
*/
#include <sys/mman.h>
#include <msg_ops.h>
#include <mem_ops_ext.h>
#include "tee_ext_api.h"
#include "tee_object_api.h"
#include "tee_crypto_api.h"
#include "tee_commom_public_service.h"
#include "tee_log.h"
#include "sre_syscall.h"
#include "securec.h"
#include "scmi_lib_api.h"
#include "hsm_command.h"
#include "hsm_service.h"
#include "hsm_common.h"

uint32_t hsm_clear_hsm_data(HSM_COMMAND *hsm_cmd, HSM_BACK_DATA *hsm_back_data)
{
    int32_t ret;

    ret = memset_s(hsm_cmd, sizeof(HSM_COMMAND), 0x0, sizeof(HSM_COMMAND));
    if (ret != EOK) {
        tloge("memset hsm_cmd failed!\n");
        return TEE_FAIL;
    }

    ret = memset_s(hsm_back_data, sizeof(HSM_BACK_DATA), 0x0, sizeof(HSM_BACK_DATA));
    if (ret != EOK) {
        tloge("memset hsm_back_data failed!\n");
        return TEE_FAIL;
    }

    return TEE_SUCCESS;
}

uint32_t hsm_ddr_total_len(const tee_service_ipc_msg *msg)
{
    return ((uint32_t)(msg->args_data.arg2 >> SHIFT_CONST_NUM_32) + (uint32_t)(msg->args_data.arg2) +
        (uint32_t)(msg->args_data.arg3 >> SHIFT_CONST_NUM_32) + (uint32_t)(msg->args_data.arg3) +
        (uint32_t)(msg->args_data.arg4 >> SHIFT_CONST_NUM_32) + (uint32_t)(msg->args_data.arg4) +
        (uint32_t)(msg->args_data.arg5 >> SHIFT_CONST_NUM_32) + (uint32_t)(msg->args_data.arg5));
}

static void hsm_data_len_back_to_client(const HSM_BACK_DATA *hsm_back_data, tee_service_ipc_msg_rsp *rsp)
{
    rsp->msg.args_data.arg2 = ((uint64_t)hsm_back_data->param_len_0 << SHIFT_CONST_NUM_32) + hsm_back_data->param_len_1;
    rsp->msg.args_data.arg3 = ((uint64_t)hsm_back_data->param_len_2 << SHIFT_CONST_NUM_32) + hsm_back_data->param_len_3;
    rsp->msg.args_data.arg4 = ((uint64_t)hsm_back_data->param_len_4 << SHIFT_CONST_NUM_32) + hsm_back_data->param_len_5;
    rsp->msg.args_data.arg5 = ((uint64_t)hsm_back_data->param_len_6 << SHIFT_CONST_NUM_32) + hsm_back_data->param_len_7;
}

STATIC uint32_t hsm_get_ta_index_by_task_id(uint32_t dev_id, uint32_t task_id, uint32_t *ta_index)
{
    uint32_t uuid[TA_ID_LEN_FOUR_WORD];
    TEE_Result ret;
    uint32_t i;

    /* change into uuid */
    ret = tee_common_get_uuid_by_sender(task_id, (TEE_UUID *)uuid, TA_ID_LEN_FOUR_WORD * sizeof(uint32_t));
    if (ret != TEE_SUCCESS) {
        tloge("task_id change into uuid failed!\n");
        return ret;
    }

    for (i = 0; i < TA_MAX_NUM; i++) {
        ret = memcmp(g_ta_keys[dev_id][i].ta_id, uuid, TA_ID_LEN_FOUR_WORD * sizeof(uint32_t));
        if (ret == 0) { /* equal */
            *ta_index = i;
            return TEE_SUCCESS;
        }
    }

    tloge("ta function don't support!\n");
    return TEE_ERROR_SERVICE_NOT_EXIST;
}

uint32_t hsm_find_ta_index(uint32_t dev_id, uint32_t task_id, HSM_COMMAND *hsm_cmd, uint32_t mainkey_cnt)
{
    uint32_t ret;
    uint32_t ta_index = TA_MAX_NUM;

    ret = hsm_get_ta_index_by_task_id(dev_id, task_id, &ta_index);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    /* config cnt&td_id */
    hsm_cmd->ta_index = ta_index;
    ret = (uint32_t)memcpy_s(hsm_cmd->ta_id, TA_ID_LEN_FOUR_WORD * LEN_OF_4BYTES,
                             g_ta_keys[dev_id][ta_index].ta_id, TA_ID_LEN_FOUR_WORD * sizeof(uint32_t));
    if (ret != EOK) {
        tloge("cpy ta_id failed!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    if (mainkey_cnt != 0) { /* use mainkey's cnt */
        hsm_cmd->cnt = g_main_key[dev_id].cnt;
    } else {
        hsm_cmd->cnt = g_ta_keys[dev_id][ta_index].cnt;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t as_hmac_calc(AS_HMAC_S *hmac_info)
{
    uint32_t ret;
    TEE_OperationHandle op = (TEE_OperationHandle)NULL;
    TEE_ObjectHandle hmac_key = (TEE_ObjectHandle)NULL;
    TEE_Attribute attrib = {0};
    size_t hmac_size = (size_t)(uintptr_t)hmac_info->key_len;
    uint32_t key_size;

    key_size = (hmac_info->key_len) << CONST_NUMBER_3;

    ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, key_size, &hmac_key);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to alloc transient object handle, 0x%x\n", ret);
        return TEE_ERROR_MAC_INVALID;
    }

    TEE_InitRefAttribute(&attrib, TEE_ATTR_SECRET_VALUE, (void *)hmac_info->c_key, hmac_info->key_len);
    ret = TEE_PopulateTransientObject(hmac_key, &attrib, 1);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to populate key, 0x%x\n", ret);
        goto free_obj;
    }

    ret = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, key_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to alloc sign operation handle, 0x%x", ret);
        goto free_obj;
    }

    ret = TEE_SetOperationKey(op, hmac_key);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to set sign operation key, 0x%x", ret);
        goto free_opertion;
    }

    TEE_MACInit(op, NULL, 0);

    TEE_MACUpdate(op, hmac_info->cmd_data, hmac_info->cmd_data_len);

    ret = TEE_MACComputeFinal(op, hmac_info->ddr_data, hmac_info->ddr_data_len,
        hmac_info->result, &hmac_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to compute hmac, 0x%x!\n", ret);
    }

free_opertion:
    TEE_FreeOperation(op);
free_obj:
    TEE_FreeTransientObject(hmac_key);
    return ret;
}

STATIC uint32_t as_hmac_main_key(uint32_t dev_id, AS_HMAC_S *hmac_info)
{
    if (hmac_info == NULL) {
        tloge("hmac_info is NULL\n");
        return TEE_ERROR_READ_DATA;
    }

    hmac_info->c_key = g_main_key[dev_id].main_key;
    hmac_info->key_len = HMAC_KEY_LEN_32;

    return as_hmac_calc(hmac_info);
}

STATIC uint32_t as_hmac_ta_key(uint32_t dev_id, AS_HMAC_S *hmac_info, uint32_t ta_index)
{
    if (hmac_info == NULL) {
        tloge("hmac_info is NULL!\n");
        return TEE_ERROR_READ_DATA;
    }

    hmac_info->c_key = g_ta_keys[dev_id][ta_index].ta_key;
    hmac_info->key_len = HMAC_TA_KEY_LEN;

    return as_hmac_calc(hmac_info);
}

/* calculate hmac with main key or ta key */
uint32_t service_calc_hmac(uint32_t dev_id, uint32_t hmac_key, const SERVICE_INFO_S *service_info,
    uint8_t *result, uint32_t dir)
{
    AS_HMAC_S hmac_info;
    uint32_t ta_index;

    if (dir == HMAC_INPUT) {
        hmac_info.cmd_data = (uint8_t *)service_info->p_in_msg;
        hmac_info.cmd_data_len = sizeof(HSM_COMMAND) - SERVICE_HMAC_LEN;
        hmac_info.ddr_data = service_info->in_buf;
        hmac_info.ddr_data_len = service_info->p_in_msg->ddr_data_len;
        ta_index = service_info->p_in_msg->ta_index;
    } else {
        hmac_info.cmd_data = (uint8_t *)service_info->p_out_msg;
        hmac_info.cmd_data_len = sizeof(HSM_BACK_DATA) - SERVICE_HMAC_LEN;
        hmac_info.ddr_data = service_info->out_buf;
        hmac_info.ddr_data_len = service_info->p_out_msg->ddr_data_len;
        ta_index = service_info->p_out_msg->ta_index;
    }

    hmac_info.result = result;
    if (hmac_key == SERVICE_HMAC_NONE) {
        return TEE_SUCCESS;
    } else if (hmac_key == SERVICE_HMAC_KEY1) {
        return as_hmac_main_key(dev_id, &hmac_info);
    } else {
        return as_hmac_ta_key(dev_id, &hmac_info, ta_index);
    }
}

/* verify hmac with main key or ta key */
uint32_t service_verify_hmac(uint32_t dev_id, uint32_t hmac_key, HSM_BACK_DATA *hsm_back,
    uint64_t data_addr)
{
    uint32_t ret;
    uint32_t i;
    uint32_t hmac_result[SERVICE_HMAC_WORD_LEN] = {0};
    SERVICE_INFO_S service_info = {0};

    if (hmac_key == SERVICE_HMAC_NONE) {
        return TEE_SUCCESS;
    }

    service_info.out_buf = (uint8_t *)(uintptr_t)data_addr;
    service_info.p_out_msg = hsm_back;
    service_info.p_out_msg->ddr_data_len = hsm_back->ddr_data_len;

    /* calc hmac */
    ret = service_calc_hmac(dev_id, hmac_key, &service_info, (uint8_t *)hmac_result,
        HMAC_OUTPUT);
    if (ret != TEE_SUCCESS) {
        tloge("calc hmac failed, 0x%x\n!", ret);
        return ret;
    }

    /* compare hmac between result with input hmac */
    for (i = 0; i < SERVICE_HMAC_WORD_LEN; i++) {
        if (hmac_result[i] != hsm_back->hmac[i]) {
            tloge("hmac incompative\n");
            return TEE_ERROR_MAC_INVALID;
        }
    }

    return TEE_SUCCESS;
}

static void hsm_common_cmd_assign_value(HSM_COMMAND *hsm_cmd, const FILL_PART_HSM_DATA *part_hsm_data,
    const tee_service_ipc_msg *msg, SERVICE_INFO_S *service_info, uint64_t dest_vaddr)
{
    hsm_cmd->addr_addr_h = part_hsm_data->addr_addr_h;
    hsm_cmd->addr_addr_l = part_hsm_data->addr_addr_l;
    hsm_cmd->cmd = part_hsm_data->cmd;
    hsm_cmd->ddr_para_num = part_hsm_data->ddr_para_num;
    hsm_cmd->ddr_data_len = part_hsm_data->ddr_data_len;
    hsm_cmd->param_len_0 = (uint32_t)(msg->args_data.arg2 >> SHIFT_CONST_NUM_32); /* high 32bit */
    hsm_cmd->param_len_1 = (uint32_t)msg->args_data.arg2; /* low 32bit */
    hsm_cmd->param_len_2 = (uint32_t)(msg->args_data.arg3 >> SHIFT_CONST_NUM_32);
    hsm_cmd->param_len_3 = (uint32_t)msg->args_data.arg3;
    hsm_cmd->param_len_4 = (uint32_t)(msg->args_data.arg4 >> SHIFT_CONST_NUM_32);
    hsm_cmd->param_len_5 = (uint32_t)msg->args_data.arg4;
    hsm_cmd->param_len_6 = (uint32_t)(msg->args_data.arg5 >> SHIFT_CONST_NUM_32);
    hsm_cmd->param_len_7 = (uint32_t)msg->args_data.arg5;

    service_info->in_buf = (uint8_t *)(uintptr_t)dest_vaddr;
    service_info->p_in_msg = hsm_cmd;
}

STATIC uint32_t hsm_write_msg_to_shm(uint32_t task_id, uint64_t dest_shm_vaddr,
    uint64_t buf_addr, uint64_t buf_size)
{
    int32_t ret;
    uint64_t hsm_vm_addr = 0;

    ret = tee_map_from_task(task_id, buf_addr, buf_size, (uint32_t *)&hsm_vm_addr);
    if (ret != TEE_SUCCESS) {
        tloge("ta task vaddr map to service task vaddr failed!\n");
        return (uint32_t)ret;
    }

    ret = memcpy_s((void *)(uintptr_t)dest_shm_vaddr, HSM_TEE_DDR_BLOCK_SIZE,
                   (const void *)(uintptr_t)hsm_vm_addr, buf_size);
    if (ret != EOK) {
        tloge("copy msg failed!\n");
        ret = munmap((void *)(uintptr_t)hsm_vm_addr, buf_size);
        if (ret != TEE_SUCCESS) {
            tloge("unmap service task vaddr failed!\n");
        }
        return TEE_ERROR_WRITE_DATA;
    }

    ret = munmap((void *)(uintptr_t)hsm_vm_addr, buf_size);
    if (ret != TEE_SUCCESS) {
        tloge("unmap service task vaddr failed!\n");
        return (uint32_t)ret;
    }

    return TEE_SUCCESS;
}

uint32_t hsm_fill_scmi_msg(uint32_t dev_id, const tee_service_ipc_msg *msg, uint32_t task_id, HSM_COMMAND *hsm_cmd,
    FILL_PART_HSM_DATA part_hsm_data, uint64_t *data_addr)
{
    uint32_t ret;
    uint64_t dest_vaddr;
    uint32_t hmac_key;
    uint8_t hmac_result[SERVICE_HMAC_LEN] = {0};
    SERVICE_INFO_S service_info = {0};

    ret = hsm_find_ta_index(dev_id, task_id, hsm_cmd, part_hsm_data.mainkey_cnt);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    dest_vaddr = g_hsm_tee_smem_start_vaddr[dev_id] +
        part_hsm_data.addr_addr_l - HSM_TEE_SHARE_DDR_PHY_ADDR;
    if (msg->args_data.arg0 != 0) {
        ret = hsm_write_msg_to_shm(task_id, dest_vaddr, msg->args_data.arg0, msg->args_data.arg1);
        if (ret != TEE_SUCCESS) {
            return ret;
        }
    }

    hsm_common_cmd_assign_value(hsm_cmd, &part_hsm_data, msg, &service_info, dest_vaddr);

    if ((hsm_cmd->cmd & HSM_TA_CMD_MASK) == HSM_MAIN_KEY_TA_CMD) {
        hmac_key = SERVICE_HMAC_KEY1;
    } else {
        hmac_key = SERVICE_HMAC_KEY2;
    }

    ret = service_calc_hmac(dev_id, hmac_key, &service_info, hmac_result, HMAC_INPUT);
    if (ret != TEE_SUCCESS) {
        tloge("service calc hmac failed, 0x%x!\n", ret);
        return ret;
    }

    ret = (uint32_t)memcpy_s((void *)(hsm_cmd->hmac), SERVICE_HMAC_LEN, (const void *)hmac_result, SERVICE_HMAC_LEN);
    if (ret != EOK) {
        tloge("mem cpy failed!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    *data_addr = dest_vaddr;

    return TEE_SUCCESS;
}

uint32_t hsm_service_to_hiss(uint32_t dev_id, HSM_COMMAND *hsm_cmd, HSM_BACK_DATA *hsm_back_data, uint32_t channel)
{
    uint32_t ret;
    uint32_t channel_state;

    /* open channel */
    ret = lib_scmi_channel_open(dev_id, channel);
    if (ret != SCMI_LIB_RESULT_SUCCESS) {
        tloge("channel open failed, 0x%x\n", ret);
        return ret;
    }

    /* send data */
    ret = lib_scmi_channel_send_data(dev_id, channel, (uint8_t *)hsm_cmd, sizeof(HSM_COMMAND));
    if (ret != SCMI_LIB_RESULT_SUCCESS) {
        tloge("channel send data failed, 0x%x\n", ret);
        goto CloseChannel;
    }

    /* get & check data */
    ret = lib_scmi_check_task_and_get_data(dev_id, channel, (uint8_t *)hsm_back_data, sizeof(HSM_BACK_DATA));
    if (ret != SCMI_LIB_RESULT_SUCCESS) {
        tloge("check & get data failed, 0x%x\n", ret);
        goto CloseChannel;
    }

    if (hsm_back_data->process_result != HSM_PROCESS_SUCCESS) {
        tloge("hsm process failed! state=0x%x\n", hsm_back_data->process_result);
        ret = TEE_FAIL;
    }

CloseChannel:
    /* close channel */
    channel_state = lib_scmi_channel_close(dev_id, channel);
    if (channel_state != SCMI_LIB_RESULT_SUCCESS) {
        ret = channel_state;
        tloge("channel close failed, 0x%x\n", channel_state);
    }

    return ret;
}

uint32_t hsm_update_ta_cnt(uint32_t dev_id, uint32_t task_id)
{
    uint32_t ta_index;
    uint32_t ret;

    ret = hsm_get_ta_index_by_task_id(dev_id, task_id, &ta_index);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    /* update ta cnt */
    g_ta_keys[dev_id][ta_index].cnt++;

    return TEE_SUCCESS;
}

uint32_t hsm_common_process(uint32_t dev_id, const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp, FILL_PART_HSM_DATA part_hsm_data)
{
    HSM_COMMAND hsm_cmd;
    HSM_BACK_DATA hsm_back_data;
    uint32_t state;
    uint64_t data_addr;
    uint32_t hmac_key;

    (void)rsp;

    /* clear data */
    state = hsm_clear_hsm_data(&hsm_cmd, &hsm_back_data);
    if (state != TEE_SUCCESS) {
        tloge("clear data failed!\n");
        return state;
    }

    /* fill scmi msg */
    state = hsm_fill_scmi_msg(dev_id, msg, task_id, &hsm_cmd, part_hsm_data, &data_addr);
    if (state != TEE_SUCCESS) {
        tloge("hsm fill scmi msg failed!\n");
        return state;
    }

    /* send data to hiss */
    state = hsm_service_to_hiss(dev_id, &hsm_cmd, &hsm_back_data, part_hsm_data.channel_num);
    if (state != TEE_SUCCESS) {
        tloge("service to hiss failed!\n");
        return state;
    }

    if ((hsm_cmd.cmd & HSM_TA_CMD_MASK) == HSM_MAIN_KEY_TA_CMD) {
        hmac_key = SERVICE_HMAC_KEY1;
    } else {
        hmac_key = SERVICE_HMAC_KEY2;
    }

    state = service_verify_hmac(dev_id, hmac_key, &hsm_back_data, data_addr);
    if (state != TEE_SUCCESS) {
        tloge("service verify hmac failed!\n");
        return state;
    }

    /* hsm data len back to client */
    hsm_data_len_back_to_client(&hsm_back_data, rsp);

    return TEE_SUCCESS;
}

uint32_t hsm_data_back_to_client(const tee_service_ipc_msg *msg, const uint8_t *src, uint32_t task_id)
{
    uint64_t hsm_vm_addr;
    uint32_t hsm_vm_len = msg->args_data.arg1;
    int32_t ret;

    if (msg->args_data.arg1 != HSM_CLENT_MSG_LEN) {
        tloge("err ipc msg len in hsm service!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    if (msg->args_data.arg0 == 0) { /* No data need to copy back */
        return TEE_SUCCESS;
    }

    ret = tee_map_from_task(task_id, msg->args_data.arg0, msg->args_data.arg1, (uint32_t *)&hsm_vm_addr);
    if (ret != TEE_SUCCESS) {
        tloge("ta task vaddr map to service task vaddr failed!\n");
        return (uint32_t)ret;
    }

    ret = memcpy_s((void *)(uintptr_t)hsm_vm_addr, hsm_vm_len, (const void *)src, msg->args_data.arg1);
    if (ret != EOK) {
        tloge("service back to client, mem cpy failed!\n");
        ret = munmap((const void *)(uintptr_t)hsm_vm_addr, msg->args_data.arg1);
        if (ret != TEE_SUCCESS) {
            tloge("unmap service task vaddr failed!\n");
        }
        return TEE_ERROR_WRITE_DATA;
    }

    ret = munmap((const void *)(uintptr_t)hsm_vm_addr, msg->args_data.arg1);
    if (ret != TEE_SUCCESS) {
        tloge("unmap service task vaddr failed!\n");
        return (uint32_t)ret;
    }

    return TEE_SUCCESS;
}

uint32_t hsm_process_task_main(const tee_service_ipc_msg *msg, uint32_t task_id,
                               tee_service_ipc_msg_rsp *rsp,
                               FILL_PART_HSM_DATA *part_hsm_data)
{
    uint32_t ret;
    uint8_t *src = NULL;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;
    uint32_t task_start_addr = part_hsm_data->addr_addr_l;

    /* update ta cnt */
    ret = hsm_update_ta_cnt(dev_id, task_id);
    if (ret != TEE_SUCCESS) {
        tloge("hsm update ta cnt failed!\n");
        return ret;
    }

    ret = hsm_common_process(dev_id, msg, task_id, rsp, *part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm process failed!\n");
        return ret;
    }

    /* copy data back to client */
    src = (uint8_t *)(uintptr_t)(g_hsm_tee_smem_start_vaddr[dev_id] +
                                 task_start_addr - HSM_TEE_SHARE_DDR_PHY_ADDR);
    ret = hsm_data_back_to_client(msg, src, task_id);
    if (ret != TEE_SUCCESS) {
        tloge("hsm send response to client failed!\n");
        return ret;
    }

    return TEE_SUCCESS;
}
