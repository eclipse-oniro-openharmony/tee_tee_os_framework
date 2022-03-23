/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm service source file
* Author: huawei
* Create: 2020/1/8
*/
#include "tee_log.h"
#include "tee_obj.h"
#include "tee_commom_public_service.h"

#include "securec.h"
#include "msg_ops.h"

#include "hsm_ipc_command.h"
#include "scmi_lib_api.h"
#include "hsm_command.h"
#include "hsm_service.h"
#include "hsm_km.h"
#include "hsm_counter.h"
#include "hsm_crypto.h"
#include "hsm_common.h"
#include "hsm_rpmb.h"
#include "hsm_verify.h"
#include "hsm_service_fuzz.h"
#include "hsm_efuse.h"
#include "hsm_update_lib_api.h"

MAIN_KEY_INFO g_main_key[DEVICE_NUM];
TA_KEY_INFO g_ta_keys[DEVICE_NUM][TA_MAX_NUM];
uint64_t g_hsm_tee_smem_start_vaddr[DEVICE_NUM] = { 0 };
static uint32_t g_hsm_service_status = 1;
static uint32_t g_dev_id_max = 0;

STATIC uint32_t hsm_service_data_clear(uint32_t dev_id)
{
    uint32_t ret;
    uint32_t *ptr_uuid = NULL;

    /* main key data clear */
    ret = (uint32_t)memset_s(&g_main_key[dev_id], sizeof(MAIN_KEY_INFO), 0x0, sizeof(MAIN_KEY_INFO));
    if (ret != EOK) {
        tloge("main key memset_s failed!\n");
        return ret;
    }

    /* ta keys */
    ret = (uint32_t)memset_s(g_ta_keys[dev_id], sizeof(TA_KEY_INFO) * TA_MAX_NUM,
                             0x0, sizeof(TA_KEY_INFO) * TA_MAX_NUM);
    if (ret != EOK) {
        tloge("ta keys memset_s failed!\n");
        return ret;
    }

    /* fix g_ta_keys's id */
    ptr_uuid = (uint32_t *)g_ta_keys[dev_id][TEST_INDEX].ta_id;
    *(ptr_uuid + TA_ID0) = TEST_PART0;
    *(ptr_uuid + TA_ID1) = TEST_PART1;
    *(ptr_uuid + TA_ID2) = TEST_PART2;
    *(ptr_uuid + TA_ID3) = TEST_PART3;

    /* fix g_ta_keys's id */
    ptr_uuid = (uint32_t *)g_ta_keys[dev_id][BBOX_INDEX].ta_id;
    *(ptr_uuid + TA_ID0) = BBOX_PART0;
    *(ptr_uuid + TA_ID1) = BBOX_PART1;
    *(ptr_uuid + TA_ID2) = BBOX_PART2;
    *(ptr_uuid + TA_ID3) = BBOX_PART3;

    /* fix g_ta_keys's id */
    ptr_uuid = (uint32_t *)g_ta_keys[dev_id][RPMB_INDEX].ta_id;
    *(ptr_uuid + TA_ID0) = RPMB_PART0;
    *(ptr_uuid + TA_ID1) = RPMB_PART1;
    *(ptr_uuid + TA_ID2) = RPMB_PART2;
    *(ptr_uuid + TA_ID3) = RPMB_PART3;

    ptr_uuid = (uint32_t *)g_ta_keys[dev_id][FIRMUP_INDEX].ta_id;
    *(ptr_uuid + TA_ID0) = FIRMUP_PART0;
    *(ptr_uuid + TA_ID1) = FIRMUP_PART1;
    *(ptr_uuid + TA_ID2) = FIRMUP_PART2;
    *(ptr_uuid + TA_ID3) = FIRMUP_PART3;

    ptr_uuid = (uint32_t *)g_ta_keys[dev_id][RPMB_SRV_INDEX].ta_id;
    *(ptr_uuid + TA_ID0) = RPMB_SRV_PART0;
    *(ptr_uuid + TA_ID1) = RPMB_SRV_PART1;
    *(ptr_uuid + TA_ID2) = RPMB_SRV_PART2;
    *(ptr_uuid + TA_ID3) = RPMB_SRV_PART3;

    ptr_uuid = (uint32_t *)g_ta_keys[dev_id][EFUSE_INDEX].ta_id;
    *(ptr_uuid + TA_ID0) = EFUSE_PART0;
    *(ptr_uuid + TA_ID1) = EFUSE_PART1;
    *(ptr_uuid + TA_ID2) = EFUSE_PART2;
    *(ptr_uuid + TA_ID3) = EFUSE_PART3;

    return TEE_SUCCESS;
}

STATIC uint32_t hsm_start_main_key_init(uint32_t dev_id)
{
    HSM_BACK_DATA hsm_back_data;
    HSM_COMMAND hsm_cmd;
    uint32_t ret;
    uint64_t mainkey_data_addr;
    MAIN_KEY_INFO *ptr_share_ddr_vaddr = NULL;

    /* clear data firstly */
    ret = hsm_clear_hsm_data(&hsm_cmd, &hsm_back_data);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    g_main_key[dev_id].cnt = 1;

    /* fill/send/get scmi data */
    hsm_cmd.cmd = HSM_START_MAIN_KEY_INIT_CMD;
    hsm_cmd.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    hsm_cmd.addr_addr_l = HSM_TEE_START_MAIN_KEY_INIT_PADDR;
    hsm_cmd.cnt = g_main_key[dev_id].cnt;

    ret = hsm_service_to_hiss(dev_id, &hsm_cmd, &hsm_back_data, CHANNEL_NUM_0);
    if (ret != TEE_SUCCESS) {
        tloge("hiss service execute failed, 0x%x\n", ret);
        return ret;
    }

    /* save mainkey & cnt */
    mainkey_data_addr = g_hsm_tee_smem_start_vaddr[dev_id] +
         hsm_cmd.addr_addr_l - HSM_TEE_SHARE_DDR_PHY_ADDR;
    ptr_share_ddr_vaddr = (MAIN_KEY_INFO *)(uintptr_t)mainkey_data_addr;

    if (memcpy_s(g_main_key[dev_id].main_key, sizeof(g_main_key[dev_id].main_key),
        ptr_share_ddr_vaddr->main_key, MAIN_KEY_LEN_IN_BYTE) != EOK) {
        tloge("start main key init, memcpy_s failed!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    ret = service_verify_hmac(dev_id, SERVICE_HMAC_KEY1, &hsm_back_data, mainkey_data_addr);
    if (ret != TEE_SUCCESS) {
        tloge("start main key init hmac check failed, 0x%x\n", ret);
        return ret;
    }

    if (memset_s((void *)(uintptr_t)mainkey_data_addr, MAIN_KEY_LEN_IN_BYTE, 0, MAIN_KEY_LEN_IN_BYTE) != EOK) {
        tloge("clear ddr context in init main key fail!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t hsm_finished_main_key_init(uint32_t dev_id)
{
    HSM_BACK_DATA hsm_back_data;
    HSM_COMMAND hsm_cmd;
    uint64_t mainkey_data_addr;
    uint32_t ret;
    uint8_t hmac_result[SERVICE_HMAC_LEN] = {0};
    SERVICE_INFO_S service_info = {0};

    /* clear data firstly */
    ret = hsm_clear_hsm_data(&hsm_cmd, &hsm_back_data);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    /* fill/send/get scmi data */
    hsm_cmd.cmd = HSM_FINISHED_MAIN_KEY_INIT_CMD;
    hsm_cmd.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    hsm_cmd.addr_addr_l = HSM_TEE_FINISH_MAIN_KEY_INIT_PADDR;
    hsm_cmd.cnt = g_main_key[dev_id].cnt;
    mainkey_data_addr = g_hsm_tee_smem_start_vaddr[dev_id] +
        hsm_cmd.addr_addr_l - HSM_TEE_SHARE_DDR_PHY_ADDR;
    service_info.in_buf = (uint8_t *)(uintptr_t)mainkey_data_addr;
    service_info.p_in_msg = &hsm_cmd;

    ret = service_calc_hmac(dev_id, SERVICE_HMAC_KEY1, &service_info, hmac_result, HMAC_INPUT);
    if (ret != TEE_SUCCESS) {
        tloge("finish main key init cal hmac failed, 0x%x\n", ret);
        return ret;
    }

    ret = (uint32_t)memcpy_s((void *)(hsm_cmd.hmac), SERVICE_HMAC_LEN,
                             (const void *)hmac_result, SERVICE_HMAC_LEN);
    if (ret != EOK) {
        tloge("finish main key init copy hmac failed!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    g_main_key[dev_id].cnt++;

    ret = hsm_service_to_hiss(dev_id, &hsm_cmd, &hsm_back_data, CHANNEL_NUM_0);
    if (ret != TEE_SUCCESS) {
        tloge("finish main service execute failed, 0x%x\n", ret);
        return ret;
    }

    ret = service_verify_hmac(dev_id, SERVICE_HMAC_KEY1, &hsm_back_data, mainkey_data_addr);
    if (ret != TEE_SUCCESS) {
        tloge("finish main key init hmac check failed, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t tee_service_handle_params_check(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp, uint32_t cmd)
{
    uint32_t i;
    uint32_t dev_id;

    /* don't check just now */
    (void)task_id;

    if (rsp == NULL) {
        tloge("service handle rsp params NULL!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (msg == NULL) {
        rsp->ret = TEE_ERROR_BAD_PARAMETERS;
        tloge("service handle msg params NULL!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    dev_id = (uint32_t)msg->args_data.arg6;

    if (dev_id > g_dev_id_max) {
        tloge("dev id in hsm service is error!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* check invalid ipc command */
    for (i = HSM_IPC_CIPHER_START_CMD; i < HSM_MAX_IPC_CMD_INDEX; i++) {
        if (cmd == i) {
            return TEE_SUCCESS;
        }
    }

    tloge("command params wrong, 0x%x!\n", cmd);
    return TEE_ERROR_INVALID_CMD;
}

STATIC void hsm_service_cmd_assign_value(HSM_COMMAND *hsm_cmd, const FILL_PART_HSM_DATA *part_hsm_data, uint32_t idx)
{
    hsm_cmd->cmd = part_hsm_data->cmd;
    hsm_cmd->addr_addr_h = part_hsm_data->addr_addr_h;
    hsm_cmd->addr_addr_l = part_hsm_data->addr_addr_l;
    hsm_cmd->cnt = part_hsm_data->mainkey_cnt;
    hsm_cmd->ta_index = idx;
}

STATIC uint32_t hsm_gen_ta_key(uint32_t dev_id, const TA_KEY_INFO *ta_key, uint32_t idx,
    FILL_PART_HSM_DATA part_hsm_data)
{
    HSM_COMMAND hsm_cmd;
    HSM_BACK_DATA hsm_back_data;
    uint32_t ret;
    uint64_t mainkey_data_addr;
    uint8_t hmac_result[SERVICE_HMAC_LEN] = {0};
    SERVICE_INFO_S service_info = {0};

    /* clear data */
    if (hsm_clear_hsm_data(&hsm_cmd, &hsm_back_data) != TEE_SUCCESS) {
        return TEE_FAIL;
    }

    /* fill hsm_cmd data */
    hsm_service_cmd_assign_value(&hsm_cmd, &part_hsm_data, idx);
    mainkey_data_addr = g_hsm_tee_smem_start_vaddr[dev_id] + hsm_cmd.addr_addr_l - HSM_TEE_SHARE_DDR_PHY_ADDR;
    service_info.in_buf = (uint8_t *)(uintptr_t)mainkey_data_addr;
    service_info.p_in_msg = &hsm_cmd;

    ret = (uint32_t)memcpy_s(hsm_cmd.ta_id, TA_ID_LEN_FOUR_WORD * LEN_OF_4BYTES, ta_key->ta_id,
                             TA_ID_LEN_FOUR_WORD * sizeof(uint32_t));
    if (ret != EOK) {
        tloge("hsm gen ta session key, memcpy_s failed!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    ret = service_calc_hmac(dev_id, SERVICE_HMAC_KEY1, &service_info, (uint8_t *)(uintptr_t)hmac_result, HMAC_INPUT);
    if (ret != TEE_SUCCESS) {
        tloge("hsm gen ta cal hmac failed, 0x%x\n", ret);
        return ret;
    }

    ret = (uint32_t)memcpy_s((void *)(hsm_cmd.hmac), SERVICE_HMAC_LEN,
                             (const void *)hmac_result, SERVICE_HMAC_LEN);
    if (ret != EOK) {
        tloge("hsm gen ta copy hmac failed!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    /* send data to hiss */
    ret = hsm_service_to_hiss(dev_id, &hsm_cmd, &hsm_back_data, part_hsm_data.channel_num);
    if (ret != TEE_SUCCESS) {
        tloge("hsm gen ta key task execute failed, 0x%x!\n", ret);
        return ret;
    }

    ret = (uint32_t)memcpy_s(g_ta_keys[dev_id][idx].ta_key, TA_KEY_LEN_IN_BYTE,
                             (const void *)(uintptr_t)mainkey_data_addr,
                             hsm_back_data.param_len_0);
    if (ret != EOK) {
        tloge("hsm gen ta key, memcpy_s failed!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    ret = service_verify_hmac(dev_id, SERVICE_HMAC_KEY2, &hsm_back_data, mainkey_data_addr);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = (uint32_t)memset_s((void *)(uintptr_t)mainkey_data_addr, hsm_back_data.param_len_0,
                             0, hsm_back_data.param_len_0);
    if (ret != EOK) {
        tloge("clear ddr context in start get ta key fail!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t hsm_gen_ta_key_finish(uint32_t dev_id, const TA_KEY_INFO *ta_key,
    uint32_t idx, FILL_PART_HSM_DATA part_hsm_data)
{
    HSM_COMMAND hsm_cmd;
    HSM_BACK_DATA hsm_back_data;
    uint32_t ret;
    uint64_t mainkey_data_addr;
    uint8_t hmac_result[SERVICE_HMAC_LEN] = {0};
    SERVICE_INFO_S service_info = {0};

    /* clear data */
    ret = hsm_clear_hsm_data(&hsm_cmd, &hsm_back_data);
    if (ret != TEE_SUCCESS) {
        tloge("clear data failed, 0x%x\n", ret);
        return ret;
    }

    /* fill hsm_cmd data */
    hsm_service_cmd_assign_value(&hsm_cmd, &part_hsm_data, idx);

    mainkey_data_addr = g_hsm_tee_smem_start_vaddr[dev_id] +
                        hsm_cmd.addr_addr_l - HSM_TEE_SHARE_DDR_PHY_ADDR;
    service_info.in_buf = (uint8_t *)(uintptr_t)mainkey_data_addr;
    service_info.p_in_msg = &hsm_cmd;

    ret = (uint32_t)memcpy_s(hsm_cmd.ta_id, TA_ID_LEN_FOUR_WORD * LEN_OF_4BYTES, ta_key->ta_id,
                             TA_ID_LEN_FOUR_WORD * sizeof(uint32_t));
    if (ret != EOK) {
        tloge("hsm gen ta session key, memcpy_s failed!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    ret = service_calc_hmac(dev_id, SERVICE_HMAC_KEY2, &service_info, (uint8_t *)(uintptr_t)hmac_result, HMAC_INPUT);
    if (ret != TEE_SUCCESS) {
        tloge("hsm gen ta finish cal hmac failed, 0x%x\n", ret);
        return ret;
    }

    ret = (uint32_t)memcpy_s((void *)hsm_cmd.hmac, SERVICE_HMAC_LEN,
                             (void *)hmac_result, SERVICE_HMAC_LEN);
    if (ret != EOK) {
        tloge("hsm gen ta copy hmac failed!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    /* send data to hiss */
    ret = hsm_service_to_hiss(dev_id, &hsm_cmd, &hsm_back_data, part_hsm_data.channel_num);
    if (ret != TEE_SUCCESS) {
        tloge("service to hiss failed, 0x%x\n", ret);
        return ret;
    }

    ret = service_verify_hmac(dev_id, SERVICE_HMAC_KEY2, &hsm_back_data, mainkey_data_addr);
    if (ret != TEE_SUCCESS) {
        tloge("hsm gen ta hmac check failed, 0x%x\n", ret);
        return ret;
    }

    ret = (uint32_t)memset_s((void *)(uintptr_t)mainkey_data_addr,
                             hsm_back_data.param_len_0, 0, hsm_back_data.param_len_0);
    if (ret != EOK) {
        tloge("clear ddr context in finish get ta key fail!\n");
        return TEE_ERROR_WRITE_DATA;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t hsm_init_ta_key(uint32_t dev_id)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t i;

    for (i = 0; i < TA_LIST_NUMBER; i++) {
        /* update hsm service cnt */
        g_main_key[dev_id].cnt++;

        /* establish session key */
        part_hsm_data.cmd = HSM_START_ESTABLISSH_SESSION_CMD;
        part_hsm_data.addr_addr_h = 0x0;
        part_hsm_data.addr_addr_l = HSM_TEE_START_ESTABLISSH_SESSION_PADDR;
        part_hsm_data.ddr_data_len = 0x0;
        part_hsm_data.ddr_para_num = 0x0;
        part_hsm_data.channel_num = CHANNEL_NUM_0;
        part_hsm_data.mainkey_cnt = g_main_key[dev_id].cnt;
        ret = hsm_gen_ta_key(dev_id, &g_ta_keys[dev_id][i], i, part_hsm_data);
        if (ret != TEE_SUCCESS) {
            tloge("gen ta key start failed, 0x%x!\n", ret);
            return ret;
        }

        /* update hsm service cnt */
        g_main_key[dev_id].cnt++;

        /* finished session key */
        part_hsm_data.cmd = HSM_FINISHED_ESTABLISSH_SESSION_CMD;
        part_hsm_data.addr_addr_h = 0x0;
        part_hsm_data.addr_addr_l = 0;
        part_hsm_data.ddr_data_len = 0x0;
        part_hsm_data.ddr_para_num = 0x0;
        part_hsm_data.channel_num = CHANNEL_NUM_0;
        part_hsm_data.mainkey_cnt = g_main_key[dev_id].cnt;
        ret = hsm_gen_ta_key_finish(dev_id, &g_ta_keys[dev_id][i], i, part_hsm_data);
        if (ret != TEE_SUCCESS) {
            tloge("gen ta key finish failed, 0x%x!\n", ret);
            return ret;
        }
    }

    return ret;
}

STATIC tee_service_cmd g_scmi_cmd_tbl[] = {
    /* cmd                         fn */
    {HSM_IPC_CIPHER_START_CMD, hsm_cipher_start},
    {HSM_IPC_CIPHER_PROCESS_CMD, hsm_cipher_process},
    {HSM_IPC_CIPHER_FINISH_CMD, hsm_cipher_finish},
    {HSM_IPC_MAC_START_CMD, hsm_mac_start},
    {HSM_IPC_MAC_PROCESS_CMD, hsm_mac_process},
    {HSM_IPC_MAC_FINISH_CMD, hsm_mac_finish},
    {HSM_IPC_HASH_START_CMD, hsm_hash_start},
    {HSM_IPC_HASH_PROCESS_CMD, hsm_hash_process},
    {HSM_IPC_HASH_FINISH_CMD, hsm_hash_finish},
    {HSM_IPC_SIGN_START_CMD, hsm_sign_start},
    {HSM_IPC_SIGN_PROCESS_CMD, hsm_sign_process},
    {HSM_IPC_SIGN_FINISH_CMD, hsm_sign_finish},
    {HSM_IPC_VERIFY_START_CMD, hsm_verify_start},
    {HSM_IPC_VERIFY_PROCESS_CMD, hsm_verify_process},
    {HSM_IPC_VERIFY_FINISH_CMD, hsm_verify_finish},
    {HSM_IPC_GET_RANDOM_CMD, hsm_gen_random},

    {HSM_IPC_GENERATE_SYMKEY_CMD, hsm_produce_symmetric_key},
    {HSM_IPC_GENERATE_ASYMKEY_CMD, hsm_produce_asymmetric_key},
    {HSM_IPC_DERIVE_HUK_CMD, hsm_derive_huk},
    {HSM_IPC_DERIVE_KEY_CMD, hsm_derive_external_key},
    {HSM_IPC_EXCHANGE_CAL_PUB_CMD, hsm_produce_negotiation_pubkey},
    {HSM_IPC_EXCHANGE_AGREE_KEY_CMD, hsm_produce_negotiation_key},
    {HSM_IPC_IMPORT_KEY_CMD, hsm_import_key},
    {HSM_IPC_EXPORT_KEY_CMD, hsm_export_key},
    {HSM_IPC_UPDATE_PROTECT_KEY_CMD, hsm_update_guarding_key},
    {HSM_IPC_UPDATE_KEY_AUTH_CMD, hsm_update_authorize_key},
    {HSM_IPC_DELETE_KEY_CMD, hsm_delete_cipher},
    {HSM_IPC_UNWRAP_KEY_CMD, hsm_sh_key},
    {HSM_BBOX_CMD, hsm_bbox_get},
    {HSM_COUNTER_INIT_CMD, hsm_counter_init},
    {HSM_COUNTER_CREATE_CMD, hsm_counter_create},
    {HSM_COUNTER_READ_CMD, hsm_counter_read},
    {HSM_COUNTER_DELETE_CMD, hsm_counter_delete},
    {HSM_COUNTER_INC_CMD, hsm_counter_inc},
    {HSM_ALG_CHECK_CMD, hsm_alg_check},
    {HSM_GEN_RPMBKEY_CMD, generate_rpmb_key},
    {HSM_GEN_RPMB_WARPPINGKEY_CMD, generate_rpmb_wrapping_key},
    {HSM_SOC_VERIFY_CMD, hsm_soc_verify},
    {HSM_NOTIFY_PRERESET_CMD, hsm_notify_prereset},
    {HSM_IPC_RIM_UPDATE_CMD, hsm_rim_update},
    {HSM_IPC_EFUSE_POWER_ON_CMD, hsm_efuse_power_on},
    {HSM_IPC_EFUSE_POWER_OFF_CMD, hsm_efuse_power_off},
    {HSM_IPC_HBOOT1A_TRANS_CMD, hsm_hboot1a_transform},
    {HSM_IPC_SERVICE_FUZZ_CMD, hsm_service_fuzz},
};

uint32_t tee_service_init()
{
    uint32_t ret;
    uint32_t i;
    uint32_t dev_num = 0;

    ret = (uint32_t)tee_obj_init();
    if (ret != TEE_SUCCESS) {
        tloge("tee obj init failed!\n");
        return ret;
    }

    ret = lib_get_device_num(&dev_num);
    if (ret != TEE_SUCCESS) {
        tloge("get device num failed, 0x%x\n", ret);
        return TEE_ERROR_READ_DATA;
    }
    if ((dev_num > DEVICE_NUM) || (dev_num == 0)) {
        tloge("invalid dev num\n");
        return TEE_FAIL;
    }
    g_dev_id_max = dev_num - 1;

    for (i = 0; i < dev_num; i++) {
        /* clear global data firstly */
        ret = hsm_service_data_clear(i);
        if (ret != TEE_SUCCESS) {
            tloge("hsm service data clear failed, 0x%x\n", ret);
            return ret;
        }

        /* remap hsm share memory */
        ret = lib_hiss_shared_paddr_to_vaddr(i, &g_hsm_tee_smem_start_vaddr[i]);
        if (ret != SCMI_LIB_RESULT_SUCCESS) {
            tloge("hsm share memory rempap failed, 0x%x\n", ret);
            return ret;
        }

        /* main key init */
        ret = hsm_start_main_key_init(i);
        if (ret != TEE_SUCCESS) {
            tloge("main key init failed, 0x%x\n", ret);
            return ret;
        }

        /* finished main key init */
        ret = hsm_finished_main_key_init(i);
        if (ret != TEE_SUCCESS) {
            tloge("finish main key init failed, 0x%x\n", ret);
            return ret;
        }

        /* init ta session key */
        ret = hsm_init_ta_key(i);
        if (ret != TEE_SUCCESS) {
            tloge("init ta session key failed, 0x%x\n", ret);
            return ret;
        }
    }

    g_hsm_service_status = 0x0;

    return TEE_SUCCESS;
}

void tee_service_handle(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp, uint32_t cmd)
{
    uint32_t ret;
    uint32_t i;

    ret = tee_service_handle_params_check(msg, task_id, rsp, cmd);
    if (ret != TEE_SUCCESS) {
        tloge("service handle params check failed, 0x%x\n", ret);
        return;
    }

    if ((cmd != HSM_BBOX_CMD) && (cmd != HSM_GEN_RPMBKEY_CMD) && (cmd != HSM_GEN_RPMB_WARPPINGKEY_CMD)) {
        tlogw("This cmd is : 0x%x\n", cmd);
    }

    if (g_hsm_service_status != 0) {
        tloge("TEE HSM SERVICE init fail, cannot do\n");
        rsp->ret = TEE_FAIL;
        ret = (uint32_t)__SRE_MsgSnd(cmd, task_id, rsp, sizeof(tee_service_ipc_msg_rsp));
        if (ret != SRE_OK) {
            tloge("msg snd error, 0x%x\n", ret);
            return;
        }
        return;
    }

    for (i = 0; i < sizeof(g_scmi_cmd_tbl) / sizeof(g_scmi_cmd_tbl[0]); i++) {
        if (cmd != g_scmi_cmd_tbl[i].cmd) {
            continue;
        }

        if (g_scmi_cmd_tbl[i].fn != NULL) {
            g_scmi_cmd_tbl[i].fn(msg, task_id, rsp);
        }
    }
}

/*
TA's main func
*/
__attribute__((visibility ("default"))) void tee_task_entry(int init_build)
{
    tlogd("--start of hiss service task--\n");
    tee_common_task_entry(init_build, HSM_TASK_NAME);
}
