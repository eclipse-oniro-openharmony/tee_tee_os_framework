/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm key managerment source file
* Author: huawei
* Create: 2020/1/8
*/

#include "tee_log.h"
#include "securec.h"
#include "tee_service_public.h"
#include "hsm_command.h"
#include "hsm_service.h"
#include "hsm_common.h"
#include "hsm_crypto.h"

STATIC void hsm_cipher_start_encrypt(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_CIPHER_START_ENCRIPT_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_CIPHER_START_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM6;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm cipher start encrypt failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

STATIC void hsm_cipher_start_decrypt(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_CIPHER_START_DECRIPT_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_CIPHER_START_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM6;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm cipher start decrypt failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

STATIC void hsm_cipher_process_encrypt(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_CIPHER_PROCESS_ENCRIPT_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_CIPHER_PROCESS_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM2;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm cipher process encrypt failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

STATIC void hsm_cipher_process_decrypt(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_CIPHER_PROCESS_DECRIPT_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_CIPHER_PROCESS_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM2;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm cipher process encrypt failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

STATIC void hsm_cipher_finish_encrypt(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_CIPHER_FINISH_ENCRIPT_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_CIPHER_FINISH_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM1;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm cipher finish encrypt failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

STATIC void hsm_cipher_finish_decrypt(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_CIPHER_FINISH_DECRIPT_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_CIPHER_FINISH_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM1;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm cipher finish decrypt failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_hash_start(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_HASH_START_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_HASH_START_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM4;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm hash start failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_hash_process(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* update ta cnt */
    if (hsm_update_ta_cnt(dev_id, task_id) != TEE_SUCCESS) {
        tloge("hsm update ta cnt failed!\n");
        rsp->ret = TEE_FAIL;
        return;
    }

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_HASH_PROCESS_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_HASH_UPDATE_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM2;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;
    ret = hsm_common_process(dev_id, msg, task_id, rsp, part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm hash process failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    /* no copy data back to client */
    rsp->ret = TEE_SUCCESS;
}

void hsm_hash_finish(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_HASH_FINISH_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_HASH_FINISH_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM1;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm cipher start encrypt failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_mac_start(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_MAC_START_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_MAC_START_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM4;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm mac start failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_mac_process(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* update ta cnt */
    if (hsm_update_ta_cnt(dev_id, task_id) != TEE_SUCCESS) {
        rsp->ret = TEE_FAIL;
        return;
    }

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_MAC_PROCESS_CMD;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM2;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_MAC_PROCESS_PADDR;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;
    ret = hsm_common_process(dev_id, msg, task_id, rsp, part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm mac process failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    /* no copy data back to client */
    rsp->ret = TEE_SUCCESS;
}

void hsm_mac_finish(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_MAC_FINISH_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_MAC_FINISH_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM1;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm mac finish failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_sign_start(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_SIGN_START_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_SIGN_START_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM5;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm sign start failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_sign_process(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* update ta cnt */
    if (hsm_update_ta_cnt(dev_id, task_id) != TEE_SUCCESS) {
        tloge("hsm update ta cnt failed!\n");
        rsp->ret = TEE_FAIL;
        return;
    }

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_SIGN_PROCESS_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_SIGN_UPDATE_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM2;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;
    ret = hsm_common_process(dev_id, msg, task_id, rsp, part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm sign process failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_sign_finish(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_SIGN_FINISH_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_SIGN_FINISH_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM1;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm sign finish failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_verify_start(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_VERIFY_START_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_VERIFY_START_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM7;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm verfiy start failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_verify_process(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* update ta cnt */
    if (hsm_update_ta_cnt(dev_id, task_id) != TEE_SUCCESS) {
        tloge("hsm update ta cnt failed!\n");
        rsp->ret = TEE_FAIL;
        return;
    }

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_VERIFY_PROCESS_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_VERIFY_UPDATE_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM2;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;
    ret = hsm_common_process(dev_id, msg, task_id, rsp, part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm verfiy process failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_verify_finish(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_VERIFY_FINISH_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_VERIFY_FINISH_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM1;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm verfiy finish failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_gen_random(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_GEN_RANDOM_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_GEN_RANDOM_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM1;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm gen random failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_cipher_start(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    if ((uint32_t)(msg->args_data.arg4) == 0x1) {
        hsm_cipher_start_encrypt(msg, task_id, rsp);
    } else {
        hsm_cipher_start_decrypt(msg, task_id, rsp);
    }
}

void hsm_cipher_process(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    if ((uint32_t)(msg->args_data.arg4) == 0x1) {
        hsm_cipher_process_encrypt(msg, task_id, rsp);
    } else {
        hsm_cipher_process_decrypt(msg, task_id, rsp);
    }
}

void hsm_cipher_finish(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    if ((uint32_t)(msg->args_data.arg4) == 0x1) {
        hsm_cipher_finish_encrypt(msg, task_id, rsp);
    } else {
        hsm_cipher_finish_decrypt(msg, task_id, rsp);
    }
}
