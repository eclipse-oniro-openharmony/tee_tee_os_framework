/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm key managerment source file
* Author: huawei
* Create: 2020/1/8
*/

#include "tee_log.h"
#include "tee_service_public.h"

#include "securec.h"

#include "hsm_command.h"
#include "hsm_service.h"
#include "hsm_common.h"
#include "hsm_km.h"

void hsm_produce_symmetric_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_PRODUCE_SYMMETRIC_KEY_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_PRODUCE_SYMMETRIC_KEY_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM3;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm produce sym key failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_produce_asymmetric_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_PRODUCE_ASYMMETRIC_KEY_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_PRODUCE_ASYMMETRIC_KEY_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM5;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm produce asym key failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_derive_huk(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_DERIVE_HUK_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_DERIVE_HUK_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM3;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm derive huk failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_derive_external_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_DERIVE_EXTERNAL_KEY_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_DERIVE_EXTERNAL_KEY_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM7;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm derive external key failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

STATIC void hsm_import_ipk1(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_IMPORT_IPK1_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_IMPORT_IPK1_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM4;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm import key1 failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

STATIC void hsm_import_ipk2(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_IMPORT_IPK2_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_IMPORT_IPK2_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM4;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm import key2 failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_produce_negotiation_pubkey(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_PRODUCE_NEGOTIATION_PUBLIC_KEY_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_PRODUCE_NEGOTIATION_PKEY_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM5;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm produce negoritation pubkey failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_produce_negotiation_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_PRODUCE_NEGOTIATION_KEY_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_PRODUCE_NEGOTIATION_KEY_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM8;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm produce negoritation key failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_sh_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_SH_KEY_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_SH_KEY_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM3;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm sh key failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_update_guarding_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_UPDATE_GUARDING_KEY_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_UPDATE_GUARDING_KEY_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM3;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm update guarding key failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_update_authorize_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_UPDATE_VERIFY_INFO_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_UPDATE_VERIFY_INFO_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM3;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm update authorize key failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_delete_cipher(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_DELETE_CIPHER_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_DELETE_CIPHER_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM2;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm delete cipher failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

STATIC void hsm_export_ipk1(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_EXPORT_IPK1_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_EXPORT_IPK1_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM4;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm export ipk1 failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

STATIC void hsm_export_ipk2(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_EXPORT_IPK2_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_EXPORT_IPK2_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM4;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm export ipk2 failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_bbox_get(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint8_t *src = NULL;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* update hsm service cnt */
    g_main_key[dev_id].cnt++;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_BBOX_HISS_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_BBOX_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM2;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_MAINKEY_CNT;
    ret = hsm_common_process(dev_id, msg, task_id, rsp, part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm bbox info get failed, 0x%x!\n", ret);
        rsp->ret = TEE_ERROR_TIMEOUT;
        return;
    }

    /* copy data back to client */
    src = (uint8_t *)(uintptr_t)(g_hsm_tee_smem_start_vaddr[dev_id] +
        HSM_TEE_BBOX_PADDR - HSM_TEE_SHARE_DDR_PHY_ADDR);
    ret = hsm_data_back_to_client(msg, src, task_id);
    if (ret != TEE_SUCCESS) {
        tloge("hsm bbox info back to client failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_notify_prereset(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint8_t *src = NULL;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;
    tloge("hsm_notify_prereset begin\n");

    /* update hsm service cnt */
    g_main_key[dev_id].cnt++;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_NOTIFY_PRERESET_HISS_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_NOTIFY_PRERESET_PADDR;
    part_hsm_data.ddr_data_len = 0;
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM0;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_MAINKEY_CNT;
    ret = hsm_common_process(dev_id, msg, task_id, rsp, part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm notify prereset failed, 0x%x!\n", ret);
        rsp->ret = TEE_ERROR_TIMEOUT;
        return;
    }

    /* copy data back to client */
    src = (uint8_t *)(uintptr_t)(g_hsm_tee_smem_start_vaddr[dev_id] +
        HSM_TEE_NOTIFY_PRERESET_PADDR - HSM_TEE_SHARE_DDR_PHY_ADDR);
    ret = hsm_data_back_to_client(msg, src, task_id);
    if (ret != TEE_SUCCESS) {
        tloge("hsm notify prereset back to client failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_import_key(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    if ((uint32_t)(msg->args_data.arg7) == 0x1U) {
        hsm_import_ipk1(msg, task_id, rsp);
    } else {
        hsm_import_ipk2(msg, task_id, rsp);
    }
}

void hsm_export_key(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    if ((uint32_t)(msg->args_data.arg7) == 0x1U) {
        hsm_export_ipk1(msg, task_id, rsp);
    } else {
        hsm_export_ipk2(msg, task_id, rsp);
    }
}
