/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: hsm service verify source file
* Author: huawei
* Create: 2020/5/21
*/

#include "tee_log.h"
#include "tee_service_public.h"

#include "securec.h"

#include "hsm_command.h"
#include "hsm_service.h"
#include "hsm_verify.h"
#include "hsm_common.h"

void hsm_soc_verify(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_SOC_VERIFY_SEND_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_SOC_VERIFY_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM3;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm soc verify failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_hboot1a_transform(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_HBOOT1A_TRANS_SEND_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_HBOOT1A_TRANS_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM2;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm hboot1a transform failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}
