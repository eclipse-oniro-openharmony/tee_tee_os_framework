/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rpmb source codes
 * Author: huawei
 * Create: 2020-04-28
 */

#include "tee_log.h"
#include "tee_service_public.h"

#include "securec.h"

#include "hsm_command.h"
#include "hsm_service.h"
#include "hsm_common.h"
#include "hsm_rpmb.h"

void generate_rpmb_key(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_GEN_RPMB_KEY_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_GEN_RPMB_KEY_PADDR;
    part_hsm_data.ddr_data_len = 0;
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM0;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = 0x0;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm gen rpmb key failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void generate_rpmb_wrapping_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_GEN_RPMB_WRAP_KEY_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_GEN_RPMB_WRAP_KEY_PADDR;
    part_hsm_data.ddr_data_len = 0;
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM0;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = 0x0;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm gen rpmb wrap key failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}
