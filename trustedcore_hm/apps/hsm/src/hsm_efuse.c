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
#include "hsm_common.h"
#include "hsm_efuse.h"

void hsm_rim_update(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_RIM_UPDATE_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_RIM_UPDATE_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM2;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm rim update failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_efuse_power_on(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_EFUSE_PWR_ON_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_EFUSE_PWR_ON_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM0;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm efuse power on failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}

void hsm_efuse_power_off(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = HSM_EFUSE_PWR_OFF_CMD;
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_EFUSE_PWR_OFF_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = HSM_DDR_PARA_NUM0;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    if (ret != TEE_SUCCESS) {
        tloge("hsm efuse power off failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}
