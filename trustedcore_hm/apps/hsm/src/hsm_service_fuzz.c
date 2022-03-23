/*
* Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
* Description: hsm service fuzz source file
* Author: huawei
* Create: 2021/5/21
*/

#include "tee_log.h"
#include "tee_service_public.h"

#include "hsm_command.h"
#include "hsm_service_fuzz.h"
#include "hsm_common.h"

void hsm_service_fuzz(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp)
{
    FILL_PART_HSM_DATA part_hsm_data;
    uint32_t ret;
    uint32_t dev_id = (uint32_t)msg->args_data.arg6;

    /* fill part hsm data */
    part_hsm_data.cmd = (uint32_t)(msg->args_data.arg7 >> SHIFT_CONST_NUM_32);
    part_hsm_data.addr_addr_h = CHIP_PADDR_OFFSET_H * dev_id;
    part_hsm_data.addr_addr_l = HSM_TEE_FUZZ_SERVICE_PADDR;
    part_hsm_data.ddr_data_len = hsm_ddr_total_len(msg);
    part_hsm_data.ddr_para_num = (uint32_t)msg->args_data.arg7;
    part_hsm_data.channel_num = CHANNEL_NUM_0;
    if ((part_hsm_data.cmd == HSM_BBOX_HISS_CMD) || (part_hsm_data.cmd == HSM_NOTIFY_PRERESET_HISS_CMD) ||
        (part_hsm_data.cmd == HSM_ALGO_CHECK_CMD)) {
        part_hsm_data.mainkey_cnt = HSM_SERVICE_MAINKEY_CNT;
    } else {
        part_hsm_data.mainkey_cnt = HSM_SERVICE_TAKEY_CNT;
    }

    ret = hsm_process_task_main(msg, task_id, rsp, &part_hsm_data);
    tloge("hsm service fuzz ddr_data_len is : %x!\n", part_hsm_data.ddr_data_len);
    if (ret != TEE_SUCCESS) {
        tloge("hsm service fuzz failed, 0x%x!\n", ret);
        rsp->ret = TEE_FAIL;
        return;
    }

    rsp->ret = TEE_SUCCESS;
}
