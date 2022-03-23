/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm common header file
* Author: huawei
* Create: 2020/1/18
*/
#ifndef HSM_COMMON_H
#define HSM_COMMON_H

#include "tee_service_public.h"
#include "hsm_service.h"

uint32_t hsm_clear_hsm_data(HSM_COMMAND *hsm_cmd, HSM_BACK_DATA *hsm_back_data);
uint32_t hsm_find_ta_index(uint32_t dev_id, uint32_t task_id, HSM_COMMAND *hsm_cmd, uint32_t mainkey_cnt);
uint32_t hsm_service_to_hiss(uint32_t dev_id, HSM_COMMAND *hsm_cmd, HSM_BACK_DATA *hsm_back_data, uint32_t channel);
uint32_t hsm_fill_scmi_msg(uint32_t dev_id, const tee_service_ipc_msg *msg, uint32_t task_id, HSM_COMMAND *hsm_cmd,
    FILL_PART_HSM_DATA part_hsm_data, uint64_t *data_addr);
uint32_t hsm_update_ta_cnt(uint32_t dev_id, uint32_t task_id);
uint32_t hsm_common_process(uint32_t dev_id, const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp, FILL_PART_HSM_DATA part_hsm_data);
uint32_t hsm_data_back_to_client(const tee_service_ipc_msg *msg, const uint8_t *src, uint32_t task_id);
uint32_t hsm_ddr_total_len(const tee_service_ipc_msg *msg);
uint32_t service_verify_hmac(uint32_t dev_id, uint32_t hmac_key, HSM_BACK_DATA *hsm_back, uint64_t data_addrx);
uint32_t service_calc_hmac(uint32_t dev_id, uint32_t hmac_key, const SERVICE_INFO_S *service_info,
    uint8_t *result, uint32_t dir);
uint32_t hsm_process_task_main(const tee_service_ipc_msg *msg, uint32_t task_id,
                               tee_service_ipc_msg_rsp *rsp,
                               FILL_PART_HSM_DATA *part_hsm_data);
#endif
