/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: TEE's dispatch service
 * Author: QiShuai  qishuai@huawei.com
 * Create: 2019-12-20
 */

#ifndef GLOBAL_TASK_H
#define GLOBAL_TASK_H

#include "ta_framework.h"
#include "gtask_inner.h"

void gtask_main(void);
int put_last_out_cmd(const smc_cmd_t *cmd);
TEE_Result get_tee_version(const smc_cmd_t *cmd);
TEE_Result process_load_image(smc_cmd_t *cmd, bool *async);
TEE_Result process_ta_common_cmd(smc_cmd_t *cmd, uint32_t cmd_type, uint32_t task_id, bool *async,
                                 const struct ta2ta_info_t *ta2ta_info);
TEE_Result handle_time_adjust(const smc_cmd_t *cmd);
void ns_cmd_response(smc_cmd_t *cmd);
bool is_abort_cmd(const smc_cmd_t *cmd);
void restore_cmd_in(const smc_cmd_t *cmd);

#endif
