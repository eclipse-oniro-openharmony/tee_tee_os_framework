/* Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: used by ext_interface.
 * Author: yangboyu y30022050
 * Create: 2022-04-24
 */
#ifndef GTASK_EXT_INTERFACE_H
#define GTASK_EXT_INTERFACE_H

TEE_Result map_rdr_mem(const smc_cmd_t *cmd);
int32_t handle_info_query(uint32_t cmd_id, uint32_t task_id,
    const uint8_t *msg_buf, uint32_t msg_size);

#endif /* GTASK_EXT_INTERFACE_H */
