/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for MSPC API drivers.
 * Create: 2019/12/29
 */

#ifndef __MSPC_API_H__
#define __MSPC_API_H__

#include <mspc.h>
#include <mspc_errno.h>
#include <se_hal.h>

int32_t mspc_connect(uint32_t vote_id, void *p_atr, uint32_t *len);
int32_t mspc_disconnect(uint32_t vote_id);
int32_t mspc_send_apdu(uint8_t *p_cmd, uint32_t cmd_len);
int32_t mspc_receive_apdu(uint8_t *p_rsp, uint32_t *rsp_len);
int32_t mspc_get_status(void);
int32_t mspc_send_apdu_process(struct mspc_cmd_info *cmd_data);
int32_t mspc_receive_apdu_process(struct mspc_cmd_info *cmd_data);
int32_t mspc_init_apdu_process(struct mspc_cmd_info *cmd_data);
int32_t mspc_api_init(void);
#endif /* __MSPC_API_H__ */
