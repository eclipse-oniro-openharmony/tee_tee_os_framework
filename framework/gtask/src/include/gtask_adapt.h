/* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Make gtask be compatible to handle 64bit TA and 32bit TA.
 * Author: heyanhong h00424236
 * Create: 2019-04-12
 */

#ifndef __GTASK_ADAPT_H
#define __GTASK_ADAPT_H
#include "gtask_core.h"

int get_ta_info(uint32_t task_id, bool *ta_64bit, TEE_UUID *uuid);

/* struct ta_to_global_msg */
int convert_ta2gtask_msg(const uint8_t *msg_buf, uint32_t msg_size, uint32_t taskid, ta_to_global_msg *msg);

/* struct global_to_ta_msg */
TEE_Result send_global2ta_msg(const global_to_ta_msg *msg, uint32_t cmd, uint32_t taskid, const bool *type);

uint32_t get_tee_param_len(bool ta_is_64);

TEE_Result alloc_tee_param_for_ta(uint32_t taskid, struct pam_node *node);

TEE_Result send_ta_init_msg(const ta_init_msg *msg, bool ta_type, uint32_t cmd, uint32_t taskid);

#endif
