/*
 * npu_hwts_driver.h
 *
 * Copyright (c) 2012-2020 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef __NPU_HWTS_DRIVER_H__
#define __NPU_HWTS_DRIVER_H__

#include "soc_npu_hwts_interface.h"
#include "npu_base_define.h"
#include "npu_stream_info.h"

#define HWTS_SQE_DONE_S                      0x00
#define HWTS_PRE_PAUSED_S                    0x01
#define HWTS_POST_PAUSED_S                   0x02
#define HWTS_CQ_FULL_S                       0x03
#define HWTS_TASK_PAUSED_S                   0x04
#define HWTS_RESERVED                        0x05
#define HWTS_L2_BUF_SWAP_IN_S                0x06
#define HWTS_L2_BUF_SWAP_OUT_S               0x07
#define HWTS_SQ_DONE_S                       0x08
#define HWTS_CQE_WRITTEN_S                   0x09

#define HWTS_TASK_ERROR_S 0x0
#define HWTS_TASK_TIMEOUT_S 0x1
#define HWTS_TASK_TRAP_S 0x2
#define HWTS_SQE_ERROR_S 0x3
#define HWTS_SW_STATUS_ERROR_S 0x4
#define HWTS_BUS_ERROR_S 0x5
#define HWTS_POOL_CONFLICT_ERROR_S 0x7

#define HWTS_NORMAL_IRQ_MAX 0x0a
#define HWTS_SQ_NUM_MAX (64)

#define HWTS_SQ_LENGTH (1024ULL)
#define HWTS_CQ_LENGTH (1024ULL)

int npu_hwts_start_exec(npu_stream_info_t *stream_info, u16 sq_id);
void npu_clear_hwts_normal_interrupt(u32 type, u64 *value);
void npu_clear_hwts_exception_interrupt(u32 type, u64 *value);
void npu_clear_hwts_channel_sq_en(u16 sq_id);
void npu_interrupt_handle_hwts_normal();
void npu_interrupt_handle_hwts_error();

#endif

