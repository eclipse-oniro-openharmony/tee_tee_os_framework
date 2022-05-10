/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: whitebox tool key head file for 128 bytes root key
 * Create: 2020-03-28
 */

#ifndef GTASK_WB_TOOL_128_ROOT_KEY_H
#define GTASK_WB_TOOL_128_ROOT_KEY_H

#include "ta_load_key.h"

TEE_Result get_wb_tool_v1_key(struct wb_tool_key *tool_key);
#endif