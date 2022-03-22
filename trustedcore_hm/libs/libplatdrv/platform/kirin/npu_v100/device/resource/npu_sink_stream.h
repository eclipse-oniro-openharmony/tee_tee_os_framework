/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu sink stream
 */

#ifndef __NPU_SINK_STREAM_H
#define __NPU_SINK_STREAM_H

#include "sre_typedef.h"
int npu_sink_stream_list_init(u8 dev_id);

int npu_alloc_sink_stream_id(u8 dev_id);

int npu_free_sink_stream_id(u8 dev_id, u32 stream_id);

int npu_sink_stream_list_destroy(u8 dev_id);

#endif
