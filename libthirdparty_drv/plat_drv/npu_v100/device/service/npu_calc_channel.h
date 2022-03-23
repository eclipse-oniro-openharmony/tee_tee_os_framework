/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu calc channel
 */
#ifndef __NPU_CALC_CHANNEL_H
#define __NPU_CALC_CHANNEL_H
#include <list.h>
struct npu_ts_cq_info *npu_alloc_cq(u8 dev_id);
struct npu_stream_info *npu_alloc_stream(u32 cq_id, u32 strategy);
int npu_send_alloc_stream_mailbox(u8 cur_dev_id, int stream_id, int cq_id);
int npu_free_stream(u8 dev_id, u32 stream_id, u32 *sq_send_count);
#endif /* __NPU_CALC_CHANNEL_H */
