/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu event
 */
#ifndef __NPU_EVENT_H
#define __NPU_EVENT_H
#include <list.h>
int npu_event_list_init(u8 dev_id);

struct npu_event_info *npu_alloc_event(u8 dev_id);

int npu_free_event_id(u8 dev_id, u32 event_id);

int npu_event_list_destroy(u8 dev_id);

int npu_event_software_ops_register(u8 dev_id);

#endif
