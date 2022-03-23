/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu model
 */
#ifndef __NPU_MODEL_H
#define __NPU_MODEL_H

#include <list.h>
struct npu_model_info {
	int id;
	u32 devid;
	struct list_head list;
};

int npu_model_list_init(u8 dev_ctx_id);

struct npu_model_info *npu_alloc_model(u8 dev_ctx_id);

int npu_free_model_id(u8 dev_ctx_id, u32 model_id);

int npu_model_list_destroy(u8 dev_ctx_id);

int npu_model_software_ops_register(u8 dev_ctx_id);

#endif
