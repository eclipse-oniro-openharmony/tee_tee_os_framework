/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about doorbell
 */

#ifndef __NPU_DOORBELL_H
#define __NPU_DOORBELL_H

#include <sre_typedef.h>
enum res_type {
	DOORBELL_RES_CAL_SQ,
	DOORBELL_RES_CAL_CQ,
	DOORBELL_RES_DFX_SQ,
	DOORBELL_RES_DFX_CQ,
	DOORBELL_RES_MAILBOX,
	DOORBELL_RES_RESERVED
};

#define DOORBELL_MAILBOX_VALUE 0x3A
#define DOORBELL_MAILBOX_MAX_SIZE 1
#define DEVDRV_DOORBELL_MAILBOX_INDEX	127

int npu_write_doorbell_val(u32 type, u32 index, u32 val);
void npu_set_doorbell_base_vaddr(u64 vaddr);
int npu_get_doorbell_base_vaddr(u64 *vaddr);

#endif
