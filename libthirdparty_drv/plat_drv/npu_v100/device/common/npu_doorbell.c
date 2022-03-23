/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about doorbell
 */

#include "npu_doorbell.h"

#include "drv_log.h"

#include "npu_common.h"
#include "npu_pm.h"
#include "npu_platform.h"
#include "npu_reg.h"

static u64 doorbell_base = 0;
static u32 doorbell_stride = 0x1000;

void npu_set_doorbell_base_vaddr(u64 vaddr)
{
	doorbell_base = vaddr;
}

int npu_get_doorbell_base_vaddr(u64 *vaddr)
{
	if (vaddr == NULL) {
		NPU_ERR("out param vaddr is null\n");
		return -1;
	}

	if (doorbell_base == 0) {
		NPU_ERR("doorbell_base_vaddr is null, maybe npu is not powered up now\n");
		return -1;
	}

	*vaddr = doorbell_base;

	return 0;
}

int npu_write_doorbell_val(u32 type, u32 index, u32 val)
{
	u32 *addr = NULL;
	u8 db_idx = 0;
	UNUSED(index);

	NPU_DEBUG("type = %d index = %d val = %d", type, index, val);

	if (doorbell_base == 0) {
		NPU_ERR("doorbell_base_vaddr is null, maybe npu is not powered up now\n");
		return -1;
	}

	if (type == DOORBELL_RES_MAILBOX) {
		db_idx = DEVDRV_DOORBELL_MAILBOX_INDEX;
	} else if (type == DOORBELL_RES_CAL_CQ) {
		db_idx = DEVDRV_DOORBELL_FIRST_CALC_CQ_INDEX;
	} else {
		NPU_ERR("input type para = %u is invalid\n", type);
		return -1;
	}

	addr = (u32 *) (uintptr_t) (doorbell_base + doorbell_stride * db_idx);

	NPU_DEBUG("npu db_idx %d index %d addr %p, base %p \n",
		db_idx, index, (unsigned long long *)addr,
		(void *)(uintptr_t) doorbell_base);

	if (npu_pm_query_ree_status() != NPU_POWER_ON) {
		NPU_ERR("npu is power down, unable to write doorbell");
		return -1;
	}
	*addr = val;

	isb();

	return 0;
}
