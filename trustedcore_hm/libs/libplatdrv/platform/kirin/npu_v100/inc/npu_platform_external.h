/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu platform external
 */

#ifndef __NPU_PLATFORM_EXTERNEL_H
#define __NPU_PLATFORM_EXTERNEL_H

enum hisi_svm_id {
	svm_sdma = 0,
	svm_ai,
	svm_ai1,
	svm_max,
};

int npu_get_res_mem_of_smmu(uintptr_t *phy_addr, u32 *len);

#endif
