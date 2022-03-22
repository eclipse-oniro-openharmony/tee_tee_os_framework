/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu resmem
 */
#ifndef NPU_RESMEM_H
#define NPU_RESMEM_H

#include "npu_platform_resource.h"
#include "npu_spec_share.h"
#include "npu_platform.h"

#define CALC_SQ_AREA_NAME	"calc_sq_area"
#define CALC_CQ_AREA_NAME	"calc_cq_area"
#define PERSISTENT_TASK_BUFF_AREA_NAME	"persistent_task_buff_area"
#define L2CTRL_CMA_AREA_NAME	"L2_ctrl_cma_area"
#define TSCPU_LOG_AREA_NAME		"tscpu_log_area"
#define SMMU_QUEUE_AREA_NAME		"smmu_queue_area"
#define NPU_CHIP_CFG_AREA_NAME		"npu_chip_cfg_cfg_area"

int npu_plat_parse_resmem_desc(struct npu_platform_info *plat_info);

int npu_plat_find_resmem_idx(struct npu_platform_info *plat_info, const char* tag, struct npu_mem_desc **result);

typedef struct npu_res_mem_entry {
	char* area_name;
	u64 area_base;
	u32 area_len;
} npu_res_mem_entry_t;

// discribe secure reserve mem layout on teeos(phoneix 10M)
typedef struct npu_res_mem {
	u64 res_mem_base;
	u32 res_mem_len; // total len(10M on phoneix)
	npu_res_mem_entry_t *res_mem_entries;
} npu_res_mem_t;

void npu_res_mem_init(void);

int npu_get_res_mem_area_by_name(const char *area_name, npu_res_mem_entry_t *res_mem_entry);

#endif
