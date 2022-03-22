/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu resmem
 */

#include "npu_resmem.h"

#include <string.h>
#include <errno.h>

#include "drv_log.h"
#include "npu_platform_resource.h"
#include "npu_adapter.h"

#define DEVDRV_RESMEM_LEN_NAME  "reserved_memory_len"
#define DEVDRV_RESMEM_BASE_NAME "reserved_memory_base"
#define DEVDRV_RESMEM_TSFW_NAME "ts_fw_buf_idx"
#define DEVDRV_RESMEM_AIFW_NAME "ai_fw_buf_idx"
#define DEVDRV_RESMEM_SQCQ_NAME "sqcq_buf_idx"

static npu_res_mem_t s_res_mem = {0};

npu_res_mem_entry_t s_res_mem_entries[] = {
	{ CALC_SQ_AREA_NAME, NPU_S_CALC_SQ_AERA_ADDR, NPU_S_CALC_SQ_AERA_SIZE },
	{ CALC_CQ_AREA_NAME, NPU_S_CALC_CQ_AERA_ADDR, NPU_S_CALC_CQ_AERA_SIZE },
	{ PERSISTENT_TASK_BUFF_AREA_NAME, NPU_S_TASKPOOL_ADDR, NPU_S_TASKPOOL_SIZE },
	{ L2CTRL_CMA_AREA_NAME, NPU_S_L2CTRL_CMA_ADDR, NPU_S_L2CTRL_CMA_SIZE },
	{ TSCPU_LOG_AREA_NAME, NPU_S_TS_LOG_ADDR, NPU_S_TS_LOG_SIZE },
	{ SMMU_QUEUE_AREA_NAME, NPU_S_SMMU_QUEUE_ADDR, NPU_S_SMMU_QUEUE_SIZE },
	{ NPU_CHIP_CFG_AREA_NAME, NPU_S_CHIP_CFG_ADDR, NPU_S_CHIP_CFG_SIZE },
};

void npu_res_mem_init(void)
{
	u32 area_idx;
	u32 area_num = sizeof(s_res_mem_entries) / sizeof(npu_res_mem_entry_t);

	s_res_mem.res_mem_base = NPU_SEC_RESERVED_DDR_BASE_ADDR;
	s_res_mem.res_mem_len = NPU_SEC_RESERVED_DDR_SIZE;
	s_res_mem.res_mem_entries = s_res_mem_entries;

	for (area_idx = 0; area_idx < area_num; area_idx++) {
		NPU_INFO("%s base_addr = %p area_len = 0x%x",
			s_res_mem_entries[area_idx].area_name,
			(void *)(uintptr_t)s_res_mem_entries[area_idx].area_base,
			s_res_mem_entries[area_idx].area_len);
	}
}

// res_mem_entry is a out param
int npu_get_res_mem_area_by_name(const char *area_name, npu_res_mem_entry_t *res_mem_entry)
{
	u32 area_idx;
	u32 area_num = sizeof(s_res_mem_entries) / sizeof(npu_res_mem_entry_t);

	if (area_name == NULL || res_mem_entry == NULL) {
		NPU_ERR("param is null");
		return -1;
	}

	for (area_idx = 0; area_idx < area_num; area_idx++) {
		if (strcmp(s_res_mem_entries[area_idx].area_name, area_name) == 0) {
			res_mem_entry->area_base = s_res_mem_entries[area_idx].area_base;
			res_mem_entry->area_len = s_res_mem_entries[area_idx].area_len;

			NPU_INFO("find %s base_addr = %p area_len = 0x%x",
				s_res_mem_entries[area_idx].area_name,
				(void *)(uintptr_t)s_res_mem_entries[area_idx].area_base,
				s_res_mem_entries[area_idx].area_len);
			return 0;
		}
	}

	NPU_ERR("invalid area_name = %s ", area_name);
	return -1;
}

// external interface for smmu
int npu_get_res_mem_of_smmu(uintptr_t *phy_addr_ptr, u32 *len_ptr)
{
	if (phy_addr_ptr == NULL || len_ptr == NULL) {
		NPU_ERR("invalid param, phy_addr_ptr = %p ,len_ptr = %p", phy_addr_ptr, len_ptr);
		return -1;
	}

	if (npu_plat_sec_enable_status() != NPU_SEC_FEATURE_SUPPORTED) {
		*phy_addr_ptr = 0;
		*len_ptr = 0;
		return 0;
	}

	*phy_addr_ptr = NPU_S_SMMU_QUEUE_ADDR;
	*len_ptr = NPU_S_SMMU_QUEUE_SIZE;
	if (*phy_addr_ptr == 0 || *len_ptr == 0) {
		NPU_ERR("unset, *phy_addr_ptr = %x ,*len_ptr = %x", *phy_addr_ptr, *len_ptr);
		return -1;
	}
	return 0;
}

int npu_plat_find_resmem_idx(struct npu_platform_info *plat_info, const char* tag, struct npu_mem_desc **result)
{
	u32 index = 0;
	struct npu_mem_desc *desc = NULL;

	if (strcmp(tag, DEVDRV_RESMEM_SQCQ_NAME) == 0) {
		index = SQ_CQ_BUF_IDX;
	}

	NPU_DEBUG("tag %s index %d\n", tag, index);

	if (index <= 0 || index > DEVDRV_RESMEM_MAX_RESOURCE) {
		NPU_ERR("index %d out of range\n", index);
		return -1;
	}

	desc = &DEVDRV_PLAT_GET_RESMEM_DESC(plat_info, index-1);
	if ((desc->base == 0) || (desc->len == 0)) {
		NPU_ERR("found resmem desc %d NULL: base=%x, len=%x\n", index, desc->base, desc->len);
		return -1;
	}

	NPU_DEBUG("found resmem desc %d base %x len %x\n", index, desc->base, desc->len);

	*result = desc;
	return 0;
}

int npu_plat_check_resmem_overlap(struct npu_platform_info *plat_info, int index, u32 base, u32 len)
{
	int i;
	u32 comp_base;
	u32 comp_len;

	for (i = 0; i < index; i++) {
		comp_base = DEVDRV_PLAT_GET_RESMEM_DESC(plat_info, i).base;
		comp_len = DEVDRV_PLAT_GET_RESMEM_DESC(plat_info, i).len;
		if ((comp_base == 0) || (comp_len == 0)) {
			NPU_DEBUG("from resmem desc %d NULL: base=%x, len=%x\n", i, comp_base, comp_len);
			return 0;
		}
		if (((comp_base + comp_len) > base) || ((base + len) < comp_base)) {
			NPU_ERR("overlap with resmem desc %d: base=%x, len=%x"
				"comp_base=%x, comp_len=%x\n", i, base, len,
				comp_base, comp_len);
			return -1;
		}
	}
	return 0;
}

int npu_plat_parse_resmem_desc(struct npu_platform_info *plat_info)
{
	u32 desc_count;
	u32 index;
	int ret;
	u32 base;
	u32 len;

	base = NPU_SEC_RESERVED_DDR_BASE_ADDR;
	desc_count = sizeof(reserv_mem_lens) / sizeof(u32);
	if ((desc_count > DEVDRV_RESMEM_MAX_RESOURCE) || (desc_count <= 0)) {
		NPU_ERR("desc_count = %d, out of range\n", desc_count);
		return -1;
	}

	NPU_DEBUG("desc_count = %d \n", desc_count);
	for (index = 0; index < desc_count; index++) {
		len = reserv_mem_lens[index];
		NPU_DEBUG("resmem_base_addr[%d] = 0x%x len = 0x%x \n", index, base, len);
		ret  = npu_plat_check_resmem_overlap(plat_info, index, base, len);
		if (ret < 0) {
			NPU_ERR("resmem %d overlaps\n", index);
			return ret;
		}
		DEVDRV_PLAT_GET_RESMEM_DESC(plat_info, index).base = base;
		DEVDRV_PLAT_GET_RESMEM_DESC(plat_info, index).len = len;
		base += len;
	}

	return 0;
}

