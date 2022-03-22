/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu reg
 */

#include "npu_reg.h"
#include <stdint.h>

#include "drv_log.h"
#include "npu_platform.h"
#include "npu_adapter.h"
#include "svm.h"
#include "npu_platform_register.h"

#define npu_udelay(usec)                                                      \
	do {                                                                   \
		int i;                                                         \
		for (i = 0; i < 500 * (usec); i++) {                             \
			asm("nop");                                            \
		};                                                             \
	} while (0)


struct npu_mem_desc* npu_plat_get_reg_desc(u32 reg_idx)
{
	struct npu_platform_info *plat_info = NULL;

	plat_info = npu_plat_get_info();
	if (plat_info == NULL) {
		NPU_ERR("get plat_info failed\n");
		return NULL;
	}

	return &DEVDRV_PLAT_GET_REG_DESC(plat_info, reg_idx);
}

u32* npu_plat_get_reg_vaddr(u32 reg_idx, u32 offset)
{
	struct npu_platform_info *plat_info = NULL;

	plat_info = npu_plat_get_info();
	if (plat_info == NULL) {
		NPU_ERR("get plat_info failed\n");
		return NULL;
	}
	return (u32 *)((u8*)DEVDRV_PLAT_GET_REG_VADDR(plat_info, reg_idx) + offset);
}

int npu_plat_unmap_reg(struct npu_platform_info *plat_info)
{
	(void)plat_info;
	return 0;
}

int npu_plat_parse_reg_desc(struct npu_platform_info *plat_info)
{
	struct npu_mem_desc* mem_desc = NULL;

	if (plat_info == NULL) {
		NPU_ERR("invalid param plat_info is null\n");
		return -1;
	}

	mem_desc = &DEVDRV_PLAT_GET_REG_DESC(plat_info, DEVDRV_REG_TS_DOORBELL);
	mem_desc->base = TS_DOORBELL_BASE_ADDR;
	mem_desc->len = TS_DOORBELL_BASE_ADDR_SIZE;
	NPU_DEBUG("resource: base %pK len %x\n", (void *)(uintptr_t)(u64)mem_desc->base, mem_desc->len);

	mem_desc = &DEVDRV_PLAT_GET_REG_DESC(plat_info, DEVDRV_REG_TS_SRAM);
	mem_desc->base = TS_SRAM_BASE_ADDR;
	mem_desc->len = TS_SRAM_BASE_ADDR_SIZE;
	NPU_DEBUG("resource: base %pK len %x\n", (void *)(uintptr_t)(u64)mem_desc->base, mem_desc->len);

	mem_desc = &DEVDRV_PLAT_GET_REG_DESC(plat_info, DEVDRV_REG_L2BUF_BASE);
	mem_desc->base = L2BUF_BASE_BASE_ADDR;
	mem_desc->len = L2BUF_BASE_BASE_ADDR_SIZE;
	NPU_DEBUG("resource: base %pK len %x\n", (void *)(uintptr_t)(u64)mem_desc->base, mem_desc->len);

	return 0;
}

/* temporarily use, to be change later */

static unsigned npu_plat_regs[DEVDRV_REG_MAX_REG] = {
	[DEVDRV_REG_POWER_STATUS] = DRV_NPU_POWER_STATUS_REG,
};

/* return:  0--error */
unsigned npu_plat_get_vaddr(npu_reg_type reg_type)
{
	if (reg_type >= DEVDRV_REG_MAX_REG) {
		NPU_ERR("invalid reg_type %d\n", reg_type);
		return 0;
	}

	return npu_plat_regs[reg_type];
}

int npu_pm_query_ree_status(void)
{
	uint32_t  readval, addr;
	addr = npu_plat_get_vaddr(DEVDRV_REG_POWER_STATUS);
	if (addr == 0) {
		return NPU_POWER_ON;
	}

	readval = hisi_readl(addr);
	NPU_DEBUG("readval = 0x%x, addr = 0x%x\n", readval, addr);
	return (readval == DRV_NPU_POWER_ON_FLAG) ? NPU_POWER_ON : NPU_POWER_OFF;
}

void npu_reg_update(uint64_t addr, uint32_t mask, uint32_t value)
{
	uint32_t readval = 0;

	readval = hisi_readl(addr);
	readval = (readval & (~mask)) | (value & mask);
	hisi_writel(readval, addr);
}

int npu_read_wait(uint64_t addr,
	uint32_t expect_val,
	uint32_t mask,
	uint32_t wait_time)
{
	uint32_t  readval = 0;
	uint32_t time_cnt = 0;

	while (time_cnt <= wait_time) {
		readval = hisi_readl(addr);
		if ((readval & mask) == (expect_val & mask)) {
			return 0;
		}
		npu_udelay(1);
		time_cnt++;
	}

	NPU_DEBUG("read [%s] value failed !REG.addr:0x%lx,mask:0x%x,"
		"readval:0x%x,expect_val=0x%x",
		__func__,addr,mask,readval,expect_val);
	return -1;
}