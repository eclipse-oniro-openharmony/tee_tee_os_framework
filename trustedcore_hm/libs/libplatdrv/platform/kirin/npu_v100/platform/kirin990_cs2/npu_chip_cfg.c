/*
 * npu_chip_cfg.c
 *
 * about chip config
 *
 * Copyright (c) 2012-2019 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "mem_mode.h" /* non_cache */
#include "drv_log.h"
#include "drv_mem.h" /* sre_mmap */
#include "npu_common.h"
#include "npu_platform.h"
#include "npu_adapter.h"
#include "npu_resmem.h"

static uint32_t s_aicore_disable_map = 0xff;

static int npu_plat_get_chip_cfg()
{
	int ret;
	uint32_t drv_vaddr = 0;
	struct npu_chip_cfg *chip_cfg = NULL;

	ret = sre_mmap(NPU_S_CHIP_CFG_ADDR, NPU_S_CHIP_CFG_SIZE, &drv_vaddr, secure, non_cache);
	COND_RETURN_ERROR(ret, -ENOMEM, "sre_map NPU_SHM_NPU_CONFIG failed err = %d", ret);

	chip_cfg = (struct npu_chip_cfg *)(uintptr_t)drv_vaddr;
	COND_RETURN_ERROR(chip_cfg == NULL, -EINVAL, "ioremap error, pa:0x%lx, size:0x%x\n",
		NPU_S_CHIP_CFG_ADDR, NPU_S_CHIP_CFG_SIZE);
	COND_RETURN_ERROR(chip_cfg->valid_magic != NPU_DDR_CONFIG_VALID_MAGIC,
		-EINVAL, "va_npu_config valid_magic:0x%x is not valid\n",
		chip_cfg->valid_magic);
	NPU_DEBUG("aicore_disable_bitmap = %u\n", chip_cfg->aicore_disable_bitmap);
	s_aicore_disable_map = chip_cfg->aicore_disable_bitmap;
	return 0;
}

/*
 * return value : 1 disable core; 0 not disable core
 */
int npu_plat_aicore_get_disable_status(int core_id)
{
	int ret;
	int aicore_disable = 0;

	if (s_aicore_disable_map == 0xff) {
		ret = npu_plat_get_chip_cfg();
		if (ret != 0) {
			return 0;
		}
	}

	aicore_disable = BITMAP_GET(s_aicore_disable_map, (uint32_t)core_id);

	return aicore_disable;
}
