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
#include "npu_base_define.h"
#include "npu_log.h"
#include "npu_dev_ctx_mngr.h"

#define NPU_DDR_CONFIG_VALID_MAGIC      0X5A5A5A5A

#define BITMAP_GET(val, pos)            (((val) >> (pos)) & 0x01)

struct npu_chip_cfg {
	u32 valid_magic; /* if value is 0x5a5a5a5a, valid_magic is ok */
	u32 aicore_disable_bitmap; /* bit0 is aicore0, bit1 is aicore1;each bit:0:enable 1:disable */
	u32 platform_specification; /* follow efuse Grading chip type */
};

static u32 s_aicore_disable_map = 0xff;

static int npu_plat_get_chip_cfg()
{
	int ret;
	u32 drv_vaddr = 0;
	struct npu_chip_cfg *chip_cfg = NULL;

	ret = npu_get_res_mem_of_chip_cfg(&drv_vaddr);
	COND_RETURN_ERROR(ret, ret, "npu_get_res_mem_of_chip_cfg failed err = %d", ret);

	chip_cfg = (struct npu_chip_cfg *)(uintptr_t)drv_vaddr;
	COND_RETURN_ERROR(chip_cfg == NULL, -EINVAL, "ioremap error\n");
	COND_RETURN_ERROR(chip_cfg->valid_magic != NPU_DDR_CONFIG_VALID_MAGIC,
		-EINVAL, "va_npu_config valid_magic:0x%x is not valid\n",
		chip_cfg->valid_magic);
	NPU_DRV_WARN("aicore_disable_bitmap = %u platform_specification\n",
		chip_cfg->aicore_disable_bitmap, chip_cfg->platform_specification);
	s_aicore_disable_map = chip_cfg->aicore_disable_bitmap;
	return 0;
}

/*
 * return value : 1 disable core; 0 not disable core
 */
int npu_plat_aicore_get_disable_status(int core_id)
{
	int ret;
	int aicore_disable;

	if (s_aicore_disable_map == 0xff) {
		ret = npu_plat_get_chip_cfg();
		if (ret != 0)
			return 0;
	}

	aicore_disable = BITMAP_GET(s_aicore_disable_map, (u32)core_id);

	return aicore_disable;
}
