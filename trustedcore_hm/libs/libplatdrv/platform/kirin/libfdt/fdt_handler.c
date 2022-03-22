/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secos get dt hander
 * Create: 2020-04-30
 */
#include <bl2_sharedmem.h>
#include "hm_mman_ext.h"
#include "fdt_handler.h"


uintptr_t get_fwdt_handler()
{
	int ret;
	uint64_t single_dtb_phy_addr;
	uint32_t single_dtb_phy_size;
	uintptr_t single_dtb_addr;

	ret = get_fwdt_shared_mem(&single_dtb_phy_addr, &single_dtb_phy_size);
	if (ret)
		return ret;

	single_dtb_addr = (uintptr_t)hm_mmap_physical(NULL, single_dtb_phy_size,
		PROT_READ | PROT_WRITE, single_dtb_phy_addr);

	return single_dtb_addr;
}
