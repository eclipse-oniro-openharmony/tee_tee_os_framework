/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: memory manager for hava autotest
 * Author     : m00475438
 * Create     : 2019/08/09
 */
#include <hat_memory.h>
#include <pal_libc.h>
#include <eps_ddr_layout_define.h>

/* set the module to which the file belongs
 * each .C file needs to be configured
 */
#define BSP_THIS_MODULE BSP_MODULE_SYS

#define HAT_DDR_DEF_SIZE    HIEPS_SHARE_DDR_RESERVED_SIZE
#define HAT_DDR_DEF_ADDR    \
	EPS_SHARE_DDR_RESERVED_ADDR(HIEPS_DDR_SPACE_BASE_ADDR)

enum hat_mem_flag {
	HAT_MEM_FLAG_INIT = 0,
};

struct hat_mem_item g_hat_mem_mgr[] = {
	HAT_MEM_ITEM("def", HAT_MEM_TYPE_DEF, 0,
		     HAT_DDR_DEF_ADDR, HAT_DDR_DEF_SIZE),
};

const struct hat_mem_item *hat_mem_get_item(u32 is_opt, u32 t)
{
	err_bsp_t ret;
	struct hat_mem_item *pmem = NULL;

	pmem = hat_mem_lookup(is_opt, t,
			      ARRAY_SIZE(g_hat_mem_mgr),
			      g_hat_mem_mgr);
	if (!pmem)
		return NULL;

	/* check */
	if (BIT_CHK(pmem->flag, HAT_MEM_FLAG_INIT))
		return pmem;

	/* init */
	ret = pal_heap_init(pmem->pool, pmem->size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return NULL;
	BIT_SET(&pmem->flag, HAT_MEM_FLAG_INIT);
	return pmem;
}

