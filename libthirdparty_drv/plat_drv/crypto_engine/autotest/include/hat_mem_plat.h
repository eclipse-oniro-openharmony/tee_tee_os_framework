/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: memory manager for platform hava autotest
 * Author     : m00475438
 * Create     : 2019/08/09
 */
#ifndef __HAT_MEM_PLAT_H__
#define __HAT_MEM_PLAT_H__

enum hat_mem_option {
	HAT_MEM_OPT_MASTER = 0,  /* bit[0]: convert addr to master */
	HAT_MEM_OPT_CCM,         /* bit[1]: convert memory to ccm */
	HAT_MEM_OPT_DDRENC,      /* bit[2]: convert memory to ddrenc */
	HAT_MEM_OPT_SMMU,        /* bit[3]: convert memory to mmu */
	HAT_MEM_OPT_MAX = 0x08,  /* up to 8 non-default types are supported */
};

enum hat_mem_type {
	HAT_MEM_TYPE_DEF = 0,  /* default autotest pool */
	HAT_MEM_TYPE_TMP,      /* temporary pool */
	HAT_MEM_TYPE_MAX,
};

#endif /* __HAT_MEM_PLAT_H__ */
