/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: hisp drive interface.
 *              call different test interfaces
 * Author: xiehanhua x00474758
 * Create: 2020-07-06
 */
#include "hmdrv.h"
#include <sre_syscalls_id_ext.h>


int __secisp_mem_end()
{
#ifdef TEE_SUPPORT_SECISP
	uint64_t args[] = {
	};
	return hm_drv_call(SW_SYSCALL_SECISP_MEM_END, args, ARRAY_SIZE(args));
#endif
	return 0;
}

