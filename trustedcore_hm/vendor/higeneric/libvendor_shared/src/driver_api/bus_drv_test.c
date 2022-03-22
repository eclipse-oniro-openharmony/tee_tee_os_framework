/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: hieps drive interface, Analysis of test commands.
 *             call different test interfaces
 * Author:
 * Create: 2020-9-11
 */

#include "hmdrv.h"
#include "mem_page_ops.h"
#include <sre_syscalls_id_ext.h>
#include "tee_log.h"

#ifdef DEF_ENG
uint32_t __tee_call_bus_drivers(uint32_t cmd, const char *parm_info,
	uint32_t parm_size)
{
	uint64_t args[] = {
		(uint64_t)cmd,
		(uint64_t)(uintptr_t)parm_info,
		(uint64_t)parm_size,
	};

	return hm_drv_call(SW_SYSCALL_LSBUS_DRV, args, ARRAY_SIZE(args));
}
#endif