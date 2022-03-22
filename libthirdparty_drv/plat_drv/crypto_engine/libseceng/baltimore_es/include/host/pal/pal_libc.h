/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: pal for libc
 * Author     : l00370476, liuchong13@huawei.com
 * Create     : 2018/08/11
 */
#ifndef __PAL_LIBC_H__
#define __PAL_LIBC_H__
#include <string.h>
#include <securec.h>
#include <pal_libc_plat.h>

u32 pal_atoi(const char *s);

/* convert memory libc error code to bsp error code */
#define LIBC_MEM_CNV_ERRCODE(libc_ret) \
	(((libc_ret) != EOK) ? ERR_DRV(ERRCODE_MEMORY) : BSP_RET_OK)

#endif /* __PAL_LIBC_H__ */
