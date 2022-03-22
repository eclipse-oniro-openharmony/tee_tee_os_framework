/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: pal_lib function
 * Author: m00475438
 * Create: 2018-04-17
 */
#include <pal_libc.h>
#include <string.h>

#define BSP_THIS_MODULE BSP_MODULE_SYS

u32 pal_strnlen(const char *s, u32 count)
{
	return strnlen(s, count);
}

s32 pal_strncmp(const char *cs, const char *ct, u32 count)
{
	return strncmp(cs, ct, count);
}

err_bsp_t pal_memequ(const void *s1, const void *s2, u32 len)
{
	if (memcmp((void *)s1, s2, len) == 0)
		return BSP_RET_OK;
	return ERR_HAL(ERRCODE_VERIFY);
}
