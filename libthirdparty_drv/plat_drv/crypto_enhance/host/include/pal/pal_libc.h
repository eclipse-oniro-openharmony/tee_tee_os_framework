/**
 * @file   : pal_libc.h
 * @par    : Copyright (c) 2017-2019, HUAWEI Technology Co., Ltd.
 * @date   : 2018/08/11
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __PAL_LIBC_H__
#define __PAL_LIBC_H__
#include <string.h>
#include <securec.h>
#include <pal_log.h>

/**< goto err_hander when result is not EOK */
#define LIBC_MEM_ERR_GOTO(result, handler) do { \
	if (EOK != result) { \
		PAL_ERROR("errno = "PAL_FMT_PTR"\n", result); \
		ret = ERR_DRV(ERRCODE_MEMORY); \
		goto handler; \
	} \
	else { \
		ret = BSP_RET_OK;\
	} \
} while (0)

/**< return when result is not EOK */
#define LIBC_MEM_ERR_RETURN(result) do { \
	if (EOK != result) { \
		PAL_ERROR("errno = "PAL_FMT_PTR"\n", result); \
		ret = ERR_DRV(ERRCODE_MEMORY); \
		return ret; \
	} \
	else { \
		ret = BSP_RET_OK;\
	} \
} while (0)

err_bsp_t pal_memequ(const void *_s1, const void *_s2, u32 len);
u32 pal_strnlen(const char *s, u32 count);
s32 pal_strncmp(const char *cs, const char *ct, u32 count);
s32 pal_memcmp(const void *_a, const void *_b, u32 len, u32 arev, u32 brev);
s32 pal_strncmp(const char *cs, const char *ct, u32 count);

#endif /* __PAL_LIBC_H__ */
