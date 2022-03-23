/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: common func provided for drv.c, hal.c, reg.c and external
 * Author: z00293770
 * Create: 2019-12-02
 */

#include <sec_utils.h>
#include <stdlib.h>
#include <common_utils.h>
#include <pal_memory.h>
#include <pal_libc.h>

/* set the module to which the file belongs each .C file needs to be configured */
#define BSP_THIS_MODULE BSP_MODULE_SYS

/* enum for operation_mode */
enum endian_convert_e {
	BIGENDIAN_2_LITTLEENDIAN = 0,
	LITTLEENDIAN_2_BIGENDIAN = 1,
	OPERATION_UNKNOWN,
};

static void *sec_memcpy_invert(void *pdst, const void *psrc, u32 wlen)
{
	u32 value;
	u32 *dst = (u32 *)pdst;
	const u32 *src = (const u32 *)psrc;

	src = &src[wlen - 1];

	while (wlen > 0) {
		wlen--;
		value = pal_read_u32(src);
		value = U32_REV(value);
		pal_write_u32(value, dst);
		src--;
		dst++;
	}

	return pdst;
}

static err_bsp_t sec_convert_endian(u8 *dst, u32 dst_max, u8 *src, u32 src_len, enum endian_convert_e operation)
{
	u32 align_size;
	u8 *buf = NULL;
	errno_t libc_ret = EINVAL;
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	if (!dst || !src)
		return ERR_API(ERRCODE_NULL);

	if (src_len == 0)
		return ERR_API(ERRCODE_PARAMS);

	align_size = SIZE_ALIGN_IN_WORD(src_len);
	PAL_CHECK_RETURN((dst_max < align_size) || (align_size == 0), ERR_API(ERRCODE_PARAMS));

	/* private, ignore address crossover */
	if (align_size == src_len && dst != src) {
		sec_memcpy_invert(dst, src, BYTE2WORD(src_len));
		return BSP_RET_OK;
	}

	buf = (u8 *)malloc(align_size);
	PAL_CHECK_RETURN(!buf, ERR_API(ERRCODE_MEMORY));

	if (operation == BIGENDIAN_2_LITTLEENDIAN) {
		if (align_size > src_len)
			(void)memset_s(buf, align_size, 0, align_size - src_len);
		libc_ret = memcpy_s((buf + align_size - src_len), src_len, src, src_len);
		PAL_CHECK_GOTO(libc_ret != EOK, ERR_API(ERRCODE_MEMORY), sec_return);
	} else {
		if (align_size > src_len)
			(void)memset_s(buf + src_len, align_size - src_len, 0, align_size - src_len);
		libc_ret = memcpy_s(buf, align_size, src, src_len);
		PAL_CHECK_GOTO(libc_ret != EOK, ERR_API(ERRCODE_MEMORY), sec_return);
	}

	sec_memcpy_invert(dst, buf, BYTE2WORD(align_size));

sec_return:
	if (buf)
		free(buf);
	if (libc_ret != EOK)
		return ret;
	return BSP_RET_OK;
}

err_bsp_t sec_convert_big_to_little_endian(u8 *dst, u32 dst_max, u8 *src, u32 src_len)
{
	return sec_convert_endian(dst, dst_max, src, src_len, BIGENDIAN_2_LITTLEENDIAN);
}

err_bsp_t sec_convert_little_to_big_endian(u8 *dst, u32 dst_max, u8 *src, u32 src_len)
{
	return sec_convert_endian(dst, dst_max, src, src_len, LITTLEENDIAN_2_BIGENDIAN);
}

