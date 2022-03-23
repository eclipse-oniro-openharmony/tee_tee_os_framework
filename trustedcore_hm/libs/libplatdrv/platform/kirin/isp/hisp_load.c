/*
 * hisilicon ISP driver, hisp_load.c
 *
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 *
 */
#include <hisi_debug.h>
#include <securec.h>
#include <stdint.h>
#include <sre_typedef.h> // UINT32
#include <drv_mem.h> // sre_mmap
#include <drv_cache_flush.h> // v7_dma_flush_range
#include "mem_page_ops.h"
#include "hisp_load.h"
#include "sec_region_ops.h"
#include "secmem.h"
#include "hisi_boot.h"
#include "hisp.h"

static UINT32 hisp_img_copy(const UINT64 src_addr, UINT32 sfd, UINT32 len)
{
	UINT32 tmp_src_addr;
	UINT32 tmp_dst_addr;
	UINT32 ret;
	UINT32 retval;

	ret = sre_mmap(src_addr, len, &tmp_src_addr, secure, non_cache);
	if (ret) {
		ISP_ERR("map src buffer addr = 0x%x error1", src_addr);
		return SECISP_INVAILD_ADDR_MAP;
	}

	ISP_DEBUG("src_addr.0x%llx, map for tmp_src_addr.0x%x, nothing to do.", src_addr, tmp_src_addr);
	tmp_dst_addr = sion_mmap_sfd(sfd, len, DDR_SEC_FACE, secure, 1, 0);
	if (tmp_dst_addr == 0) {
		ISP_ERR("map dst buffer error2");
		(void)sre_unmap(tmp_src_addr, len);
		return SECISP_INVAILD_ADDR_MAP;
	}

	ISP_DEBUG("map for tmp_dst_addr.0x%x, nothing to do.", tmp_dst_addr);
	retval = memcpy_s((void *)(uintptr_t)tmp_dst_addr, len, (void *)(uintptr_t)tmp_src_addr, len);
	if (retval) {
		ISP_ERR("hisp_img_copy memcpy_s error");
		retval = SECISP_FAIL;
		goto memcpy_error;
	}

	retval = SECISP_SUCCESS;
	/* using dma cache flush in MP platform instead of flush cache all */
	v7_dma_flush_range(tmp_dst_addr, tmp_dst_addr + len);
memcpy_error:
	(void)sre_unmap(tmp_src_addr, len);
	(void)sion_munmap_sfd(sfd, tmp_dst_addr, len, DDR_SEC_FACE, secure, 0);

	return retval;
}

UINT32 hisp_sec_text_img_copy(UINT32 sfd, UINT32 size)
{
	UINT32 ret;

	if (size != SEC_ISP_IMG_TEXT_SIZE) {
		ISP_ERR("fail, size(0x%x), text size(0x%x).", size, SEC_ISP_IMG_TEXT_SIZE);
		return SECISP_BAD_PARA;
	}

	ret = hisp_img_copy(SEC_ISP_IMG_TEXT_BASE_ADDR, sfd, size);
	if (ret != SECISP_SUCCESS)
		ISP_ERR("fail, hisp_img_copy, ret.%u.", ret);

	return ret;
}

UINT32 hisp_sec_data_img_copy(UINT32 sfd, UINT32 size)
{
	UINT32 ret;

	if (size < SEC_ISP_IMG_DATA_SIZE) {
		ISP_ERR("fail, size.0x%x, text size.0x%x.", size, SEC_ISP_IMG_DATA_SIZE);
		return SECISP_BAD_PARA;
	}

	ret = hisp_img_copy(SEC_ISP_IMG_DATA_BASE_ADDR, sfd, SEC_ISP_IMG_DATA_SIZE);
	if (ret != SECISP_SUCCESS)
		ISP_ERR("fail, hisp_img_copy, ret.%d.", ret);

	return ret;
}

