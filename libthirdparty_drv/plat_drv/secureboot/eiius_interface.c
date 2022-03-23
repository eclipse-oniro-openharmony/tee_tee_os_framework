/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: eiius driver
 * Create: 2020/04/28
 */

#include "eiius_interface.h"

#include "securec.h"
#include "smc_to_atf.h"
#include "sre_syscall.h"
#include "hm_unistd.h"
#include "hisi_secboot.h"
#include "hisi_secureboot.h"
#include "secboot.h"
#include "drv_task_map.h"
#include "drv_mem.h"
#include "drv_cache_flush.h"
#include "cc_power.h"

static uint64_t g_eiius_addr;

#define EIIUS_WORKSPACE_SIZE    0x10000000

#define EIIUS_WORKSPACE_BASE    g_eiius_addr

#define EIIUS_WORKSPACE1_BASE   EIIUS_WORKSPACE_BASE
#define EIIUS_WORKSPACE1_SIZE   (110 * SZ_1M)

#define EIIUS_WORKSPACE2_BASE   (EIIUS_WORKSPACE1_BASE + EIIUS_WORKSPACE1_SIZE)
#define EIIUS_WORKSPACE2_SIZE   (110 * SZ_1M)

#define EIIUS_INCR_DATA_BASE    (EIIUS_WORKSPACE2_BASE + EIIUS_WORKSPACE2_SIZE)
#define EIIUS_INCR_DATA_SIZE    (35 * SZ_1M)

#define EIIUS_INCR_VRL_BASE     (EIIUS_INCR_DATA_BASE + EIIUS_INCR_DATA_SIZE)
#define EIIUS_INCR_VRL_SIZE     EIIUS_VRL_SIZE

#define EIIUS_O_I_VRL_BASE      (EIIUS_INCR_VRL_BASE + EIIUS_INCR_VRL_SIZE)
#define EIIUS_O_I_VRL_SIZE      EIIUS_VRL_SIZE

#define EIIUS_N_I_VRL_BASE      (EIIUS_O_I_VRL_BASE + EIIUS_O_I_VRL_SIZE)
#define EIIUS_N_I_VRL_SIZE      EIIUS_VRL_SIZE

#define EIIUS_RESERVED_BASE     (EIIUS_N_I_VRL_BASE + EIIUS_N_I_VRL_SIZE)
#define EIIUS_USED_SIZE         (EIIUS_RESERVED_BASE - EIIUS_WORKSPACE_BASE)
#define EIIUS_RESERVED_SIZE     (EIIUS_WORKSPACE_SIZE - EIIUS_USED_SIZE)

#ifndef MAX
#define MAX(a, b)        (((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)        (((a) < (b)) ? (a) : (b))
#endif

static uint32_t eiius_get_img_name(uint32_t vrl_vaddr, char *img_name,
				   uint32_t len)
{
	uint32_t ret;
	struct vrl_additiondata *p_add_data = NULL;

	if (!img_name || vrl_vaddr == 0) {
		tloge("Error: params is invalid in %s\n", __func__);
		return EIIUS_DRV_ERR_PARA;
	}

	p_add_data = (struct vrl_additiondata *)(uintptr_t)vrl_vaddr;

	ret = memcpy_s(img_name, len, p_add_data->partitionname,
		       SECBOOT_PART_NAMELEN);
	if (ret != EOK) {
		tloge("Error: memcpy_s in %s\n", __func__);
		return EIIUS_DRV_ERR_COPY_DATA;
	}

	v7_dma_flush_range((unsigned long)(uintptr_t)img_name,
			   (unsigned long)(uintptr_t)(img_name + SECBOOT_PART_NAMELEN));

	return EIIUS_DRV_SUCCESS;
}

static uint32_t eiius_get_certpkg(uint32_t data_vaddr,
				  uint32_t vrl_vaddr,
				  const char *img_name,
				  struct seb_cert_pkg *p_seb_certpkg,
				  struct vrl_additiondata *p_addition_data)
{
	uint32_t ret;

	ret = seb_fillcertpkg((uint64_t)vrl_vaddr, p_seb_certpkg);
	if (ret != EIIUS_DRV_SUCCESS) {
		tloge("Error: seb_fillcertpkg (0x%x) in %s\n", ret, __func__);
		return ret;
	}

	ret = secboot_check_adddata(p_seb_certpkg, img_name,
				    p_addition_data, TRUE);
	if (ret != EIIUS_DRV_SUCCESS) {
		tloge("Error: secboot_check_adddata in %s\n", __func__);
		return ret;
	}

	/* change the image store address to the RAM address. */
	ret = secboot_changecompstoreaddr(p_seb_certpkg, data_vaddr);
	if (ret != EIIUS_DRV_SUCCESS)
		tloge("Error: secboot_changecompstoreaddr in %s\n", __func__);

	return ret;
}

static uint32_t do_eiius_image_verify(uint32_t data_vaddr,
				      uint32_t data_size,
				      uint32_t vrl_vaddr,
				      enum secboot_seccfg lcs,
				      uint32_t decrypto)
{
	uint32_t ret;
	BOOL be_secure = FALSE;
	BOOL be_burning = FALSE;
	struct seb_cert_pkg seb_certpkg = {0};
	char img_name[SECBOOT_PART_NAMELEN] = {0};
	struct vrl_additiondata addition_data = {0};

	ret = eiius_get_img_name(vrl_vaddr, img_name, sizeof(img_name));
	if (ret != EIIUS_DRV_SUCCESS) {
		tloge("Error: get_img_name fail in %s\n", __func__);
		goto exit;
	}

	ret = eiius_get_certpkg(data_vaddr, vrl_vaddr, img_name,
				&seb_certpkg, &addition_data);
	if (ret != EIIUS_DRV_SUCCESS) {
		tloge("Error: get_certpkg fail in %s\n", __func__);
		goto exit;
	}

	/* using dma cache flush in MP platform instead of flush cache all */
	v7_dma_flush_range(vrl_vaddr, vrl_vaddr + SECBOOT_VRL_SIZE);
	v7_dma_flush_range(data_vaddr, data_vaddr + data_size);

	be_burning = decrypto ? FALSE : TRUE;
	be_secure = (lcs == SECBOOT_SECCFG_SECURE) ? TRUE : FALSE;

	ret = secboot_imageverification(&seb_certpkg, img_name,
					be_secure, TRUE, be_burning);
	if (ret != EIIUS_DRV_SUCCESS) {
		tloge("Error: secboot_imageverification(0x%x) in %s\n",
		      ret, __func__);
	}

exit:
	return ret;
}

static uint32_t check_paddr_range(paddr_t paddr, uint32_t size)
{
	paddr_t start = EIIUS_WORKSPACE_BASE;
	paddr_t end = EIIUS_WORKSPACE_BASE + EIIUS_WORKSPACE_SIZE;

	return !(start <= paddr && paddr < paddr + size && paddr + size <= end);
}

uint32_t eiius_image_verify(paddr_t data_paddr,
			    paddr_t vrl_paddr,
			    uint32_t maxsize,
			    uint32_t decrypto)
{
	uint32_t ret;
	uint32_t data_vaddr = 0;
	uint32_t data_size = 0;
	uint32_t vrl_vaddr = 0;
	enum secboot_seccfg lcs = SECBOOT_SECCFG_ERROR;

	if (check_paddr_range(vrl_paddr, SECBOOT_VRL_SIZE)) {
		tloge("error,vrl paddr info\n");
		return EIIUS_DRV_ERR_PARA;
	}

	/* get the secure configuration. */
	ret = secboot_getseccfg(&lcs);
	if (ret != EIIUS_DRV_SUCCESS) {
		tloge("Error: secboot_getseccfg in %s\n", __func__);
		return ret;
	}

	/* if it is none, we just return. */
	if (lcs == SECBOOT_SECCFG_NONE) {
		tloge("The LCS is None in %s.\n", __func__);
		return EIIUS_DRV_ERR_LCS_NONE;
	}

	if (sre_mmap(vrl_paddr, SECBOOT_VRL_SIZE, &vrl_vaddr, secure, cache)) {
		tloge("Error: map vrl_paddr failed in %s\n", __func__);
		ret = EIIUS_DRV_ERR_MEM_MAP;
		goto exit;
	}

	ret = seb_parservrl(vrl_vaddr, &data_size);
	if (ret != EIIUS_DRV_SUCCESS) {
		tloge("Error:get img size in %s\n", __func__);
		goto exit_unmap_vrl;
	}

	if (data_size > maxsize) {
		tloge("Error: overflow maxsize = 0x%x data_size = 0x%x\n",
		      maxsize, data_size);
		ret = EIIUS_DRV_ERR_DATA_TOO_BIG;
		goto exit_unmap_vrl;
	}

	if (check_paddr_range(data_paddr, data_size)) {
		tloge("error,data paddr info\n");
		ret = EIIUS_DRV_ERR_PARA;
		goto exit_unmap_vrl;
	}

	if (sre_mmap(data_paddr, data_size, &data_vaddr, secure, cache)) {
		tloge("Error: map data_paddr failed in %s\n", __func__);
		ret = EIIUS_DRV_ERR_MEM_MAP;
		goto exit_unmap_vrl;
	}

	ret = do_eiius_image_verify(data_vaddr, data_size,
				    vrl_vaddr, lcs, decrypto);
	if (sre_unmap(data_vaddr, data_size))
		tloge("unmap data_vaddr failed in %s\n", __func__);

exit_unmap_vrl:
	if (sre_unmap(vrl_vaddr, SECBOOT_VRL_SIZE))
		tloge("unmap vrl_vaddr failed in %s\n", __func__);

exit:
	return ret;
}

uint32_t eiius_encrypto_ctr(paddr_t in_paddr,
			    paddr_t out_paddr,
			    uint32_t in_size,
			    uint8_t *iv,
			    uint32_t iv_size,
			    uint32_t crypto_direction)
{
	int res;
	uint32_t ret;
	uint32_t out_vaddr;
	uint32_t in_vaddr = 0;
	uint8_t aes_iv[EIIUS_AES_IV_SIZE] = {0};

	if (!iv) {
		tloge("Error: iv is null in %s\n", __func__);
		return EIIUS_DRV_ERR_PARA;
	}

	if (crypto_direction != EIIUS_DECRYPTO_DATA &&
	    crypto_direction != EIIUS_ENCRYPTO_DATA) {
		tloge("Error: crypto_direction(0x%x)\n", crypto_direction);
		return EIIUS_DRV_ERR_PARA;
	}

	/* !!!Assume the input and output address be identical. */
	if (in_paddr != out_paddr) {
		tloge("Error: in_paddr not equal out_paddr\n");
		return EIIUS_DRV_ERR_PARA;
	}

	if (check_paddr_range(in_paddr, in_size)) {
		tloge("error,encrypto in data paddr\n");
		return EIIUS_DRV_ERR_PARA;
	}

	ret = memcpy_s(aes_iv, sizeof(aes_iv), iv, iv_size);
	if (ret != EOK) {
		tloge("Error: memcpy_s in %s\n", __func__);
		return EIIUS_DRV_ERR_COPY_DATA;
	}

	v7_dma_flush_range((unsigned long)(uintptr_t)aes_iv,
			   (unsigned long)(uintptr_t)(aes_iv + sizeof(aes_iv)));
	/*
	 * The below just list in here, we don't complish it
	 * The output address can't locate in input data range!!
	 * The input address can locate in output date rang.
	 * The input and output address can be identical.
	 * case1:
	 * INPUT : |_________________|
	 * OUTPUT: |_________________|

	 * case2:
	 * INPUT : |__________________|
	 * OUTPUT:           |_________________|

	 * case3:
	 * INPUT : |_________________|
	 * OUTPUT:                   |_________________|

	 * case4:
	 * INPUT : |_________________|
	 * OUTPUT:                     |_________________|

	 * case5:
	 * INPUT :           |__________________|
	 * OUTPUT: |_________________|

	 * case6:
	 * INPUT :                   |_________________|
	 * OUTPUT: |_________________|

	 * case7:
	 * INPUT :                     |_________________|
	 * OUTPUT: |_________________|
	 */

	ret = sre_mmap(in_paddr, in_size, &in_vaddr, secure, cache);
	if (ret != 0) {
		tloge("map in_paddr failed in %s.\n", __func__);
		return EIIUS_DRV_ERR_MEM_MAP;
	}

	out_vaddr = in_vaddr;
	res = secs_power_on();
	if (res != 0) {
		tloge("secs power on failed\n");
		(void)sre_unmap(in_vaddr, in_size);
		return SECBOOT_RET_FAILURE;
	}

	ret = seb_eiius_crypto((uint64_t)in_vaddr, in_size, (uint64_t)out_vaddr,
			       (uint64_t)(uintptr_t)aes_iv, sizeof(aes_iv),
			       crypto_direction);

	(void)sre_unmap(in_vaddr, in_size);
	res = secs_power_down();
	if (res != 0) {
		tloge("secs power down failed\n");
		return SECBOOT_RET_FAILURE;
	}

	return ret;
}

static uint32_t eiius_workspace_addr(uint32_t *low_paddr,
				     uint32_t *high_paddr,
				     uint32_t *p_size,
				     uint32_t addr_type)
{
	uint32_t ret = 0;

	switch (addr_type) {
	case  EIIUS_ADDR_WORKSPACE1_TYPE:
		*low_paddr = (EIIUS_WORKSPACE1_BASE & 0xffffffff);
		*high_paddr = (uint64_t)EIIUS_WORKSPACE1_BASE >> 32;
		*p_size = EIIUS_WORKSPACE1_SIZE;
		break;

	case  EIIUS_ADDR_WORKSPACE2_TYPE:
		*low_paddr = (EIIUS_WORKSPACE2_BASE & 0xffffffff);
		*high_paddr = (uint64_t)EIIUS_WORKSPACE2_BASE >> 32;
		*p_size = EIIUS_WORKSPACE2_SIZE;
		break;

	case  EIIUS_ADDR_INCR_DATA_TYPE:
		*low_paddr = (EIIUS_INCR_DATA_BASE & 0xffffffff);
		*high_paddr = (uint64_t)EIIUS_INCR_DATA_BASE >> 32;
		*p_size = EIIUS_INCR_DATA_SIZE;
		break;

	case  EIIUS_ADDR_INCR_VRL_TYPE:
		*low_paddr = (EIIUS_INCR_VRL_BASE & 0xffffffff);
		*high_paddr = (uint64_t)EIIUS_INCR_VRL_BASE >> 32;
		*p_size = EIIUS_INCR_VRL_SIZE;
		break;

	case  EIIUS_ADDR_O_I_VRL_TYPE:
		*low_paddr = (EIIUS_O_I_VRL_BASE & 0xffffffff);
		*high_paddr = (uint64_t)EIIUS_O_I_VRL_BASE >> 32;
		*p_size = EIIUS_O_I_VRL_SIZE;
		break;

	case  EIIUS_ADDR_N_I_VRL_TYPE:
		*low_paddr = (EIIUS_N_I_VRL_BASE & 0xffffffff);
		*high_paddr = (uint64_t)EIIUS_N_I_VRL_BASE >> 32;
		*p_size = EIIUS_N_I_VRL_SIZE;
		break;

	case  EIIUS_ADDR_STUB_TYPE:
		*low_paddr = 0;
		*high_paddr = 0;
		*p_size = 0;
		break;

	case  EIIUS_ADDR_RESERVED_TYPE:
		*low_paddr = (EIIUS_RESERVED_BASE & 0xffffffff);
		*high_paddr = (uint64_t)EIIUS_RESERVED_BASE >> 32;
		*p_size = EIIUS_RESERVED_SIZE;
		break;

	default:
		*low_paddr = 0;
		*high_paddr = 0;
		*p_size = 0;
		ret = EIIUS_DRV_ERR_PARA;
		break;
	}
	return ret;
}

uint32_t eiius_get_paddr(uint32_t *low_paddr,
			 uint32_t *high_paddr,
			 uint32_t *p_size,
			 uint32_t addr_type)
{
	uint32_t ret;
	uint32_t eiius_size = 0;

	if (!low_paddr) {
		tloge("Error: low_paddr is NULL\n");
		return EIIUS_DRV_ERR_PARA;
	}

	if (!high_paddr) {
		tloge("Error: high_paddr is NULL\n");
		return EIIUS_DRV_ERR_PARA;
	}

	if (!p_size) {
		tloge("Error: p_size is NULL\n");
		return EIIUS_DRV_ERR_PARA;
	}

	if (addr_type >= EIIUS_ADDR_MAX_TYPE) {
		tloge("Error: addr_type = 0x%x\n", addr_type);
		return EIIUS_DRV_ERR_PARA;
	}

	ret = eiius_get_workspace_info(&g_eiius_addr, &eiius_size);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("Error: eiius get workspace info\n");
		return EIIUS_DRV_ERR_PARA;
	}

	if (g_eiius_addr == 0 || eiius_size < EIIUS_WORKSPACE_SIZE) {
		tloge("Error: eiius workspace info error\n");
		return EIIUS_DRV_ERR_PARA;
	}

	return eiius_workspace_addr(low_paddr, high_paddr, p_size, addr_type);
}

uint32_t eiius_secure_memory_map(paddr_t paddr,
				 uint32_t size,
				 uint32_t *vaddr,
				 uint32_t secure_mode,
				 uint32_t cache_mode)
{

	if (check_paddr_range(paddr, size)) {
		tloge("Error: paddr = 0x%llx size = 0x%x\n",
		      (uint64_t)paddr, size);
		return EIIUS_DRV_ERR_MEM_MAP;
	}

	if (!vaddr) {
		tloge("Error: vaddr is NULL\n");
		return EIIUS_DRV_ERR_MEM_MAP;
	}

	if (drv_map_paddr_to_task(paddr, size, vaddr, secure_mode, cache_mode))
		return EIIUS_DRV_ERR_MEM_MAP;
	else
		return EIIUS_DRV_SUCCESS;
}

uint32_t eiius_secure_memory_unmap(uint32_t vaddr, uint32_t size)
{
	if (drv_unmap_from_task(vaddr, size))
		return EIIUS_DRV_ERR_MEM_UNMAP;
	else
		return EIIUS_DRV_SUCCESS;
}
