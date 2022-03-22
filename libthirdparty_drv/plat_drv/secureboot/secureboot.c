/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
 *  Description: hisi security for kirin platform
 * Create: 2013/5/16
 */
#ifdef CONFIG_COLD_PATCH_BORROW_DDR
#include <product_config_drv.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <sre_debug.h> // uart_printf
#include <drv_mem.h> // sre_mmap
#include <drv_cache_flush.h> // v7_dma_flush_range
#include <register_ops.h> // writel
#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include <sre_typedef.h>
#include <platform.h>
#include <bsp_modem_call.h>
#include <mem_page_ops.h>
#include <drv_module.h>
#include <drv_pal.h>
#include <drv_legacy_def.h>
#include <hisi_isp.h>
#include <ivp.h>
#include <process_hifi_info.h>
#include <process_modem_info.h>
#include <process_isp_info.h>
#include <process_ivp_info.h>
#include <hifi.h>
#include "bsp_secboot_adp.h"
#include "hisi_seclock.h"
#include "secboot.h"
#include "sec_derive_cuid.h"
#include <securec.h>
#include "tee_log.h"
#include "eiius_interface.h"
#include "hisi_secboot_external.h"

#ifdef CONFIG_COLD_PATCH
#include "secure_bspatch.h"
#endif

#include "drv_param_type.h"
/* hack for `HANDLE_SYSCALL` */
#include <hmdrv_stub.h>

#define DIE_ID_SIZE (5 * 4)
static UINT32 g_vrl_buf[SECBOOT_VRL_SIZE / sizeof(UINT32)]
	__attribute__((aligned(OS_CACHE_LINE_SIZE)));
#define NELEMENTS(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifdef CONFIG_COLD_PATCH
struct secboot_modem_cold_patch_info_s g_modem_cold_patch_info;
#endif
struct process_info g_process_info_tbl[] = {
	{ HIFI, process_hifi_info_init, process_hifi_info_succ,
	  process_hifi_info_fail },
	{ ISP, process_isp_info_init, process_isp_info_succ,
	  process_isp_info_fail },
#ifdef CONFIG_HISI_IVP_SEC_IMAGE
	{ IVP, process_ivp_info_init, process_ivp_info_succ,
	  process_ivp_info_fail },
#endif
};

struct img_info g_soc_info_tbl[] = {
	{ MODEM, "modem_fw" },
	{ DSP, "modem_fw" },
	{ XDSP, "modem_fw" },
	{ MODEM_DTB, "modem_fw" },
	{ HIFI, "fw_hifi" },
	{ ISP, "isp_firmware" },
#ifdef CONFIG_HISI_NVIM_SEC
	{ NVM, "nvm_rdwr" },
	{ NVM_S, "nvm_rdwr" },
	{ MBN_R, "carrier_resum" },
	{ MBN_A, "carrier_set" },
#endif
#ifdef CONFIG_HISI_IVP_SEC_IMAGE
	{ IVP, "ivp" },
#endif
#if (defined CONFIG_COLD_PATCH) || (defined CONFIG_MODEM_COLD_PATCH)
	{ MODEM_COLD_PATCH, "modem_fw" },
	{ DSP_COLD_PATCH, "modem_fw" },
#endif
#ifdef CONFIG_RFIC_LOAD
	{ RFIC, "modem_fw"},
#endif
};

static struct secboot_info *g_secimage_info;
static UINT32 g_soc_type_size;

INT32 secboot_image_info_init(void)
{
	UINT32 ret;
	UINT32 type_size = 0;
	struct secboot_info *secimage_info = NULL;

	ret = secboot_get_image_info_addr(&secimage_info, &type_size);
	if (ret != SECBOOT_RET_SUCCESS || !secimage_info) {
		tloge("%s, invalid secimage_info\n", __func__);
		return -1;
	}
	if (type_size != MAX_SOC) {
		tloge("%s, invalid soc type_size_info\n", __func__);
		return -1;
	}
	g_secimage_info = secimage_info;
	g_soc_type_size = type_size;

	return 0;
}

/*
 * copy vrl to dst
 * dst_addr[in]: dst addr
 * src_addr[in]: src addr
 * len[in]: len, should be SECBOOT_VRL_SIZE
 * return: SECBOOT_RET_SUCCESS if success
 *         other err code if failed
 */
static UINT32 secboot_copy_vrl_data(uintptr_t dst_addr, UINT32 dst_len,
				    const uintptr_t src_addr, UINT32 src_len)
{
	if (dst_len != SECBOOT_VRL_SIZE || src_len != SECBOOT_VRL_SIZE)
		return SECBOOT_RET_FAILURE;
	if (memcpy_s((void *)dst_addr, dst_len, (void *)src_addr,
		     src_len) != EOK) {
		tloge("%s, memcpy vrl data fail!\n", __func__);
		return SECBOOT_RET_FAILURE;
	}
	/* using dma cache flush in MP platform instead of flush cache all */
	v7_dma_flush_range((unsigned long)dst_addr,
			   (unsigned long)(dst_addr + dst_len));
	return SECBOOT_RET_SUCCESS;
}

/*
 * get imagename from soc_info_tbl by soc_type
 * soc_tye[in]: soc_type
 * imagenameptr[out]: buf of imagename
 * return: SECBOOT_RET_SUCCESS if success
 *         other err code if failed
 */
UINT32 secboot_get_soc_name(UINT32 soc_type, UINT8 *imagenameptr, UINT32 len)
{
	UINT32 i;
	UINT32 count = NELEMENTS(g_soc_info_tbl);

	if (!imagenameptr || len != SECBOOT_IMGNAME_MAXLEN) {
		tloge("%s, name buf err!\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}
	/* find the soc_type processing flow */
	for (i = 0; i < count; i++) {
		if (soc_type == g_soc_info_tbl[i].soc_type) {
			if (memcpy_s(imagenameptr, len,
				     g_soc_info_tbl[i].soc_name,
				     SECBOOT_IMGNAME_MAXLEN) != EOK) {
				tloge("%s, memcpy soc name fail!\n", __func__);
				return SECBOOT_RET_FAILURE;
			}
			return SECBOOT_RET_SUCCESS;
		}
	}
	/* not find the soc_type processing flow */
	tloge("%s, invalid soc type=0x%x!\n", __func__, soc_type);
	return SECBOOT_RET_INVALIED_SOC_TYPE;
}

/*
 * copy vrl to g_vrl_buf, and then fill seb_certpkg with cert add from vrl,
 * and then change store addr with real imageaddress
 * vrladdress[in]: vrl addr
 * seb_certpkg[inout]: addr of seb_certpkg
 * imageaddress[in]: image addr
 * return: SECBOOT_RET_SUCCESS if success
 *         other err code if failed
 */
static UINT32 secboot_get_certpkg(UINT32 vrladdress,
				  struct seb_cert_pkg *seb_certpkg,
				  paddr_t imageaddress)
{
	UINT32 ret;

	ret = secboot_copy_vrl_data((uintptr_t)g_vrl_buf, SECBOOT_VRL_SIZE,
				    (uintptr_t)vrladdress, SECBOOT_VRL_SIZE);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, copy vrl data failed\n", __func__);
		return ret;
	}

	ret = seb_fillcertpkg((UINT64)(uintptr_t)g_vrl_buf, seb_certpkg);
	if (ret) {
		tloge("%s, seb_fillcertpkg error(0x%x)!\n", __func__, ret);
		return ret;
	}

	/* change the image store address to the RAM address. */
	ret = secboot_changecompstoreaddr(seb_certpkg, imageaddress);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, changecompstoreaddr error(0x%x)!\n", __func__, ret);
		return ret;
	}

	return SECBOOT_RET_SUCCESS;
}

#if defined(CONFIG_DYNAMIC_MMAP_ADDR)
static UINT32 modem_dynamic_mmap(UINT32 vrl_address, paddr_t image_address,
				 UINT32 *img_size, UINT32 *virt_img_addr)
{
	if (seb_parservrl(vrl_address, img_size) != SECBOOT_RET_SUCCESS) {
		tloge("%s, get img size failed\n", __func__);
		return SECBOOT_RET_FAILURE;
	}

	if (sre_mmap(image_address, *img_size, virt_img_addr, secure, cache)) {
		tloge("%s, map data buffer addr=0x%x error2\n", __func__,
		      image_address);
		return SECBOOT_RET_FAILURE;
	}

	return SECBOOT_RET_SUCCESS;
}
#endif

/*
 * verify image and check plat info, and oem info, called by
 * secboot_soc_verification
 * seb_certpkg_ptr[in]: pointer of seb_certpkg
 * imagenameptr[in]: image name
 * isprimvrl[in]: if Prim or not
 * sec_cfg[in]: state of lcs
 * return: SECBOOT_RET_SUCCESS if success
 *         other err code if failed
 */
static UINT32 secboot_verify_and_check(struct seb_cert_pkg *seb_certpkg_ptr,
				       const char *imagenameptr,
				       enum secboot_seccfg sec_cfg,
				       UINT32 isprimvrl)
{
	UINT32 ret;
	BOOL be_secure;
	struct vrl_additiondata addition_data;

	if (!seb_certpkg_ptr || !imagenameptr) {
		tloge("%s invalid input\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	be_secure = (sec_cfg == SECBOOT_SECCFG_SECURE) ? TRUE : FALSE;

	/* get and check addition_data, check is done in func */
	ret = secboot_check_adddata(seb_certpkg_ptr, imagenameptr,
				    &addition_data, isprimvrl);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, secboot_check_adddata error(0x%x)!\n", __func__,
		      ret);
		return ret;
	}

	ret = secboot_imageverification(seb_certpkg_ptr, imagenameptr,
					be_secure, true, FALSE);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, secboot_imageverification error(0x%x)!\n", __func__,
		      ret);
		return ret;
	}

	return SECBOOT_RET_SUCCESS;
}

/*
 * verify secimage with input vrladdr/imageaddr and imagename
 * vrlAddress[in]: vrl addr
 * imageAddress[in]: image addr
 * imageNamePtr[in]: image name
 * isPrimVRL[in]: if Prim or not
 * lock_state[in]: lock state
 * return: SECBOOT_RET_SUCCESS if success
 *         other err code if failed
 */
UINT32 secboot_soc_verification(UINT32 vrladdress, paddr_t imageaddress,
				const char *imagenameptr, UINT32 isprimvrl,
				SECBOOT_LOCKSTATE lock_state)
{
	UINT32 ret;
	enum secboot_seccfg sec_cfg = SECBOOT_SECCFG_ERROR;
	struct seb_cert_pkg seb_certpkg = { 0 };
#if defined(CONFIG_DYNAMIC_MMAP_ADDR)
	UINT32 virt_img_addr = 0;
	UINT32 img_size = 0;
#endif
	UNUSED(lock_state);

	if (!imagenameptr || vrladdress == 0 || imageaddress == 0) {
		tloge("%s, input err\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	/* get the secure configuration. */
	ret = secboot_getseccfg(&sec_cfg);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, secboot_getseccfg error!\n", __func__);
		return ret;
	}

	/* if it is none, we just return. */
	if (sec_cfg == SECBOOT_SECCFG_NONE) {
		tloge("%s: system is SECBOOT_SECCFG_NONE.\n", __func__);
		return SECBOOT_RET_SUCCESS;
	}

#if defined(CONFIG_DYNAMIC_MMAP_ADDR)
	ret = modem_dynamic_mmap(vrladdress, imageaddress, &img_size,
				 &virt_img_addr);
	if (ret != SECBOOT_RET_SUCCESS)
		return ret;
	imageaddress = virt_img_addr;
#endif

	if (imageaddress == SEB_INVALID_VALUE) {
		tloge("%s, imageaddress is invalid, check it out.\n", __func__);
		ret = SECBOOT_RET_FAILURE;
		goto process_out;
	}

	ret = secboot_get_certpkg(vrladdress, &seb_certpkg, imageaddress);
	if (ret != SECBOOT_RET_SUCCESS)
		goto process_out;

	/* using dma cache flush in MP platform instead of flush cache all */
	v7_dma_flush_range(virt_img_addr, virt_img_addr + img_size);

	ret = secboot_verify_and_check(&seb_certpkg, imagenameptr, sec_cfg,
				       isprimvrl);

process_out:
#if defined(CONFIG_DYNAMIC_MMAP_ADDR)
	if (sre_unmap(virt_img_addr, img_size)) {
		tloge("unmap virt_img_addr failed\n");
		ret = SECBOOT_RET_FAILURE;
	}
#endif
	return ret;
}

/*
 * Process the addr from kernel,Check addr is valid
 * Corresponding process flow base on process type
 * Return: SECBOOT_RET_SUCCESS indicate succ
 *         OTHERS indicate fail
 */
UINT32 hisi_secboot_process_soc_addr(UINT32 soc_type, const paddr_t soc_addr,
				     UINT32 process_type)
{
	UINT32 ret = SECBOOT_RET_SUCCESS;
#ifdef WITH_IMAGE_LOAD_SUPPORT
	UINT32 i;
	UINT32 count = NELEMENTS(g_process_info_tbl);

	/* find the soc_type processing flow */
	for (i = 0; i < count; i++)
		if (soc_type == g_process_info_tbl[i].soc_type)
			break;

	/* not find the soc_type processing flow */
	if (i == count)
		return SECBOOT_RET_SUCCESS;

	/* process info base on process_type */
	switch (process_type) {
	case INIT_PROC_TYPE:
		if (g_process_info_tbl[i].process_init)
			ret = g_process_info_tbl[i].process_init(soc_addr);
		break;
	case SUCC_PROC_TYPE:
		if (g_process_info_tbl[i].process_succ)
			ret = g_process_info_tbl[i].process_succ();
		break;
	case FAIL_PROC_TYPE:
		if (g_process_info_tbl[i].process_fail)
			ret = g_process_info_tbl[i].process_fail();
		break;
	default:
		tloge("%s, process type(0x%x) is not correct\n", __func__,
		      process_type);
		ret = SECBOOT_RET_INVALIED_PROCESS_TYPE;
		break;
	}
#endif
	return ret;
}

/*
 * hisi_secboot_copy_img_from_os, only used for isp now
 * copy soc_type img data from secure buffer to
 * run addr through secure os
 * soc_type[in]: soc_type
 * return: SECBOOT_RET_SUCCESS if ok
 *         other err code if failed
 */
UINT32 hisi_secboot_copy_img_from_os(UINT32 soc_type)
{
	INT32 err_code;
	INT64 src_addr;
	UINT32 map_dst_addr = 0;
	UINT32 map_src_addr = 0;
	UINT32 max_copy_len;

	if (soc_type != ISP) {
		tloge("%s, invalid soctype, only isp allowed!\n", __func__);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	tloge("%s, start to copy from src_addr to run_addr\n", __func__);

	/* get and map fixed src_addr */
	max_copy_len = g_secimage_info[soc_type].ddr_size;
	src_addr = get_base_addr(soc_type);
	if (src_addr == SECBOOT_ILLEGAL_BASE_ADDR)
		return SECBOOT_ILLEGAL_BASE_ADDR;

	err_code = sre_mmap(g_secimage_info[soc_type].ddr_phy_addr, max_copy_len,
			    &map_dst_addr, secure, cache);
	if (err_code) {
		tloge("%s, map data buffer addr=0x%x error1\n", __func__,
		      g_secimage_info[soc_type].ddr_phy_addr);
		return SECBOOT_RET_INVALIED_ADDR_MAP;
	}

	err_code =
		sre_mmap(src_addr, max_copy_len, &map_src_addr, secure, cache);
	if (err_code) {
		tloge("%s, map data buffer addr=0x%x error2\n", __func__,
		      src_addr);
		err_code = SECBOOT_RET_INVALIED_ADDR_MAP;
		goto err_map_src;
	}

	err_code = memcpy_s((void *)(uintptr_t)map_dst_addr, max_copy_len,
			    (void *)(uintptr_t)map_src_addr, max_copy_len);
	if (err_code != EOK) {
		tloge("%s, memcpy img data from src_add to run_addr fail!\n",
		      __func__);
		err_code = SECBOOT_RET_FAILURE;
		goto err_memcpy;
	}

	v7_dma_flush_range(map_dst_addr, map_dst_addr + max_copy_len);
	err_code = SECBOOT_RET_SUCCESS;
	tloge("%s, success to copy from src_addr to run_addr\n", __func__);
err_memcpy:
	(void)sre_unmap(map_src_addr, max_copy_len);
err_map_src:
	(void)sre_unmap(map_dst_addr, max_copy_len);

	return err_code;
}

/* check input param for soc_verification: soc_type and vrladdress */
static UINT32 hisi_secboot_param_check(UINT32 soc_type, paddr_t address)
{
	if (address == 0) {
		tloge("%s, soc_type %d, addr is null\n", __func__, soc_type);
		return SECBOOT_RET_FAILURE;
	}

	if (soc_type >= MAX_SOC) {
		tloge("%s, invalid soctype %d!\n", __func__, soc_type);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}
	return SECBOOT_RET_SUCCESS;
}

/*
 * func for copy img data to img load addr
 * Return: SECBOOT_RET_SUCCESS indicate succ
 *         OTHERS indicate fail
 */
UINT32 hisi_secboot_copy_soc_data(UINT32 soc_type, UINT32 offset,
				  const paddr_t src_addr, UINT32 len)
{
	UINT32 ret;
	UINT32 size;
	UINT32 tmp_dst_addr = 0;
	UINT32 tmp_src_addr = 0;

	ret = hisi_secboot_param_check(soc_type, src_addr);
	if (ret != SECBOOT_RET_SUCCESS)
		return ret;

	ret = secboot_config_dynamic_load_addr(soc_type);
	if (ret != SECBOOT_RET_SUCCESS)
		return ret;

	if (hisi_secboot_is_modem_img(soc_type) == IS_MODEM_IMG)
		g_secimage_info[soc_type].image_size += len;

#ifdef CONFIG_COLD_PATCH
	/* if DSP_COLD_PATCH verify pass, copy dsp img data to modem ddr */
	if (soc_type == DSP &&
	    (g_modem_load.verify_flag & (0x1u << DSP_COLD_PATCH)))
		soc_type = MODEM;
#endif

	size = g_secimage_info[soc_type].ddr_size;
#ifdef CONFIG_COLD_PATCH_BORROW_DDR
	if (soc_type == MODEM || soc_type == MODEM_COLD_PATCH)
		offset = offset + DDR_MCORE_NR_SIZE;
#endif
	/* check overflow */
	if (((offset + len) > size) || ((offset + len) < offset) ||
	    ((offset + len) < len)) {
		tloge("%s, offset(0x%x) & len(0x%x) is error, size is 0x%x\n",
		      __func__, offset, len, size);
		return SECBOOT_RET_INVALIED_OFFSET_OR_LEN;
	}

	if (sre_mmap(src_addr, len, &tmp_src_addr, non_secure, cache)) {
		tloge("%s, map buffer addr=0x%x error1\n", __func__, src_addr);
		return SECBOOT_RET_INVALIED_ADDR_MAP;
	}
	if (sre_mmap((g_secimage_info[soc_type].ddr_phy_addr + offset), len,
		     &tmp_dst_addr, secure, cache)) {
		tloge("%s, map buffer addr=0x%x error2\n", __func__,
		      g_secimage_info[soc_type].ddr_phy_addr + offset);
		(void)sre_unmap(tmp_src_addr, len);
		return SECBOOT_RET_INVALIED_ADDR_MAP;
	}

	if (g_secimage_info[soc_type].image_addr == IMAGE_ADDR_INVALID_VALUE)
		g_secimage_info[soc_type].image_addr =
			g_secimage_info[soc_type].ddr_phy_addr + offset;

	if (memcpy_s((void *)(uintptr_t)tmp_dst_addr, len,
		     (void *)(uintptr_t)tmp_src_addr, len)) {
		tloge("%s, memcpy_s failed!\n", __func__);
		(void)sre_unmap(tmp_src_addr, len);
		(void)sre_unmap(tmp_dst_addr, len);
		return SECBOOT_RET_FAILURE;
	}
	/* using dma cache flush in MP platform instead of flush cache all */
	v7_dma_flush_range(tmp_dst_addr, tmp_dst_addr + len);

	(void)sre_unmap(tmp_src_addr, len);
	(void)sre_unmap(tmp_dst_addr, len);

	return SECBOOT_RET_SUCCESS;
}

#if defined(CONFIG_MODEM_ASLR) || defined(CONFIG_MODEM_BALONG_ASLR)
extern struct aslr_sec_param g_aslr_sec_param;
#endif

#ifdef CONFIG_COLD_PATCH

/*
 * func for copy splicing img data to img load addr
 * Return: size indicate succ
 *         0 indicate fail
 */
static size_t secboot_copy_splicing_img_to_run_addr_call_back(
	const uint8_t *src_addr, size_t size)
{
	int ret = 0;
	UINT32 offset;

	if (g_modem_cold_patch_info.soc_type == MODEM) {
		offset = g_modem_cold_patch_info.ccore_offset;

		ret = memcpy_s((void *)(uintptr_t)(
				       g_modem_cold_patch_info.ccore_vir_addr +
				       offset),
			       size, (void *)src_addr, size);
		/* using dma cache flush in MP platform instead of flush all */
		v7_dma_flush_range(
			g_modem_cold_patch_info.ccore_vir_addr + offset,
			g_modem_cold_patch_info.ccore_vir_addr + offset + size);
		g_modem_cold_patch_info.ccore_offset += size;
	} else if (g_modem_cold_patch_info.soc_type == DSP) {
		offset = g_modem_cold_patch_info.dsp_offset;

		ret = memcpy_s(
			(void *)(uintptr_t)(
				g_modem_cold_patch_info.dsp_vir_addr + offset),
			size, (void *)src_addr, size);
		/* using dma cache flush in MP platform instead of flush all */
		v7_dma_flush_range(
			g_modem_cold_patch_info.dsp_vir_addr + offset,
			g_modem_cold_patch_info.dsp_vir_addr + offset + size);
		g_modem_cold_patch_info.dsp_offset += size;
	}
	if (ret != EOK) {
		tloge("%s, soc_type = 0x%x,memcpy_s error: ret=[0x%x] error.\n",
		      __func__, g_modem_cold_patch_info.soc_type, ret);
		return 0;
	}
	return size;
}

UINT32 secboot_splicing_img(enum SVC_SECBOOT_IMG_TYPE old_img_type,
			    UINT32 inflate_img_offset,
			    UINT32 decompress_img_size)
{
	UINT32 vir_old_img_addr;
	UINT32 vir_patch_img_addr = 0;
	UINT32 old_img_size;
	UINT32 patch_img_size = 0;
	UINT32 ret;

	if (sre_mmap(g_secimage_info[MODEM].ddr_phy_addr, g_secimage_info[MODEM].ddr_size,
		     &g_modem_cold_patch_info.ccore_vir_addr, secure, cache)) {
		tloge("%s, SoC_Type:%d map data buf addr=0x%x size=0x%x error\n",
		      __func__, MODEM, g_secimage_info[MODEM].ddr_phy_addr, g_secimage_info[MODEM].ddr_size);
		return SECBOOT_RET_INVALIED_ADDR_MAP;
	}

	if (old_img_type == MODEM) {
#if defined(CONFIG_MODEM_ASLR) || defined(CONFIG_MODEM_BALONG_ASLR)
		g_modem_cold_patch_info.ccore_offset = g_aslr_sec_param.image_offset;
#else
		g_modem_cold_patch_info.ccore_offset = 0;
#endif
		g_modem_cold_patch_info.soc_type = MODEM;

		vir_patch_img_addr = g_modem_cold_patch_info.ccore_vir_addr +
			g_secimage_info[MODEM_COLD_PATCH].image_addr - g_secimage_info[MODEM_COLD_PATCH].ddr_phy_addr;
		patch_img_size = g_secimage_info[MODEM_COLD_PATCH].image_size;
	} else if (old_img_type == DSP) {
		g_modem_cold_patch_info.dsp_offset = 0;
		g_modem_cold_patch_info.soc_type = DSP;
		if (sre_mmap(g_secimage_info[DSP].ddr_phy_addr, g_secimage_info[DSP].ddr_size,
			     &g_modem_cold_patch_info.dsp_vir_addr, secure, cache)) {
			tloge("%s, soc:%d map data buf add=0x%x size=0x%x err\n",
			      __func__, DSP, g_secimage_info[DSP].ddr_phy_addr, g_secimage_info[DSP].ddr_size);
			return SECBOOT_RET_INVALIED_ADDR_MAP;
		}
		vir_patch_img_addr = g_modem_cold_patch_info.ccore_vir_addr +
			g_secimage_info[DSP_COLD_PATCH].image_addr - g_secimage_info[DSP_COLD_PATCH].ddr_phy_addr;
		patch_img_size = g_secimage_info[DSP_COLD_PATCH].image_size;
	}
	vir_old_img_addr = g_modem_cold_patch_info.ccore_vir_addr + inflate_img_offset;
	old_img_size = decompress_img_size;

	ret = secure_bspatch((uint8_t *)(uintptr_t)vir_old_img_addr, old_img_size,
		(uint8_t *)(uintptr_t)vir_patch_img_addr, patch_img_size,
		secboot_copy_splicing_img_to_run_addr_call_back);
	if (ret) {
		tloge("%s, SoC_Type:%d modem cold patch fail!\n", __func__, MODEM);
		ret |= SECBOOT_SPLICING_RET_BASE_ADDR;
	}

#if defined(CONFIG_MODEM_ASLR) || defined(CONFIG_MODEM_BALONG_ASLR)
	if (old_img_type == MODEM) {
		if (memmove_s((uint8_t *)(uintptr_t)g_modem_cold_patch_info.ccore_vir_addr, MODEM_REL_COPY_CODE_SIZE,
			(uint8_t *)(uintptr_t)(g_modem_cold_patch_info.ccore_vir_addr + g_aslr_sec_param.image_offset),
			MODEM_REL_COPY_CODE_SIZE) != EOK) {
			tloge("%s, memmove_s failed.\n", __func__);
			ret = SECBOOT_RET_FAILURE;
			goto error;
		}
		writel(g_aslr_sec_param.image_offset, g_modem_cold_patch_info.ccore_vir_addr + MODEM_IMAGE_OFFSET);
		writel(g_aslr_sec_param.stack_guard, g_modem_cold_patch_info.ccore_vir_addr + MODEM_STACK_GUARD_OFFSET);
		writel(g_aslr_sec_param.heap_offset, g_modem_cold_patch_info.ccore_vir_addr + MODEM_MEM_PT_OFFSET);
		v7_dma_flush_range(g_modem_cold_patch_info.ccore_vir_addr, g_modem_cold_patch_info.ccore_vir_addr +
					   MODEM_REL_COPY_CODE_SIZE);
		ret = memset_s(&g_aslr_sec_param, sizeof(struct aslr_sec_param), 0, sizeof(struct aslr_sec_param));
		if (ret != EOK) {
			tloge("%s, memset_s failed.\n", __func__);
			ret = SECBOOT_RET_FAILURE;
			goto error;
		}
	}
error:
#endif

	(void)sre_unmap(g_modem_cold_patch_info.ccore_vir_addr, g_secimage_info[MODEM].ddr_size);
	if (old_img_type == DSP) {
		(void)sre_unmap(g_modem_cold_patch_info.dsp_vir_addr, g_secimage_info[DSP].ddr_size);
		g_secimage_info[MODEM].image_addr = IMAGE_ADDR_INVALID_VALUE;
	}
	return ret;
}

#endif

static void secboot_modem_reset(void)
{
	UINT32 i;

	for (i = 0; i < MAX_SOC; i++)
		g_secimage_info[i].image_size = 0;
#if (defined CONFIG_COLD_PATCH) || (defined CONFIG_MODEM_COLD_PATCH)
	g_modem_load.verify_flag &= ~(0x1u << DSP_COLD_PATCH);
	g_modem_load.verify_flag &= ~(0x1u << MODEM_COLD_PATCH);
	g_secimage_info[MODEM_COLD_PATCH].image_addr = IMAGE_ADDR_INVALID_VALUE;
	g_secimage_info[DSP_COLD_PATCH].image_addr = IMAGE_ADDR_INVALID_VALUE;
#endif
	g_modem_load.modem_is_ursted = 0;
	g_secimage_info[MODEM].image_addr = IMAGE_ADDR_INVALID_VALUE;
}

/* show info of image, return if soc_type invalid */
static void secboot_show_image_info(UINT32 soc_type)
{
	if (soc_type >= MAX_SOC) {
		tloge("%s, invalid soctype!\n", __func__);
		return;
	}

	tloge("type=0x%x. ", soc_type);
	tloge("ddr_phy_addr=0x%x%x. ", g_secimage_info[soc_type].ddr_phy_addr);
	tloge("ddr_size=0x%x. ", g_secimage_info[soc_type].ddr_size);
	tloge("unreset_dependcore=0x%x\n",
	      g_secimage_info[soc_type].unreset_dependcore);
}

UINT32 secboot_verify(UINT32 vrl_addr, size_t vrl_size, UINT32 img_addr,
		      size_t img_size, const char *img_name, size_t name_len)
{
	UINT32 ret;
	enum secboot_seccfg sec_cfg;
	struct seb_cert_pkg seb_certpkg;

	if (vrl_addr == 0 || vrl_size != SECBOOT_VRL_SIZE || img_addr == 0 ||
	    !img_name || name_len > SECBOOT_IMGNAME_MAXLEN) {
		tloge("%s, invalid vrl/image addr\n", __func__);
		return SECBOOT_RET_FAILURE;
	}

	if (vrl_addr & 0x3F || img_addr & 0x3F) {
		tloge("%s, vrl_addr(%xllx) or img_addr(%xllx) should cacheline align\n",
		      __func__, vrl_addr, img_addr);
		return SECBOOT_RET_FAILURE;
	}

	ret = secboot_getseccfg(&sec_cfg);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, seccfg error 0x%x!\n", __func__, ret);
		return ret;
	}

	if (sec_cfg == SECBOOT_SECCFG_NONE) {
		tlogi("%s: system is SECBOOT_SECCFG_NONE.\n", __func__);
		return SECBOOT_RET_SUCCESS;
	}

	v7_dma_flush_range(vrl_addr, vrl_addr + vrl_size);
	v7_dma_flush_range(img_addr, img_addr + img_size);

	ret = secboot_get_certpkg(vrl_addr, &seb_certpkg, img_addr);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, get_certpkg error 0x%x!\n", __func__, ret);
		return ret;
	}

	ret = secboot_verify_and_check(&seb_certpkg, (const char *)img_name,
				       sec_cfg, TRUE);
	if (ret != SECBOOT_RET_SUCCESS)
		tloge("%s, secboot_verify error 0x%x!\n", __func__, ret);

	return ret;
}

/*
 * func for image verify and modem inflate
 * Return: SECBOOT_RET_SUCCESS indicate succ
 *         OTHERS indicate fail
 */
UINT32 hisi_secboot_soc_verification(UINT32 soc_type, UINT32 vrladdress,
				     paddr_t core_id,
				     SECBOOT_LOCKSTATE lock_state)
{
	UINT32 ret;
	UINT32 modem_img_flag;
	paddr_t imageaddresstmp;
	UINT8 imagenameptr[SECBOOT_IMGNAME_MAXLEN] = { 0 };

	ret = hisi_secboot_param_check(soc_type, (paddr_t)vrladdress);
	if (ret != SECBOOT_RET_SUCCESS)
		return ret;

	modem_img_flag = hisi_secboot_is_modem_img(soc_type);
	if (modem_img_flag == IS_MODEM_IMG)
		return hisi_secboot_verify_modem_imgs(soc_type, vrladdress,
						      core_id, lock_state);

	tlogi("%s in,type=0x%x.\n", __func__, soc_type);
	secboot_show_image_info(soc_type);

	imageaddresstmp = g_secimage_info[soc_type].ddr_phy_addr;
	ret = secboot_get_soc_name(soc_type, imagenameptr,
				   SECBOOT_IMGNAME_MAXLEN);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, failed to get soc name 0x%x\n", __func__, soc_type);
		return ret;
	}

	if (vrladdress == SEB_INVALID_VALUE ||
	    imageaddresstmp == SEB_INVALID_VALUE) {
		tloge("%s, %s verify fail vrlAddr=0x%x, imageAddr=0x%llx.\n",
		      __func__, imagenameptr, vrladdress, imageaddresstmp);
		return SECBOOT_RET_FAILURE;
	}

	ret = secboot_soc_verification(vrladdress, imageaddresstmp,
				       (const char *)imagenameptr, TRUE,
				       lock_state);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, %s ", __func__, imagenameptr);
		tloge("soc_type=%x verify fail vrlAddr=0x%x, imgAddr=0x%llx.\n",
		      soc_type, vrladdress, imageaddresstmp);
		return ret;
	}

	tlogi("%s out, ret=0x%x.\n", __func__, ret);
	return ret;
}

/*
 * img reset process
 * Return: SECBOOT_RET_SUCCESS indicate succ
 *         OTHERS indicate fail
 */
UINT32 hisi_secboot_soc_reset(UINT32 soc_type)
{
	UINT32 ret = SECBOOT_RET_SUCCESS;

	tlogi("%s in. soc_type is 0x%x\n", __func__, soc_type);
	switch (soc_type) {
	case MODEM:
		secboot_modem_reset();
		break;
	case HIFI:
#if defined(CONFIG_SUPPORT_HIFI_LOAD)
		/* clean hifi run addr */
		ret = prepare_reload_hifi();
		if (ret != SECBOOT_RET_SUCCESS) {
			tloge("%s, soctype=0x%x reload_hifi fail ret=0x%x\n",
			      __func__, soc_type, ret);
			return ret;
		}
#endif
		break;
	case DSP:
	case XDSP:
	case TAS:
	case WAS:
	case MODEM_DTB:
#ifdef CONFIG_RFIC_LOAD
	case RFIC:
#endif
		tlogi("%s, ignore, no need to reset soc 0x%x!\n", __func__,
		      soc_type);
		break;
	case ISP:
#if defined(CONFIG_SUPPORT_ISP_LOAD)
		hisi_isp_reset();
#endif
		break;
#ifdef CONFIG_HISI_NVIM_SEC
	case NVM:
	case NVM_S:
	case MBN_R:
	case MBN_A:
		tlogi("%s, ignore, no need to reset nvm 0x%x!\n", __func__,
		      soc_type);
		break;
#ifdef CONFIG_HISI_IVP_SEC_IMAGE
	case IVP:
		tlogi("%s, ignore, no need to reset IVP!\n", __func__);
		break;
#endif
#endif
#if (defined CONFIG_COLD_PATCH) || (defined CONFIG_MODEM_COLD_PATCH)
	case MODEM_COLD_PATCH:
	case DSP_COLD_PATCH:
		tlogi("%s, ignore, no need to reset colde_patch 0x%x!\n",
		      __func__, soc_type);
		break;
#endif
	default:
		tloge("%s, invalid soc type!\n", __func__);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}
	tlogi("%s out.\n", __func__);
	return ret;
}

/*
 * img disreset process
 * Return: SECBOOT_RET_SUCCESS indicate succ
 *         OTHERS indicate fail
 */
UINT32 hisi_secboot_soc_set(UINT32 soc_type)
{
	UINT32 ret = SECBOOT_RET_SUCCESS;

	tloge("secboot disreset in. soc_type is 0x%x\n", soc_type);

	switch (soc_type) {
	case MODEM:
		ret = hisi_modem_disreset(soc_type);
		if (ret != SECBOOT_RET_SUCCESS)
			return ret;
		break;
#ifdef CONFIG_MLOADER
	case MODEM_COMM_IMG:
#endif
	case HIFI:
	case DSP:
	case XDSP:
	case TAS:
	case WAS:
	case MODEM_DTB:
#ifdef CONFIG_RFIC_LOAD
	case RFIC:
#endif
		tlogi("%s, ignore, no need to set soc 0x%x!\n", __func__,
		      soc_type);
		break;
	case ISP:
#if defined(CONFIG_SUPPORT_ISP_LOAD)
		hisi_isp_disreset((UINT32)g_secimage_info[soc_type].ddr_phy_addr);
#endif
		break;
#ifdef CONFIG_HISI_NVIM_SEC
	case NVM:
	case NVM_S:
	case MBN_R:
	case MBN_A:
		tlogi("%s, ignore, no need to set nvim 0x%x!\n", __func__,
		      soc_type);
		break;
#ifdef CONFIG_HISI_IVP_SEC_IMAGE
	case IVP:
		tlogi("%s, ignore, no need to set IVP!\n", __func__);
		break;
#endif
#endif
#if (defined CONFIG_COLD_PATCH) || (defined CONFIG_MODEM_COLD_PATCH)
	case MODEM_COLD_PATCH:
	case DSP_COLD_PATCH:
		tlogi("%s, ignore, no need to set colde_patch 0x%x!\n",
		      __func__, soc_type);
		break;
#endif
	default:
		tloge("%s invalid soc type!\n", __func__);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	tloge("secboot disreset out.\n");
	return ret;
}

INT32 hisi_secboot_info_init(void)
{
	INT32 ret;

	ret = secboot_dma_init();
	if (ret)
		return ret;
	ret = secboot_get_secinfo();
	if (ret)
		return ret;
	ret = secboot_image_info_init();

	return ret;
}

int secureboot_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
	UINT32 uwret;

	if (!params || !params->args) {
		tloge("%s invalid input\n", __func__);
		return -1;
	}
	/*
	 * According to ARM AAPCS arguments from 5-> in a function call
	 * are stored on the stack, which in this case is pointer by
	 * user sp. Our own TrustedCore also push FP and LR on the stack
	 * just before SWI, so skip them. first args locate at usr_sp + 8
	 */
	uint64_t *args = (uint64_t *)(uintptr_t)(params->args);

	HANDLE_SYSCALL(swi_id)
	{
		SYSCALL_PERMISSION(SW_SYSCALL_BSP_MODEM_CALL, permissions, MDMCALL_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[2], (size_t)args[3]);
		ACCESS_WRITE_RIGHT_CHECK(args[2], (size_t)args[3]);
		uwret = (UINT32)bsp_modem_call((unsigned int)args[0], (unsigned int)args[1],
			(void *)(uintptr_t)args[2], (unsigned int)args[3]);
		args[0] = uwret;
		SYSCALL_END

#ifdef CONFIG_CC_CUID
		SYSCALL_PERMISSION(SW_GET_CUID, permissions, GENERAL_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[0], args[1]);
		ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
		uwret = secboot_get_cuid((uint8_t *)(uintptr_t)args[0], (uint32_t)args[1]);
		args[0] = uwret;
		SYSCALL_END;
#endif
		SYSCALL_PERMISSION(SW_SYSCALL_TEE_HAL_GET_DIEID, permissions, GENERAL_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[0], DIE_ID_SIZE);
		ACCESS_WRITE_RIGHT_CHECK(args[0], DIE_ID_SIZE);
		uwret = (UINT32)secboot_get_secinfo_dieid((unsigned int *)(uintptr_t)args[0], DIE_ID_SIZE);
		args[0] = uwret;
		SYSCALL_END
		SYSCALL_PERMISSION(SW_COPY_SOC_DATA_TYPE, permissions, SECBOOT_GROUP_PERMISSION)
#ifndef ARM_PAE
		uwret = hisi_secboot_copy_soc_data(
				args[0], args[1],
				(uint32_t)(args[2] & 0xFFFFFFFF),
				(uint32_t)((args[2] >> BITS32) & 0xFFFFFFFF));
#else
		uwret = hisi_secboot_copy_soc_data(args[0], args[1], args[2], args[3]);
#endif
		args[0] = uwret;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_VERIFY_SOC_DATA_TYPE, permissions, SECBOOT_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[1], SECBOOT_VRL_SIZE);
		ACCESS_READ_RIGHT_CHECK(args[1], SECBOOT_VRL_SIZE);
#ifndef ARM_PAE
		uwret = hisi_secboot_soc_verification(
				(int)args[0], (unsigned int)args[1],
				(unsigned int)(args[2] & 0xFFFFFFFF),
				(int)((args[2] >> BITS32) & 0xFFFFFFFF));
#else
		uwret = hisi_secboot_soc_verification(
				args[0], (unsigned int)args[1],
				args[2], (int)args[3]);
#endif
		args[0] = uwret;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SOC_IMAGE_RESET, permissions, SECBOOT_GROUP_PERMISSION)
		uwret = hisi_secboot_soc_reset(args[0]);
		args[0] = uwret;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SOC_IMAGE_SET, permissions, SECBOOT_GROUP_PERMISSION)
		uwret = hisi_secboot_soc_set(args[0]);
		args[0] = uwret;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SOC_GET_VRL_ADDR, permissions, SECBOOT_GROUP_PERMISSION)
		SYSCALL_END

		SYSCALL_PERMISSION(SW_PROCESS_SOC_ADDR, permissions, SECBOOT_GROUP_PERMISSION)
#ifndef ARM_PAE
		uwret = hisi_secboot_process_soc_addr(
				args[0],
				(uint32_t)(args[1] & 0xFFFFFFFF),
				(uint32_t)((args[1] >> BITS32) & 0xFFFFFFFF));
#else
		uwret = hisi_secboot_process_soc_addr(
				args[0], args[1], args[2]);
#endif
		args[0] = uwret;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_COPY_IMG_FROM_OS_DRIVER, permissions, SECBOOT_GROUP_PERMISSION)
#ifndef ARM_PAE
		uwret = hisi_secboot_copy_img_from_os(args[0]);
#else
		uwret = hisi_secboot_copy_img_from_os(args[0]);
#endif
		args[0] = uwret;
		SYSCALL_END

#ifdef CONFIG_HISI_EIIUS
		/* eiius: encrypto image */
		SYSCALL_PERMISSION(SW_EIIUS_ENCRYPTO_DATA, permissions, SECBOOT_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[3], args[4]);
		ACCESS_READ_RIGHT_CHECK(args[3], args[4]);

		uwret = eiius_encrypto_ctr(args[0], args[1], (uint32_t)args[2],
			(uint8_t *)(uintptr_t)args[3], (uint32_t)args[4], (uint32_t)args[5]);
		args[0] = uwret;
		SYSCALL_END

		/* eiius: verify image */
		SYSCALL_PERMISSION(SW_EIIUS_VERIFY_DATA, permissions, SECBOOT_GROUP_PERMISSION)
		uwret = eiius_image_verify(args[0],
			args[1], (uint32_t)args[2], (uint32_t)args[3]);
		args[0] = uwret;
		SYSCALL_END

		/* eiius: get physical address */
		SYSCALL_PERMISSION(SW_EIIUS_GET_PADDR, permissions, SECBOOT_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[0], sizeof(unsigned int));
		ACCESS_CHECK_A64(args[1], sizeof(unsigned int));
		ACCESS_CHECK_A64(args[2], sizeof(unsigned int));
		ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(unsigned int));
		ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(unsigned int));
		ACCESS_WRITE_RIGHT_CHECK(args[2], sizeof(unsigned int));
		uwret = eiius_get_paddr((uint32_t *)(uintptr_t)args[0], (uint32_t *)(uintptr_t)args[1],
					(uint32_t *)(uintptr_t)args[2], args[3]);
		args[0] = uwret;
		SYSCALL_END

		/* eiius: mmap secure memroy */
		SYSCALL_PERMISSION(SW_EIIUS_MAP_ADDR, permissions, SECBOOT_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[2], sizeof(UINT32));
		ACCESS_WRITE_RIGHT_CHECK(args[2], sizeof(UINT32));
		uwret = (UINT32)eiius_secure_memory_map((paddr_t)args[0], (unsigned int)args[1],
			(unsigned int *)(uintptr_t)args[2], (unsigned int)args[3], (unsigned int)args[4]);
		args[0] = uwret;
		SYSCALL_END

		/* eiius: ummap secure memory */
		SYSCALL_PERMISSION(SW_EIIUS_UNMAP_ADDR, permissions, SECBOOT_GROUP_PERMISSION)
		uwret = (UINT32)eiius_secure_memory_unmap((unsigned int)args[0], (unsigned int)args[1]);
		args[0] = uwret;
		SYSCALL_END
#endif

	default:
		return -1;
	}
	return 0;
}

DECLARE_TC_DRV(secboot_driver, 0, 0, 0, TC_DRV_MODULE_INIT,
	       hisi_secboot_info_init, NULL, secureboot_syscall, NULL, NULL);
