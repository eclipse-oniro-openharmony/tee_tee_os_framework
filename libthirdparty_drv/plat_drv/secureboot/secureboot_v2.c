/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: copy from secureboot.c, and will be used in 9a0 and newer
 *              platfor mmodem function will move out here
 * Create: 2019/9/19
 */

#include <stdint.h>
#include <stdio.h>
#include <mem_page_ops.h>
#include <sre_typedef.h>
#include "eiius_interface.h"
#include "hisi_secboot_external.h"
#include "hisi_seclock.h"
#include "secboot.h"
#include "sre_access_control.h"
#include "sre_syscalls_id.h"
#include "sre_syscalls_id_ext.h"
#include "tee_log.h"
#include <errno.h>
#include <hifi.h>
#include <hisi_isp.h>
#include <ivp.h>
#include <platform.h>
#include <drv_mem.h>  // sre_mmap
#include <drv_cache_flush.h> // v7_dma_flush_range
#include <drv_module.h>
#include <drv_legacy_def.h>
#include <process_hifi_info.h>
#include <process_isp_info.h>
#include <process_ivp_info.h>
#include <process_modem_info.h>
#include <securec.h>
#include "drv_param_type.h"
/* hack for `HANDLE_SYSCALL` */
#include <hmdrv_stub.h>

#define DIE_ID_SIZE (5 * 4) /* define in efuse/hisi_efuse.h */
#define NELEMENTS(arr) (sizeof(arr) / sizeof((arr)[0]))
static UINT32 g_vrl_buf[SECBOOT_VRL_SIZE / sizeof(UINT32)]
	__attribute__((aligned(OS_CACHE_LINE_SIZE)));

static struct verify_struct_op g_verify_op_tbl[MAX_AP_SOC + 1];
/*
 * modem here is not a real soc_type in ap, just for a position,
 * modem shold be addressed in MODEM_START-MODEM_END
 */
#define MODEM MAX_AP_SOC

static struct process_info g_process_info_tbl[] = {
	{ HIFI, process_hifi_info_init, process_hifi_info_succ,
	  process_hifi_info_fail },
	{ ISP, process_isp_info_init, process_isp_info_succ,
	  process_isp_info_fail },
#ifdef CONFIG_HISI_IVP_SEC_IMAGE
	{ IVP, process_ivp_info_init, process_ivp_info_succ,
	  process_ivp_info_fail },
#endif
};

static struct img_info g_soc_info_tbl[] = {
	{ HIFI, "fw_hifi" },
	{ ISP, "isp_firmware" },
	{ IVP, "ivp" },
};

static struct secboot_info *g_secimage_info;
static UINT32 g_soc_type_size;

/*
 * print vrl info which is helpful when vrl verify failed,
 * called by caller and works only when eng mode
 */
void secboot_dump_vrl(void)
{
#ifdef CONFIG_HISI_SECBOOT_DEBUG
	tloge("%s g_vrl_buf dump:\n", __func__);

	for (UINT32 i = 0; i < NELEMENTS(g_vrl_buf); i++) {
		tloge("0x%x ", g_vrl_buf[i]);
		if (i % 32 == 0) /* show 32 words every line */
			tloge("\n");
	}
	tloge("\n%s g_vrl_buf end dump \n", __func__);
#endif
}

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
 * get image size from vrl
 * vrl_addr[in]: vrl addr
 * img_siz[out]: buf of img_siz
 * return: SECBOOT_RET_SUCCESS if success
 *         other err code if failed
 */
UINT32 secboot_get_secimage_size(UINT32 vrl_addr, UINT32 *img_size)
{
	if (!img_size || vrl_addr == 0) {
		tloge("%s: invalid input\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	return seb_parservrl(vrl_addr, img_size);
}

/*
 * get imagename from soc_info_tbl by soc_type
 * soc_tye[in]: soc_type
 * imagename[out]: buf of imagename
 * return: SECBOOT_RET_SUCCESS if success
 *         other err code if failed
 */
static UINT32 secboot_get_soc_name_v2(UINT32 soc_type, UINT8 *imagename,
				      UINT32 namelen)
{
	UINT32 i;
	UINT32 count = NELEMENTS(g_soc_info_tbl);

	if (!imagename || namelen != SECBOOT_IMGNAME_MAXLEN) {
		tloge("%s, name buf err!\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	/* find the soc_type processing flow */
	for (i = 0; i < count; i++) {
		if (soc_type == g_soc_info_tbl[i].soc_type) {
			if (memcpy_s(imagename, namelen,
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
 * register modem ops
 * modem_op[in]: modem ops
 * return: SECBOOT_RET_SUCCESS if success
 *         other err code if failed
 */
UINT32 secboot_modem_register(struct verify_struct_op *modem_op)
{
	INT32 ret;

	if (!modem_op || !modem_op->set || !modem_op->reset ||
	    !modem_op->verification || !modem_op->copy) {
		tloge("%s, modem func NULL or type err, register failed\n");
		return SECBOOT_RET_MODEM_REGISTER_FAIL;
	}
	if (modem_op->soc_type < MODEM_START ||
	    modem_op->soc_type > MODEM_END) {
		tloge("%s, modem soc_type err, register failed\n");
		return SECBOOT_RET_MODEM_REGISTER_FAIL;
	}

	ret = memcpy_s((void *)&g_verify_op_tbl[MODEM],
		       sizeof(struct verify_struct_op), modem_op,
		       sizeof(struct verify_struct_op));
	if (ret != EOK) {
		tloge("%s, memcpy img data from src_add to run_addr fail!\n",
		      __func__);
		return SECBOOT_RET_FAILURE;
	}

	return SECBOOT_RET_SUCCESS;
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
static UINT32 modem_dynamic_mmap(UINT32 vrladdress, paddr_t imageaddress,
				 UINT32 *img_size, UINT32 *virt_img_addr)
{
	if (seb_parservrl(vrladdress, img_size) != SECBOOT_RET_SUCCESS) {
		tloge("%s, get img size failed\n", __func__);
		return SECBOOT_RET_FAILURE;
	}

	if (sre_mmap(imageaddress, *img_size, virt_img_addr, secure, cache)) {
		tloge("%s, map data buffer addr=0x%x error\n", __func__,
		      imageaddress);
		return SECBOOT_RET_FAILURE;
	}

	return SECBOOT_RET_SUCCESS;
}
#endif

/*
 * verify image and check plat info, and carrier info, called by
 * secboot_soc_verification
 * seb_certpkg_ptr[in]: pointer of seb_certpkg
 * imagename[in]: image name
 * isprimvrl[in]: if Prim or not
 * sec_cfg[in]: state of lcs
 * return: SECBOOT_RET_SUCCESS if success
 *         other err code if failed
 */
static UINT32 secboot_verify_and_check(struct seb_cert_pkg *seb_certpkg_ptr,
				       const char *imagename,
				       enum secboot_seccfg sec_cfg,
				       UINT32 isprimvrl)
{
	UINT32 ret;
	BOOL be_secure;
	struct vrl_additiondata addition_data;

	if (!seb_certpkg_ptr || !imagename) {
		tloge("%s invalid input\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	be_secure = (sec_cfg == SECBOOT_SECCFG_SECURE) ? TRUE : FALSE;

	ret = secboot_check_adddata(seb_certpkg_ptr, imagename, &addition_data,
				    isprimvrl);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, secboot_check_adddata error(0x%x)!\n", __func__,
		      ret);
		return ret;
	}

	ret = secboot_imageverification(seb_certpkg_ptr, imagename, be_secure,
					true, FALSE);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, secboot_imageverification error(0x%x)!\n", __func__,
		      ret);
		secboot_dump_vrl();
		return ret;
	}

	return SECBOOT_RET_SUCCESS;
}

/*
 * verify secimage with input vrladdr/imageaddr and imagename
 * vrlAddress[in]: vrl addr
 * imageAddress[in]: image addr
 * imagename[in]: image name
 * isPrimVRL[in]: if Prim or not
 * lock_state[in]: lock state
 * return: SECBOOT_RET_SUCCESS if success
 *         other err code if failed
 */
UINT32 secboot_soc_verification(UINT32 vrladdress, paddr_t imageaddress,
				const char *imagename, UINT32 isprimvrl,
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

	if (!imagename || vrladdress == 0 || imageaddress == 0) {
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
		tlogi("%s: system is SECBOOT_SECCFG_NONE.\n", __func__);
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

	ret = secboot_verify_and_check(&seb_certpkg, imagename, sec_cfg,
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
 * hisi_secboot_process_soc_addr
 * Process the addr from kernel, Check addr is valid, and call func
 * for init/fail/succ process of individual soc
 * Corresponding process flow base on process type
 * soc_type[in]: input soc_type
 * soc_addr[in]: input addr of image verified
 * process_type[in]: INIT/SUCC/FAIL state
 * return: SECBOOT_RET_SUCCESS if ok
 *         other err code if failed
 */
UINT32 hisi_secboot_process_soc_addr(UINT32 soc_type, const paddr_t soc_addr,
				     UINT32 process_type)
{
	UINT32 i;
	UINT32 ret = SECBOOT_RET_SUCCESS;
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
	}

	if (ret != SECBOOT_RET_SUCCESS)
		tloge("%s: soc_type(0x%x) process(0x%x) err", __func__,
		      soc_type, process_type);
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

	err_code =
		sre_mmap(src_addr, max_copy_len, &map_src_addr, secure, cache);
	if (err_code) {
		tloge("%s, map data buffer addr=0x%x error1\n", __func__,
		      src_addr);
		return SECBOOT_RET_INVALIED_ADDR_MAP;
	}

	/* map dst addr */
	err_code = sre_mmap(g_secimage_info[soc_type].ddr_phy_addr, max_copy_len,
			    &map_dst_addr, secure, cache);
	if (err_code) {
		tloge("%s, map data buffer addr=0x%x error2\n", __func__,
		      g_secimage_info[soc_type].ddr_phy_addr);
		err_code = SECBOOT_RET_INVALIED_ADDR_MAP;
		goto err_map_src;
	}

	/* copy image */
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

/* check is or modem image or not */
UINT32 is_modem(UINT32 soc_type)
{
	if (soc_type >= MODEM_START && soc_type <= MODEM_END)
		return SECBOOT_RET_SUCCESS;
	return SECBOOT_RET_FAILURE;
}

/*
 * modem for image copy
 * soc_type[in]: soc_type
 * offset[in]: offset of dest addr
 * src_addr[in]: src_addr
 * len: len of data
 * return: SECBOOT_RET_SUCCESS if ok
 *         other err code if failed
 */
static UINT32 secboot_modem_copy(UINT32 soc_type, UINT32 offset,
				 const paddr_t src_addr, UINT32 len)
{
	UINT32 ret;

	if (!g_verify_op_tbl[MODEM].copy) {
		tloge("%s modem ops not register\n", __func__);
		return SECBOOT_RET_MODEM_NOT_REGISTERED;
	}
	ret = g_verify_op_tbl[MODEM].copy(soc_type, offset, src_addr, len);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s modem copy failed\n", __func__);
		return SECBOOT_RET_MODEM_COPY_FAILED;
	}
	return SECBOOT_RET_SUCCESS;
}

/*
 * hisi_secboot_copy_soc_data
 * func for copy img data to img load addr
 * soc_type[in]: soc_type
 * offset[in]: offset of dest
 * src_addr[in]: src_addr
 * len: len of data
 * return: SECBOOT_RET_SUCCESS if ok
 *         other err code if failed
 */
UINT32 hisi_secboot_copy_soc_data(UINT32 soc_type, UINT32 offset,
				  const paddr_t src_addr, UINT32 len)
{
	UINT32 tmp_dst_addr = 0;
	UINT32 tmp_src_addr = 0;
	UINT32 size;

	/* modem process, call modem func */
	if (is_modem(soc_type) == SECBOOT_RET_SUCCESS)
		return secboot_modem_copy(soc_type, offset, src_addr, len);

	if (soc_type >= MAX_AP_SOC) {
		tloge("%s, invalid soctype!\n", __func__);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}
	if (src_addr == 0) {
		tloge("%s, vrladdr is null\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	size = g_secimage_info[soc_type].ddr_size;
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
	tloge("%s: out.\n", __func__);

	return SECBOOT_RET_SUCCESS;
}

/*
 * modem for image verify
 * vrl_address[in]: vrl addr
 * core_id[in]: core_id
 * lock_state[in]: state of device
 * return: SECBOOT_RET_SUCCESS if ok
 *         other err code if failed
 */
static UINT32 secboot_modem_verify(UINT32 soc_type, UINT32 vrl_addr,
				   paddr_t core_id,
				   SECBOOT_LOCKSTATE lock_state)
{
	UINT32 ret;

	if (!g_verify_op_tbl[MODEM].verification) {
		tloge("%s modem ops not register\n", __func__);
		return SECBOOT_RET_MODEM_NOT_REGISTERED;
	}
	ret = g_verify_op_tbl[MODEM].verification(soc_type, vrl_addr, core_id,
						  lock_state);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s modem verification failed\n", __func__);
		return SECBOOT_RET_MODEM_VERIFY_FAILED;
	}
	return SECBOOT_RET_SUCCESS;
}

UINT32 secboot_verify(UINT32 vrl_addr, size_t vrl_size, UINT32 img_addr,
		      size_t img_size, const char *img_name, size_t name_len)
{
	UINT32 ret;
	enum secboot_seccfg sec_cfg = SECBOOT_SECCFG_ERROR;
	struct seb_cert_pkg seb_certpkg = { 0 } ;

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
 * hisi_secboot_soc_verification
 * func for image verify
 * soc_type[in]: soc_type
 * vrl_address[in]: vrl addr
 * core_id[in]: core_id
 * lock_state[in]: state of device
 * return: SECBOOT_RET_SUCCESS if ok
 *         other err code if failed
 */
UINT32 hisi_secboot_soc_verification(UINT32 soc_type, UINT32 vrl_addr,
				     paddr_t core_id,
				     SECBOOT_LOCKSTATE lock_state)
{
	UINT32 ret;
	paddr_t imageaddresstmp;
	UINT8 imagename[SECBOOT_IMGNAME_MAXLEN] = { 0 };

	if (vrl_addr == 0 || vrl_addr == SEB_INVALID_VALUE) {
		tlogi("%s, invalid vrladdr:0x%x\n", __func__, vrl_addr);
		return SECBOOT_RET_FAILURE;
	}

	/* modem process, call modem func */
	if (is_modem(soc_type) == SECBOOT_RET_SUCCESS)
		return secboot_modem_verify(soc_type, vrl_addr, core_id,
					    lock_state);

	if (soc_type >= MAX_AP_SOC) {
		tloge("%s, invalid soctype!\n", __func__);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	tlogi("%s: begin,type=0x%x.\n", __func__, soc_type);

	/* get image addr */
	imageaddresstmp = g_secimage_info[soc_type].ddr_phy_addr;
	if (imageaddresstmp == SEB_INVALID_VALUE) {
		tloge("%s, %s invlide addr: vrladdr=0x%x, imageaddr=0x%llx.\n",
		      __func__, imagename, vrl_addr, imageaddresstmp);
		return SECBOOT_RET_FAILURE;
	}

	/* get image name */
	ret = secboot_get_soc_name_v2(soc_type, imagename,
				      SECBOOT_IMGNAME_MAXLEN);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, failed to get soc name 0x%x\n", __func__, soc_type);
		return ret;
	}

	/* verify image */
	ret = secboot_soc_verification(vrl_addr, imageaddresstmp,
				       (const char *)imagename, TRUE,
				       lock_state);
	if (ret) {
		tloge("%s, %s ", __func__, imagename);
		tloge("soc_type=0x%x v fail vrlAddr=0x%x, imageAddr=0x%llx.\n",
		      soc_type, vrl_addr, imageaddresstmp);
		return ret;
	}

	tlogi("%s:success\n", __func__);
	return SECBOOT_RET_SUCCESS;
}

/*
 * hisi_secboot_soc_reset
 * img reset process
 * soc_type[in]: soc_type
 * return: SECBOOT_RET_SUCCESS if ok
 *         other err code if failed
 */
UINT32 hisi_secboot_soc_reset(UINT32 soc_type)
{
	UINT32 ret;
	UINT32 tmp_type = soc_type;

	tlogi("%s:in.\n", __func__);
	if (is_modem(soc_type) == SECBOOT_RET_SUCCESS) {
		tmp_type = MODEM;
	} else if (soc_type >= MAX_AP_SOC) {
		tloge("%s, invalid soctype!\n", __func__);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	if (!g_verify_op_tbl[tmp_type].reset) {
		tloge("%s, reset of 0x%x not register!\n", __func__, soc_type);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	ret = g_verify_op_tbl[tmp_type].reset(soc_type);
	if (ret) {
		tloge("%s, 0x%x reset failed!\n", __func__, soc_type);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	tlogi("%s: out.\n", __func__);
	return SECBOOT_RET_SUCCESS;
}

/*
 * hisi_secboot_soc_set
 * img reset process
 * soc_type[in]: soc_type
 * return: SECBOOT_RET_SUCCESS if ok
 *         other err code if failed
 */
UINT32 hisi_secboot_soc_set(UINT32 soc_type)
{
	UINT32 ret;
	UINT32 tmp_type = soc_type;

	tloge("%s:secboot disreset in. soc_type is 0x%x\n", __func__, soc_type);

	/* max soc_type is MAX_SOC, max ap soc type is MAX_AP_SOC */
	if (is_modem(soc_type) == SECBOOT_RET_SUCCESS) {
		tmp_type = MODEM;
	} else if (soc_type >= MAX_AP_SOC) {
		tloge("%s, invalid soctype!\n", __func__);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	} else {
		tlogi("%s, legal soc_type!\n", __func__);
	}

	if (!g_verify_op_tbl[tmp_type].set) {
		tloge("%s, set of 0x%x not register!\n", __func__, soc_type);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	ret = g_verify_op_tbl[tmp_type].set(soc_type);
	if (ret) {
		tloge("%s, 0x%x set failed!\n", __func__, soc_type);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	tlogi("%s:out.\n", __func__);
	return SECBOOT_RET_SUCCESS;
}

/*
 * init g_verify_op_tbl: hifi, ivp and isp;
 * modem should register by secboot_modem_register
 */
static void init_verify_ops(void)
{
	(void)memset_s((void *)g_verify_op_tbl, sizeof(g_verify_op_tbl), 0,
		       sizeof(g_verify_op_tbl));
	g_verify_op_tbl[HIFI].set = hifi_set;
	g_verify_op_tbl[HIFI].reset = hifi_reset;
	g_verify_op_tbl[IVP].set = hisi_ivp_set;
	g_verify_op_tbl[IVP].reset = hisi_ivp_reset;
	g_verify_op_tbl[ISP].set = hisi_isp_set_v2;
	g_verify_op_tbl[ISP].reset = hisi_isp_reset_v2;
}

INT32 hisi_secboot_info_init(void)
{
	INT32 ret;

	init_verify_ops();

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
	uint64_t *args = (uint64_t *)(uintptr_t)params->args;

	HANDLE_SYSCALL(swi_id)
	{
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

		uwret = eiius_encrypto_ctr(args[0],
			args[1], (uint32_t)args[2],
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
