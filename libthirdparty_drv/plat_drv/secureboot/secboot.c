/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
 * Description: bsp layer of secboot, call by secureboot
 * Create: 2013/5/16
 */

#include "secboot.h"
#include <sre_typedef.h>
#include <sre_debug.h> // uart_printf
#include <drv_mem.h> // sre_mmap
#include <drv_cache_flush.h> // v7_dma_flush_range
#include "hisi_seclock.h"
#include "hisi_secureboot.h"
#include "mem_page_ops.h"
#include <drv_module.h>
#include <securec.h>
#include <hifi.h>
#include <hisi_isp.h>
#include <ivp.h>
#include <boot_sharedmem.h>
#include <tee_log.h>
#include <sys_generic.h>
#include <hisi_boot.h>
#include "cc_power.h"
#define CONFIG_SECBOOT_EFUSE_NO_SECLCS

#define SECBOOT_VRL_FLAG_ENCRYPTION_USED_BIT_LOCATION 16
#define SECBOOT_OTP_CARRIERID_SEL                     48
#define SECBOOT_OTP_CARRIERID_DW1                     49
#define SECBOOT_OTP_CARRIERID_DW2                     50
#define SECBOOT_OTP_CARRIERID_DW3                     51
#define SECBOOT_OTP_CARRIERID_DW4                     52
#define SECBOOT_OTP_CARRIERID_DW5                     53
#define SECBOOT_OTP_CCS_DW_SIZE                       4

#ifdef CONFIG_CHECK_PLATFORM_INFO
#define SECBOOT_CHIPID_SHIFT                          16
#endif

/* VRL header structure */
struct vrl_header_t {
	/* Magic number to validate VRL */
	UINT32 magic_number;
	/* Certificate version to validate certificate */
	UINT32 vrl_version;
	/*
	 * Bits [0:15] holds direct offset in words to the VRL signature,
	 * Bits [16:31] holds the number of sw components
	 */
	UINT32 vrl_size;
	/*
	 * Bits [0:7] holds HASH algorithm identifier
	 * Bits [8:15] holds pub key algorithm identifier
	 * Bits [16] is SW revocation supported
	 * Bits [17] is Secondary VRL exist
	 * Bits [18:31] reserved
	 */
	UINT32 vrl_flags;
};

/* SW component information */
struct vrl_swaddinfo_t {
	/* Hash value in content, should be UINT32 * 8 */
	UINT32 hash_value[8];
	/* load address */
	UINT64 load_addr;
	/* sign value, should be UINT32 * 64 */
	UINT32 cert_sign[64];
	UINT64 store_addr;
	UINT32 store_len;
};

struct vrl_nvcountinfo_t {
	/* sign value, should be UINT32 * 64 */
	UINT32 rsa_pubkey[64];
	/* barr value, should be UINT32 * 5 */
	UINT32 barr_value[5];
	UINT32 nvcount_type;
	UINT32 nvcount_value;
};

/* MACRO to count one bits */
#define COUNT_ONE_BITS(number, bitcount)                                       \
	do {                                                                   \
		UINT32 tmp_num = number;                                       \
		bitcount = 0;                                                  \
		while (tmp_num) {                                              \
			tmp_num = tmp_num & (tmp_num - 1);                     \
			bitcount = bitcount + 1;                               \
		}                                                              \
	} while (0)

struct secboot_imggrp {
	UINT32 imggrp_id;
	char **imggrp_list_ptr;
};

/*
 * the struct decripts secure info, the length is 108 bytes
 * mark, provision key temporarily on the front of head magic
 */
struct tee_secureinfo {
	UINT8 provision_key[PROVISON_SIZE_IN_BYTES]; /* provision key:1*16 */
	UINT32 head_magic; /* magic number:4 */
	UINT16 oem_id; /* oemid:2 */
	UINT16 hw_id; /* hwid:2 */
	UINT8 sec_cfg; /* otp state:1 */
	UINT8 lock_status; /* sec lock status:1 */
	UINT8 first_vernum; /* first verision number:1 */
	UINT8 second_vernum; /* second verision number:1 */
	UINT8 unsec_vernum; /* unsec verision number:1 */
	UINT8 die_id[DIEID_SIZE_IN_BYTES]; /* dieid:1*20 */
	UINT8 fbe2_flag; /* fbe2 flag; 0: normal  else(A5): enhanced */
	UINT8 for_align[6]; /* for_align:1*6 */
	UINT64 eiius_addr; /* eiius wkspace addr:8 */
	UINT32 eiius_size; /* eiius wkspace size:4 */
	UINT32 pubkey_hash[HASH_SIZE_IN_WORDS]; /* eng pubkey hash:32 */
	UINT32 img_nvcnt; /* eng pubkey hash:4 */
	UINT32 tail_magic; /* magic number:4 */
} __attribute__((__packed__));

#define SECBOOT_MAGIC_NUM 0x55AA55AA

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* the workspcae of ccs */
#define SECBOOT_DX_WORKSPACE_SIZE (128 * 1024 + 2 * 1024)
static void *g_secboot_workspace_addr;

INT32 secboot_dma_init(void)
{
	/* malloc at the beginning, no need to free */
	g_secboot_workspace_addr = malloc_coherent(SECBOOT_DX_WORKSPACE_SIZE);
	if (!g_secboot_workspace_addr) {
		tloge("%s: fail to malloc SECBOOT_DX_WORKSPACE\n", __func__);
		return -1;
	}
	return 0;
}

/* define the images that need to update version. */
static const char g_secboot_grplist_sec1udp[SECBOOT_GRPIMG_MAXNUM][SECBOOT_IMGNAME_MAXLEN] = {
	"fastboot", "", "", "", "", "", "", "", "", ""
};

static const char g_secboot_grplist_sec2udp[SECBOOT_GRPIMG_MAXNUM][SECBOOT_IMGNAME_MAXLEN] = {
	"modem", "modem_dtb", "modem_fw", "modem_dsp", "fw_hifi", "isp_firmware", "", "", "", ""
};

static const char g_secboot_grplist_unsecudp[SECBOOT_GRPIMG_MAXNUM][SECBOOT_IMGNAME_MAXLEN] = {
	"boot", "recovery", "recovery2", "", "", "", "", "", "", ""
};

/* define the images that need to check version. */
static const char g_secboot_grplist_sec1chk[SECBOOT_GRPIMG_MAXNUM][SECBOOT_IMGNAME_MAXLEN] = {
	"xloader", "fastboot", "", "", "", "", "", "", "", ""
};

static const char g_secboot_grplist_sec2chk[SECBOOT_GRPIMG_MAXNUM][SECBOOT_IMGNAME_MAXLEN] = {
	"modem", "modem_dtb", "modem_fw", "modem_dsp", "fw_hifi", "isp_firmware", "", "", "", ""
};

static const char g_secboot_grplist_unsecchk[SECBOOT_GRPIMG_MAXNUM][SECBOOT_IMGNAME_MAXLEN] = {
	"boot", "recovery", "recovery2", "", "", "", "", "", "", ""
};

/* define the images that need to verify. */
static const char g_secboot_grplist_preload[SECBOOT_GRPIMG_MAXNUM][SECBOOT_IMGNAME_MAXLEN] = {
	"modem", "modem_dtb", "modem_fw", "modem_dsp", "fw_hifi", "isp_firmware", "", "", "", ""
};

static const char g_secboot_grplist_bootup[SECBOOT_GRPIMG_MAXNUM][SECBOOT_IMGNAME_MAXLEN] = {
	"boot", "recovery", "recovery2", "", "", "", "", "", "", ""
};

static struct secboot_imggrp g_img_grp[] = {
	{ SECBOOT_IMGGRPID_SEC1UPD, (char **)g_secboot_grplist_sec1udp },
	{ SECBOOT_IMGGRPID_SEC2UPD, (char **)g_secboot_grplist_sec2udp },
	{ SECBOOT_IMGGRPID_UNSECUPD, (char **)g_secboot_grplist_unsecudp },
	{ SECBOOT_IMGGRPID_SEC1CHK, (char **)g_secboot_grplist_sec1chk },
	{ SECBOOT_IMGGRPID_SEC2CHK, (char **)g_secboot_grplist_sec2chk },
	{ SECBOOT_IMGGRPID_UNSECCHK, (char **)g_secboot_grplist_unsecchk },
	{ SECBOOT_IMGGRPID_PRELOAD, (char **)g_secboot_grplist_preload },
	{ SECBOOT_IMGGRPID_BOOTUP, (char **)g_secboot_grplist_bootup },
};

static struct tee_secureinfo g_secboot_secinfo;
/* this array used by modem, not static here */
struct secboot_info g_image_info[MAX_SOC];

static UINT32 secboot_version_verify(struct seb_cert_pkg *seb_certpkg,
				     const char *imagename);
static UINT32 secboot_getimggrpid(const char *imagename);

UINT32 secboot_get_image_info_addr(struct secboot_info **image_info, UINT32 *size)
{
	if (!image_info || !size) {
		tloge("%s invalid input\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	*image_info = &g_image_info[0];
	*size = MAX_SOC;

	return SECBOOT_RET_SUCCESS;
}

UINT32 seb_parservrl(UINT32 vrladdress, UINT32 *img_size)
{
	UINT32 ret;
	struct seb_cert_pkg seb_certpkg = { 0 };
	struct seb_comps_info_t pswimagesdata = { 0 };
	struct vrl_swaddinfo_t *tempswinfo = NULL;

	ret = seb_fillcertpkg((UINT64)vrladdress, &seb_certpkg);
	if (ret) {
		tloge("%s: seb_fillcertpkg error(0x%x)!\n", __func__, ret);
		return SECBOOT_RET_FAILURE;
	}

	/* parse primary vrl and get components of vrl. */
	ret = seb_get_compdata((UINT32 *)(uintptr_t)seb_certpkg.concert_addr,
			       &pswimagesdata);
	if (ret) {
		tloge("%s: seb_get_compdata error(0x%x)!\n", __func__, ret);
		return SECBOOT_RET_FAILURE;
	}

	tempswinfo = (struct vrl_swaddinfo_t *)pswimagesdata.p_comps_data;
	*img_size = tempswinfo->store_len * sizeof(UINT32);
	return SECBOOT_RET_SUCCESS;
}

/*
 * This function is responsible to verification of the VRL list
 * read from EMMC/RAM.
 */
UINT32 secboot_imageverification(struct seb_cert_pkg *seb_certpkg,
				 const char *imagename, BOOL besecure,
				 BOOL beram, BOOL beburning)
{
	UINT32 user_context;
	UINT32 *context_ptr = NULL;
	UINT32 ret = SECBOOT_RET_SUCCESS;
	UINT64 vrl_ptr = 0;
	struct vrl_header_t *vrl_header = NULL;
	INT32 res;

	if (!seb_certpkg || !imagename || !g_secboot_workspace_addr) {
		tloge("%s input err\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}
	if (!beram) {
		tloge("%s only beram support\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	user_context = 0;
	context_ptr = &user_context;

	vrl_ptr = seb_certpkg->concert_addr;
	vrl_header = (struct vrl_header_t *)(uintptr_t)(
			(UINT32)vrl_ptr + sizeof(struct vrl_additiondata));
	if (vrl_header->vrl_flags &
		(0x1 << SECBOOT_VRL_FLAG_ENCRYPTION_USED_BIT_LOCATION)) {
		if (beburning)
			context_ptr = NULL;
	}
	res = secs_power_on();
	if (res != 0) {
		tloge("secs power on failed\n");
		return SECBOOT_RET_FAILURE;
	}

	if (besecure) {
		ret = seb_imgsecure_verify(seb_flashread_ram,
					   seb_certpkg, context_ptr,
					   g_secboot_workspace_addr,
					   SECBOOT_DX_WORKSPACE_SIZE);
		if (ret != SECBOOT_RET_SUCCESS) {
			tloge("%s: SEB_FlashImageVerification error(0x%x)!\n",
			      __func__, ret);
			goto err_proc;
		}
		ret = secboot_version_verify(seb_certpkg, imagename);
		if (ret != SECBOOT_RET_SUCCESS) {
			tloge("%s: secboot_version_verify error(0x%x)!\n",
			      __func__, ret);
			goto err_proc;
		}
	} else {
		ret = seb_imghash_verify(seb_flashread_ram, context_ptr,
					 vrl_ptr,
					 g_secboot_workspace_addr,
					 SECBOOT_DX_WORKSPACE_SIZE);
		if (ret != SECBOOT_RET_SUCCESS) {
			tloge("%s: SEB_ImageHashVerification error(0x%x)!\n",
			      __func__, ret);
			goto err_proc;
		}
	}
err_proc:
	res = secs_power_down();
	if (res != 0) {
		tloge("secs power down failed\n");
		if (ret != SECBOOT_RET_SUCCESS)
			return SECBOOT_RET_FAILURE;
	}
	return ret;
}

/*
 * If engineering img in ship device, have some process.
 * img_keycert1_addr: input para, img's 1 level keycert address.
 */
void secboot_engineering_img_process(uintptr_t img_keycert1_addr)
{
	struct vrl_additiondata *addtion_data =
		(struct vrl_additiondata *)img_keycert1_addr;

	if (!addtion_data) {
		tloge("%s: wrong keycert address.\n", __func__);
		return;
	}

	tloge("%s: %s engineering img in ship device!\n", __func__,
	      addtion_data->partitionname);
}

#if defined(CONFIG_CHECK_PTN_NAME)
static UINT32 sec_boot_check_ptn_name(const char *imagename,
				      struct seb_cert_pkg *seb_certpkg)
{
	struct vrl_additiondata *p_add_data = NULL;

	if (seb_certpkg->keycert1_addr == 0 || seb_certpkg->keycert2_addr == 0 ||
		seb_certpkg->concert_addr == 0) {
		tloge("%s invalid seb_certpkg\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	p_add_data = (struct vrl_additiondata *)(uintptr_t)(
		seb_certpkg->keycert1_addr);
	if (strncmp(imagename, (const char *)p_add_data->partitionname,
		    SECBOOT_IMGNAME_MAXLEN)) {
		tloge("%s: ptn mismatch in 1st additional_data, %s,%s\n",
		      __func__, imagename, p_add_data->partitionname);
		return SECBOOT_RET_VRL_INVALID;
	}
	if (seb_certpkg->keycert2_addr != SEB_INVALID_ADDR) {
		p_add_data = (struct vrl_additiondata *)(uintptr_t)(
			seb_certpkg->keycert2_addr);
		if (strncmp(imagename, (const char *)p_add_data->partitionname,
			    SECBOOT_IMGNAME_MAXLEN)) {
			tloge("%s: ptn mismatch in 2nd add_data, %s,%s\n",
			      __func__, imagename, p_add_data->partitionname);
			return SECBOOT_RET_VRL_INVALID;
		}
	}
	p_add_data = (struct vrl_additiondata *)(uintptr_t)(
		seb_certpkg->concert_addr);
	if (strncmp(imagename, (const char *)p_add_data->partitionname,
		    SECBOOT_IMGNAME_MAXLEN)) {
		tloge("%s: ptn mismatch in 3rd additional_data, %s,%s\n",
		      __func__, imagename, p_add_data->partitionname);
		return SECBOOT_RET_VRL_INVALID;
	}
	return SECBOOT_RET_SUCCESS;
}
#endif

static UINT32 secboot_get_secinfo_nv_counter(UINT32 *cert_addr,
					     UINT32 *nv_counter)
{
	struct vrl_nvcountinfo_t nv_count_info;
	UINT32 offset;
	UINT32 ret;

	if (!nv_counter || !cert_addr) {
		tloge("%s, param error\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	offset = (sizeof(struct vrl_additiondata) +
		  sizeof(struct vrl_header_t)) / sizeof(UINT32);
	ret = memcpy_s((void *)&nv_count_info, sizeof(struct vrl_nvcountinfo_t),
		       (void *)(cert_addr + offset),
		       sizeof(struct vrl_nvcountinfo_t));
	if (ret != EOK) {
		tloge("%s, memcpy failed\n", __func__);
		return SECBOOT_RET_FAILURE;
	}
	*nv_counter = nv_count_info.nvcount_value;
	return SECBOOT_RET_SUCCESS;
}

static UINT32 secboot_check_secinfo_magic(void)
{
	if (g_secboot_secinfo.head_magic != SECBOOT_MAGIC_NUM ||
	    g_secboot_secinfo.tail_magic != SECBOOT_MAGIC_NUM) {
		tloge("secboot secinfo error, head_magic 0x%x, tail_magic 0x%x\n",
		      g_secboot_secinfo.head_magic,
		      g_secboot_secinfo.tail_magic);
		return SECBOOT_RET_FAILURE;
	}
	return SECBOOT_RET_SUCCESS;
}

static UINT32 secboot_get_secinfo_seccfg(UINT8 *pseccfg)
{
	if (!pseccfg) {
		tloge("%s, param error\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
		return SECBOOT_RET_FAILURE;

	*pseccfg = g_secboot_secinfo.sec_cfg;

	return SECBOOT_RET_SUCCESS;
}

UINT32 secboot_get_secinfo_dieid(UINT32 *pdieid, UINT32 len)
{
	UINT32 ret;

	if (!pdieid || len < sizeof(g_secboot_secinfo.die_id)) {
		tloge("%s, param error\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
		return SECBOOT_RET_FAILURE;

	ret = memcpy_s((void *)pdieid, len, (void *)g_secboot_secinfo.die_id,
		       sizeof(g_secboot_secinfo.die_id));
	if (ret != EOK) {
		tloge("%s, memcpy failed\n", __func__);
		return SECBOOT_RET_FAILURE;
	}
	return SECBOOT_RET_SUCCESS;
}

#ifndef FILE_ENCRY_KEY_ENHANCED
#define FILE_ENCRY_KEY_ENHANCED 0x5A
#endif
UINT32 secboot_get_fbe2_flag(UINT8 *fbe2_flag)
{
	if (!fbe2_flag) {
		tloge("%s, param error\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

#ifdef TEE_SUPPORT_FILE_ENCRY_PASS_FBE2
	if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
		return SECBOOT_RET_FAILURE;
	*fbe2_flag = g_secboot_secinfo.fbe2_flag;
#else
	*fbe2_flag = FILE_ENCRY_KEY_ENHANCED;
#endif

	return SECBOOT_RET_SUCCESS;
}

#ifndef CONFIG_DERIVE_TEEKEY
UINT32 plat_derive_teekey(UINT8 *pkey, UINT32 len)
{
	UINT32 ret;

	if (!pkey || len < sizeof(g_secboot_secinfo.provision_key)) {
		tloge("%s, param error\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
		return SECBOOT_RET_FAILURE;

	ret = memcpy_s((void *)pkey, len,
		       (void *)g_secboot_secinfo.provision_key,
		       sizeof(g_secboot_secinfo.provision_key));
	if (ret != EOK) {
		tloge("%s, memcpy failed\n", __func__);
		return SECBOOT_RET_FAILURE;
	}

	return SECBOOT_RET_SUCCESS;
}
#endif
/*
 * Get engineering pubkey hash from secure share memory.
 * pub_hash: input/output para, point to pubkey hash.
 * len: input para, length of pub_hash.
 * return: 0 success ; other fail.
 */
UINT32 secboot_get_pubkey_hash(UINT32 *pub_hash, UINT32 len)
{
	if (!pub_hash || len < sizeof(g_secboot_secinfo.pubkey_hash)) {
		tloge("%s, param error.\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS) {
		tloge("%s, magic error.\n", __func__);
		return SECBOOT_RET_FAILURE;
	}

	if (memcpy_s((void *)pub_hash, len,
		     (void *)g_secboot_secinfo.pubkey_hash,
		     sizeof(g_secboot_secinfo.pubkey_hash)) != EOK) {
		tloge("%s, memcpy error.\n", __func__);
		return SECBOOT_RET_FAILURE;
	}

	return SECBOOT_RET_SUCCESS;
}

/*
 * check the oem_id from sharemem
 * between fastboot and teeos read from efuse
 * and oem id from image certificate
 */
static UINT32 secboot_check_oem_info(struct seb_cert_pkg *seb_certpkg)
{
#ifdef CONFIG_CHECK_OEM_INFO
	if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
		return SECBOOT_RET_FAILURE;

	UINT32 oem_id = g_secboot_secinfo.oem_id;
	struct vrl_additiondata *key_additiondata_ptr = (struct vrl_additiondata *)
		(uintptr_t)(seb_certpkg->keycert1_addr);

	if (oem_id != key_additiondata_ptr->oem_id) {
		tloge("check oem info error\n");
		return SECBOOT_RET_VRL_INVALID;
	}
#else
	UNUSED(seb_certpkg);
#endif
	return SECBOOT_RET_SUCCESS;
}

static UINT32 secboot_get_secinfo_firstvernum(UINT8 *pvernum)
{
	if (!pvernum) {
		tloge("%s, param error\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
		return SECBOOT_RET_FAILURE;

	*pvernum = g_secboot_secinfo.first_vernum;

	return SECBOOT_RET_SUCCESS;
}

static UINT32 secboot_get_secinfo_secondvernum(UINT8 *pvernum)
{
	if (!pvernum) {
		tloge("%s, param error\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
		return SECBOOT_RET_FAILURE;

	*pvernum = g_secboot_secinfo.second_vernum;

	return SECBOOT_RET_SUCCESS;
}

static UINT32 secboot_get_secinfo_unsecvernum(UINT8 *pvernum)
{
	if (!pvernum) {
		tloge("%s, param error\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
		return SECBOOT_RET_FAILURE;

	*pvernum = g_secboot_secinfo.unsec_vernum;

	return SECBOOT_RET_SUCCESS;
}

UINT32 eiius_get_workspace_info(UINT64 *eiius_addr, UINT32 *eiius_size)
{
	if (!eiius_addr) {
		tloge("error,eiius addr is NULL\n");
		return SECBOOT_RET_FAILURE;
	}
	if (!eiius_size) {
		tloge("error,eiius size is NULL\n");
		return SECBOOT_RET_FAILURE;
	}

	if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
		return SECBOOT_RET_FAILURE;

	*eiius_addr = g_secboot_secinfo.eiius_addr;
	*eiius_size = g_secboot_secinfo.eiius_size;

	return SECBOOT_RET_SUCCESS;
}

void secboot_print_secinfo(void)
{
#ifdef SECBOOT_SECINFO_DEBUG_ON
	UINT32 ret, i;
	UINT8 sec_cfg;
	UINT8 first_vernum, second_vernum, unsec_vernum;
	UINT16 oem_id, hw_id;
	UINT64 eiius_addr;
	UINT32 eiius_size;
	UINT8 die_id[DIEID_SIZE_IN_BYTES] = { 0 };
	UINT8 provision_key[PROVISON_SIZE_IN_BYTES] = { 0 };

	ret = secboot_get_secinfo_seccfg(&sec_cfg);
	ret |= secboot_get_secinfo_dieid(die_id, sizeof(die_id));
	ret |= secboot_get_secinfo_firstvernum(&first_vernum);
	ret |= secboot_get_secinfo_secondvernum(&second_vernum);
	ret |= secboot_get_secinfo_unsecvernum(&unsec_vernum);
	ret |= eiius_get_workspace_info(&eiius_addr, &eiius_size);

	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s, get secinfo fail\n", __func__);
		return;
	}

	/* print secinfo */
	tloge("[secinfo] sec_cfg: 0x%x\n", sec_cfg);
	for (i = 0; i < DIEID_SIZE_IN_BYTES; i++)
		tloge("[secinfo] die_id[0x%x]: 0x%x\n", i, die_id[i]);

	for (i = 0; i < PROVISON_SIZE_IN_BYTES; i++)
		tloge("[secinfo] provision_key[0x%x]: 0x%x\n", i,
		      provision_key[i]);

	tloge("[secinfo] oem_id: 0x%x\n", oem_id);
	tloge("[secinfo] hw_id: 0x%x\n", hw_id);
	tloge("[secinfo] first_vernum: 0x%x\n", first_vernum);
	tloge("[secinfo] second_vernum: 0x%x\n", second_vernum);
	tloge("[secinfo] unsec_vernum: 0x%x\n", unsec_vernum);
	tloge("[secinfo] eiius_addr: 0x%x\n", eiius_addr);
	tloge("[secinfo] eiius_size: 0x%x\n", eiius_size);
#endif
}

INT32 secboot_get_secinfo(void)
{
	UINT32 ret;

	/* clear secboot secinfo zero */
	(void)memset_s((void *)&g_secboot_secinfo,
		       sizeof(struct tee_secureinfo), 0,
		       sizeof(struct tee_secureinfo));

	/* map secboot secinfo ddr memory address */
	ret = (UINT32)get_shared_mem_info(TEEOS_SHARED_MEM_SECBOOT,
					     (unsigned int *)&g_secboot_secinfo,
					     sizeof(struct tee_secureinfo));
	if (ret) {
		tloge("Get sharemem info Failed, ret is 0x%x.\n", ret);
		return -1;
	}

	ret = secboot_check_secinfo_magic();
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s fail.\n", __func__);
		return -1;
	}
	tlogd("%s ok.\n", __func__);

	/* print secinfo */
	secboot_print_secinfo();

	return 0;
}

#ifdef CONFIG_CHECK_PLATFORM_INFO
static UINT32 secboot_getchipid(void)
{
	return hisi_readl(SCSOCID0);
}
#endif

UINT32 secboot_check_adddata(struct seb_cert_pkg *seb_certpkg,
			     const char *imagename,
			     struct vrl_additiondata *additiondataptr,
			     UINT32 isprimvrl)
{
	struct vrl_additiondata *additiondata_ptr = NULL;
	UINT32 ret;

	UNUSED(isprimvrl);

	if (!seb_certpkg || !imagename || seb_certpkg->concert_addr == 0) {
		tloge("%s input err\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}
#if defined(CONFIG_CHECK_PTN_NAME)
	if (sec_boot_check_ptn_name(imagename, seb_certpkg)) {
		tloge("%s: check_ptn_name error!\n", __func__);
		return SECBOOT_RET_VRL_INVALID;
	}
#endif
	additiondata_ptr = (struct vrl_additiondata *)(uintptr_t)(
		seb_certpkg->concert_addr);

	/* check the burnchk flag in additional data. */
	if (additiondata_ptr->burncheckflag != SECBOOT_VRL_BURNCHK_N &&
	    additiondata_ptr->burncheckflag != SECBOOT_VRL_BURNCHK_Y) {
		tloge("%s: check burnchk flag error!\n", __func__);
		return SECBOOT_RET_VRL_INVALID;
	}

	/* check the bootchk flag in additional data. */
	if (additiondata_ptr->bootmodeflag != SECBOOT_VRL_BOOTMODE_EMMC &&
	    additiondata_ptr->bootmodeflag != SECBOOT_VRL_BOOTMODE_RAM) {
		tloge("%s: check bootchk flag error!\n", __func__);
		return SECBOOT_RET_VRL_INVALID;
	}
#ifdef CONFIG_CHECK_PLATFORM_INFO
	UINT32 chipid = secboot_getchipid();
	UINT32 platinfo = chipid >> SECBOOT_CHIPID_SHIFT;

	if (platinfo != additiondata_ptr->platinfo) {
		tloge("%s: check platform information error!\n", __func__);
		return SECBOOT_RET_VRL_INVALID;
	}
#endif

	ret = secboot_check_oem_info(seb_certpkg);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("check oem info error\n");
		return SECBOOT_RET_VRL_INVALID;
	}

	ret = memcpy_s(additiondataptr, sizeof(struct vrl_additiondata),
		       additiondata_ptr, sizeof(struct vrl_additiondata));
	if (ret != EOK) {
		tloge("%s, memcpy failed\n", __func__);
		return SECBOOT_RET_FAILURE;
	}
	return SECBOOT_RET_SUCCESS;
}

static UINT32 secboot_version_verify(struct seb_cert_pkg *seb_certpkg,
				     const char *imagename)
{
	UINT32 imggrp_id;
	UINT32 version_val = 0;
	UINT32 ret = SECBOOT_RET_SUCCESS;
	UINT8 first_vernum = 0;
	UINT8 second_vernum = 0;
	UINT8 unsec_vernum = 0;

	imggrp_id = secboot_getimggrpid(imagename);
	if (imggrp_id & SECBOOT_IMGGRPID_SEC1UPD) {
		ret = secboot_get_secinfo_nv_counter(
			(UINT32 *)(uintptr_t)seb_certpkg->concert_addr,
			&version_val);
		if (ret != SECBOOT_RET_SUCCESS) {
			tloge("%s: sec1 class version check error!\n",
			      __func__);
			return ret;
		}

		ret = secboot_get_secinfo_firstvernum(&first_vernum);
		if (ret != SECBOOT_RET_SUCCESS) {
			tloge("%s: get secinfo firstvernum error!\n", __func__);
			return ret;
		}

		if (first_vernum > version_val) {
			tloge("%s: first version verify failed!\n", __func__);
			return SECBOOT_RET_FAILURE;
		}
	}

	if (imggrp_id & SECBOOT_IMGGRPID_SEC2UPD) {
		version_val = ((struct vrl_additiondata *)(uintptr_t)
			seb_certpkg->concert_addr)->sec2curver;
		ret = secboot_get_secinfo_secondvernum(&second_vernum);
		if (ret != SECBOOT_RET_SUCCESS) {
			tloge("%s: get secinfo secondvernum error!\n",
			      __func__);
			return ret;
		}

		if (second_vernum > version_val) {
			tloge("%s: second version verify failed! ", __func__);
			tloge("second_vernum 0x%x, version_val 0x%x\n",
			      second_vernum, version_val);
			return SECBOOT_RET_FAILURE;
		}
	}

	if (imggrp_id & SECBOOT_IMGGRPID_UNSECUPD) {
		ret = secboot_get_secinfo_nv_counter(
			(UINT32 *)(uintptr_t)seb_certpkg->concert_addr,
			&version_val);
		if (ret != SECBOOT_RET_SUCCESS) {
			tloge("%s: unsec class version check error!\n",
			      __func__);
			return ret;
		}

		ret = secboot_get_secinfo_unsecvernum(&unsec_vernum);
		if (ret != SECBOOT_RET_SUCCESS) {
			tloge("%s: get secinfo unsecvernum error!\n", __func__);
			return ret;
		}

		if (unsec_vernum > version_val) {
			tloge("%s: unsec version verify failed!\n", __func__);
			return SECBOOT_RET_FAILURE;
		}
	}

	return ret;
}

static UINT32 secboot_getimggrpid(const char *imagename)
{
	UINT32 imggrp_id;
	struct secboot_imggrp *img_grp = NULL;
	UINT32 grp_num;
	UINT32 i;
	UINT32 j;
	char *list_ptr = NULL;

	imggrp_id = SECBOOT_IMGGRPID_NONE;
	img_grp = g_img_grp;
	grp_num = ARRAY_SIZE(g_img_grp);
	for (i = 0; i < grp_num; i++) {
		list_ptr = (char *)(img_grp[i].imggrp_list_ptr);
		for (j = 0; j < SECBOOT_GRPIMG_MAXNUM; j++) {
			if (!strncmp(imagename,
				     (list_ptr + (SECBOOT_IMGNAME_MAXLEN * j)),
				     SECBOOT_IMGNAME_MAXLEN)) {
				tloge("%s: %s\n",
				      (list_ptr + (SECBOOT_IMGNAME_MAXLEN * j)),
				      __func__);
				break;
			}
		}
		if (j < SECBOOT_GRPIMG_MAXNUM)
			imggrp_id |= img_grp[i].imggrp_id;
	}
	return imggrp_id;
}

/* get parser config function */
UINT32 secboot_getseccfg(enum secboot_seccfg *seccfg)
{
	UINT32 lcs;
	UINT8 sec_cfg;
	UINT32 ret;
	INT32 res;

	if (!seccfg) {
		tloge("%s, invalid input param\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	res = secs_power_on();
	if (res != 0) {
		tloge("secs power on failed\n");
		return SECBOOT_RET_FAILURE;
	}
	ret = seb_getlcs(&lcs);

	res = secs_power_down();
	if (res != 0) {
		tloge("secs power down failed\n");
		return SECBOOT_RET_FAILURE;
	}
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s: SecBoot_GetLcs error(0x%x)\n", __func__, ret);
		*seccfg = SECBOOT_SECCFG_ERROR;
		return ret;
	}

	switch (lcs) {
	case SEB_RMA_LCS:
	case SEB_SECURE_LCS:
		*seccfg = SECBOOT_SECCFG_SECURE;
		return SECBOOT_RET_SUCCESS;
	case SEB_SECURITY_DISABLED_LCS:
	case SEB_CHIP_MANUFACTURE_LCS:
	case SEB_DEVICE_MANUFACTURE_LCS:
#ifndef CONFIG_SECBOOT_EFUSE_NO_INTEGRALITY
		ret = secboot_get_secinfo_seccfg(&sec_cfg);
		if (ret != SECBOOT_RET_SUCCESS) {
			tloge("%s: SEB_ReadOTPWord error\n", __func__);
			return ret;
		}
		if (sec_cfg == SECBOOT_SECCFG_INTEGRITY)
			*seccfg = SECBOOT_SECCFG_INTEGRITY;
		else
			*seccfg = SECBOOT_SECCFG_NONE;
#else
		*seccfg = SECBOOT_SECCFG_NONE;
#endif
		return SECBOOT_RET_SUCCESS;
	default:
		tloge("%s: lcs default error\n", __func__);
		*seccfg = SECBOOT_SECCFG_ERROR;
		return SECBOOT_RET_FAILURE;
	}
}

UINT32 secboot_changecompstoreaddr(struct seb_cert_pkg *seb_certpkg,
				   paddr_t storeaddress)
{
	UINT32 ret;

	if (!seb_certpkg || storeaddress == 0 ||
		seb_certpkg->concert_addr == 0) {
		tloge("%s: invalid input\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}

	/* change the image store address to the RAM address. */
	ret = seb_change_compaddr(
		(UINT32 *)(uintptr_t)(seb_certpkg->concert_addr), storeaddress,
		0);
	if (ret != SECBOOT_RET_SUCCESS) {
		tloge("%s:seb_change_compaddr error(0x%x)!\n", __func__, ret);
		return ret;
	}

	return SECBOOT_RET_SUCCESS;
}

UINT32 get_cma_size(UINT32 soc_type)
{
	if (soc_type == HIFI)
		return get_hifi_cma_size();
	else if (soc_type == ISP)
		return get_isp_cma_size();
#ifdef CONFIG_HISI_IVP_SEC_IMAGE
	else if (soc_type == IVP)
		return get_ivp_cma_size();
#endif
	else
		return SECBOOT_ILLEGAL_CMA_SIZE;
}

UINT32 get_base_addr(UINT32 soc_type)
{
	if (soc_type == ISP)
		return get_isp_baseaddr();
	return SECBOOT_ILLEGAL_BASE_ADDR;
}

UINT32 process_map_addr(UINT32 soc_type, UINT32 *map_addr, UINT32 *cma_size)
{
	paddr_t soc_addr;

	if (!map_addr || !cma_size) {
		tloge("%s, input param is null\n", __func__);
		return SECBOOT_RET_FAILURE;
	}

	if (soc_type >= MAX_SOC) {
		tloge("%s soc_type err\n", __func__);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	*cma_size = get_cma_size(soc_type);
	soc_addr = g_image_info[soc_type].ddr_phy_addr;

	if (sre_mmap(soc_addr, *cma_size, map_addr, secure, cache)) {
		tloge("%s, map soc_addr=0x%x size=0x%x error\n", __func__,
		      soc_addr, *cma_size);
		return SECBOOT_RET_INVALIED_ADDR_MAP;
	}
	return SECBOOT_RET_SUCCESS;
}

void process_clean_addr(UINT32 map_addr, UINT32 cma_size)
{
	/* ignore memset_s fail before unmap */
	(void)memset_s((void *)(uintptr_t)map_addr, cma_size, 0, cma_size);
	/* using dma cache flush in MP platform instead of flush cache all */
	v7_dma_flush_range(map_addr, map_addr + cma_size);
	(void)sre_unmap(map_addr, cma_size);
}
