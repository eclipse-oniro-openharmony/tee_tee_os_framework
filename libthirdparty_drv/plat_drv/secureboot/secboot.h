/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
 * Description: some defination for secboot, should checked by REE
 * and modem at the same time when modify
 * Create: 2013/5/16
 */

#ifndef __SECBOOT_H__
#define __SECBOOT_H__
#include "hisi_secboot.h"
#include "hisi_seclock.h"
#include "hisi_secureboot.h"
#include "tee_log.h"
#include "mem_page_ops.h" /* paddr_t */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * enum in these files shold be changed at the same time
 * mbb tzdriver
 * vendor/hisi/system/kernel-4.14/drivers/hisi/tzdriver_hm/teek_client_id.h
 * mbb secos
 * vendor/hisi/system/secure_os/trustedcore_hm/prebuild/hm-teeos-release/ \
 *       headers/hm/TEE/tee_common.h(enum deled)
 * vendor/hisi/system/secure_os/trustedcore_hm/libs/libplatdrv/platform/ \
 *       balong/include/bsp_param_cfg.h
 * mbb phone:ccore modem
 * vendor/hisi/modem/drv/acore/bootable/bootloader/legacy/modem/include/ \
 *       param_cfg_to_sec.h
 * vendor/hisi/modem/drv/acore/kernel/drivers/hisi/modem/drv/include/ \
 *       param_cfg_to_sec.h
 * vendor/hisi/modem/drv/ccore/include/fusion/param_cfg_to_sec.h
 * vendor/hisi/modem/drv/ccore/include/ccpu/param_cfg_to_sec.h
 * vendor/hisi/modem/drv/fastboot/include/param_cfg_to_sec.h
 * phone tzdriver
 * vendor/hisi/ap/kernel/drivers/tzdriver/teek_client_id.h
 * phone secos
 * vendor/thirdparty/secure_os/trustedcore_hm/prebuild/hm-teeos-release/ \
 *       headers/hm/TEE/tee_common.h(enum deled)
 * vendor/thirdparty/secure_os/trustedcore_hm/libs/libplatdrv/platform/ \
 *       kirin/secureboot/secboot.h
 */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660 ||        \
	 TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 ||    \
	 TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6250 ||    \
	 TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW ||   \
	 TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)

enum SVC_SECBOOT_IMG_TYPE {
	MODEM,
	HIFI,
	DSP,
	XDSP,
	TAS,
	WAS,
	CAS,
	MODEM_DTB,
	ISP,
#ifdef CONFIG_COLD_PATCH
	MODEM_COLD_PATCH,
	DSP_COLD_PATCH,
#endif
#ifdef CONFIG_RFIC_LOAD
	RFIC,
#endif
	MAX_SOC,
	MAX_SOC_MODEM = MAX_SOC
};
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE ||   \
	   TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER || \
	   TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_CHARLOTTE || \
	   TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BURBANK || \
	   TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_LAGUNA)
enum SVC_SECBOOT_IMG_TYPE {
	HIFI,
	ISP,
	IVP,
	MAX_AP_SOC,
	MODEM_START = 0x100,
	MODEM_END = 0x1FF,
	MAX_SOC,
};
#else
enum SVC_SECBOOT_IMG_TYPE {
	MODEM,
	DSP,
	XDSP,
	TAS,
	WAS,
	MODEM_COMM_IMG,
	MODEM_DTB,
	NVM,
	NVM_S,
	MBN_R,
	MBN_A,
	MODEM_COLD_PATCH,
	DSP_COLD_PATCH,
	MODEM_CERT,
	MAX_SOC_MODEM,
	HIFI,
	ISP,
	IVP,
	MAX_SOC
};
#endif

enum secboot_proc_type {
	INIT_PROC_TYPE,
	FAIL_PROC_TYPE,
	SUCC_PROC_TYPE,
	MAX_PROC_TYPE
};

struct secboot_info {
	UINT64 ddr_phy_addr;
	UINT64 ddr_virt_addr;
	UINT64 image_addr;
	UINT32 ddr_size;
	UINT32 unreset_dependcore;
	UINT32 image_size;
};

#if defined(CONFIG_MODEM_ASLR) || defined(CONFIG_MODEM_BALONG_ASLR)
struct aslr_sec_param {
	u32 image_offset;
	u32 stack_guard;
	u32 heap_offset;
};

#define MODEM_IMAGE_OFFSET          0x40
#define MODEM_STACK_GUARD_OFFSET    0x44
#define MODEM_MEM_PT_OFFSET         0x48
#define MODEM_REL_COPY_CODE_SIZE    (64 * 1024)
#endif

struct secboot_modem_cold_patch_info_s {
	u32 soc_type;
	UINT32 ccore_vir_addr;
	UINT32 ccore_offset;
	UINT32 dsp_vir_addr;
	UINT32 dsp_offset;
};

extern struct secboot_info g_image_info[];

#define IMAGE_ADDR_INVALID_VALUE        0xFFFFFFFF

#define SECBOOT_GRPIMG_MAXNUM           10
#define SECBOOT_IMGNAME_MAXLEN          36
#define SECBOOT_VRL_SIZE                0x1000

#define SECBOOT_VRL_BURNCHK_N           0x0
#define SECBOOT_VRL_BURNCHK_Y           0x1
#define SECBOOT_VRL_BOOTMODE_EMMC       0x0
#define SECBOOT_VRL_BOOTMODE_RAM        0x1

#define SECBOOT_OTP_CPU_DW_SIZE         1

#define SECBOOT_OTP_VER_SEC1_START      24
#define SECBOOT_OTP_VER_SEC1_LEN        1
#define SECBOOT_OTP_VER_SEC1_NUM        31

#define SECBOOT_OTP_VER_SEC2_START      61
#define SECBOOT_OTP_VER_SEC2_LEN        1
#define SECBOOT_OTP_VER_SEC2_NUM        31

#define SECBOOT_OTP_VER_UNSEC_START     25
#define SECBOOT_OTP_VER_UNSEC_LEN       7
#define SECBOOT_OTP_VER_UNSEC_NUM       223

#define SECBOOT_IMGGRPID_NONE           0x0
#define SECBOOT_IMGGRPID_SEC1UPD        0x01
#define SECBOOT_IMGGRPID_SEC2UPD        0x02
#define SECBOOT_IMGGRPID_UNSECUPD       0x04
#define SECBOOT_IMGGRPID_SEC1CHK        0x08
#define SECBOOT_IMGGRPID_SEC2CHK        0x10
#define SECBOOT_IMGGRPID_UNSECCHK       0x20
#define SECBOOT_IMGGRPID_PRELOAD        0x40
#define SECBOOT_IMGGRPID_BOOTUP         0x80
#define ALIGNED_64BYTE_VALUE(value) ((((value) + 63) / 64) * 64)

#define PROVISON_SIZE_IN_BYTES 16
#define DIEID_SIZE_IN_BYTES    20
#define HASH_SIZE_IN_WORDS     8

#define BITS32                 32
#ifndef UNUSED
#define UNUSED(x)              ((void)(x))
#endif

/* extern function from tee os */
extern void *malloc_coherent(size_t n);
extern void v7_flush_kern_cache_all(void);

INT32 secboot_get_secinfo(void);
INT32 secboot_dma_init(void);
UINT32 secboot_get_image_info_addr(struct secboot_info **image_info,
				   UINT32 *size);

UINT32 secboot_imageverification(struct seb_cert_pkg *seb_certpkg,
				 const char *imagenameptr, BOOL besecure,
				 BOOL beram, BOOL beburning);
UINT32 secboot_check_adddata(struct seb_cert_pkg *seb_certpkg,
			     const char *imagenameptr,
			     struct vrl_additiondata *additiondataptr,
			     UINT32 isprimvrl);
UINT32 secboot_getdevicecarrierid(UINT32 *carrieridptr);
UINT32 secboot_getseccfg(enum secboot_seccfg *seccfgptr);
UINT32 secboot_changecompstoreaddr(struct seb_cert_pkg *seb_certpkg,
				   paddr_t storeaddress);
UINT32 seb_parservrl(UINT32 vrladdress, UINT32 *img_size);
UINT32 secboot_get_secinfo_dieid(UINT32 *pdieid, UINT32 len);
UINT32 secboot_get_fbe2_flag(UINT8 *fbe2_flag);
UINT32 eiius_get_workspace_info(UINT64 *eiius_addr, UINT32 *eiius_size);
UINT32 process_map_addr(UINT32 soc_type, UINT32 *map_addr, UINT32 *cma_size);
void process_clean_addr(UINT32 map_addr, UINT32 cma_size);
UINT32 get_cma_size(UINT32 soc_type);
UINT32 get_base_addr(UINT32 soc_type);
UINT32 secboot_get_soc_name(UINT32 soc_type, UINT8 *imagenameptr, UINT32 len);
UINT32 secboot_splicing_img(enum SVC_SECBOOT_IMG_TYPE old_img_type,
			    UINT32 inflate_img_offset,
			    UINT32 decompress_img_size);
struct aslr_sec_param *hisi_secboot_get_aslr_sec_param_st(void);
UINT32 hisi_secboot_is_modem_img(UINT32 soc_type);
UINT32 secboot_soc_verification(UINT32 vrladdress, paddr_t imageaddress,
				const char *imagenameptr, UINT32 isprimvrl,
				SECBOOT_LOCKSTATE lock_state);
UINT32 hisi_secboot_verify_modem_imgs(UINT32 soc_type, UINT32 vrladdress,
				      UINT32 core_id,
				      SECBOOT_LOCKSTATE lock_state);
#ifdef __cplusplus
}
#endif

#endif
