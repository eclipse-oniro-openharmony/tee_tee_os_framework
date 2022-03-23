/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
 * Description: defination of ERR CODE/struct/function for secboot
 * Create: 2013/5/16
 */

#ifndef __HISI_SECUREBOOT_H__
#define __HISI_SECUREBOOT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sre_typedef.h>

#define SECBOOT_RET_SUCCESS                         0
#define SECBOOT_RET_CONTINUE                        0xFFFFFF00
#define SECBOOT_RET_VRL_INVALID                     0xFFFFFF01
#define SECBOOT_RET_PARAM_ERROR                     0xFFFFFF02
#define SECBOOT_RET_FAILURE                         0xFFFFFFFF

#define SECBOOT_RET_MODEM_IS_UNRESET                0xFFFFFF10
#define SECBOOT_RET_INVALIED_SOC_TYPE               0xFFFFFF11
#define SECBOOT_RET_INVALIED_PHY_ADDR               0xFFFFFF12
#define SECBOOT_RET_INVALIED_OFFSET_OR_LEN          0xFFFFFF13
#define SECBOOT_RET_SRC_MAP_FAILED                  0xFFFFFF14
#define SECBOOT_RET_DEPENDCORE_NOT_READY            0xFFFFFF15
#define SECBOOT_RET_INVALIED_MODEM_INFO_BASE        0xFFFFFF16
#define SECBOOT_RET_INVALIED_MODEM_INFLATE          0xFFFFFF17
#define SECBOOT_RET_INVALIED_ADDR_CHECK             0xFFFFFF18
#define SECBOOT_RET_INVALIED_ADDR_MAP               0xFFFFFF19
#define SECBOOT_RET_INVALIED_PROCESS_TYPE           0xFFFFFF1A
#define SECBOOT_RET_INVALIED_CMA_ADDR               0xFFFFFF1B
#define SECBOOT_RET_HIFI_MAP_FAIL                   0xFFFFFF1C
#define SECBOOT_RET_HIFI_PRE_CHECK_FAIL             0xFFFFFF1D
#define SECBOOT_RET_HIFI_LOAD_CHECK_FAIL            0xFFFFFF1E
#define SECBOOT_RET_HIFI_ADDR_MAP_FAIL              0xFFFFFF1F
#define SECBOOT_RET_HIFI_SEC_HEAD_DIRTY             0xFFFFFF20
#define SECBOOT_RET_COLD_PATCH_SPLICING_FAIL        0xFFFFFF22
#define SECBOOT_RET_HIFI_NOT_POWER_ON               0xFFFFFF23
#define SECBOOT_RET_ASLR_RND_FAIL                   0xFFFFFF24
#define SECBOOT_RET_MODEM_CMD_TYPE_NOT_SUPPORT      0xFFFFFF25
#define SECBOOT_RET_INVALIED_MODEM_CORE_ID          0xFFFFFF26
#define SECBOOT_RET_MODEM_SPLICING_PARAM_INVALID    0xFFFFFF27
#define SECBOOT_RET_MODEM_NOT_REGISTERED            0xFFFFFF28
#define SECBOOT_RET_MODEM_COPY_FAILED               0xFFFFFF29
#define SECBOOT_RET_MODEM_REGISTER_FAIL             0xFFFFFF2A
#define SECBOOT_RET_MODEM_VERIFY_FAILED             0xFFFFFF2B
#define SECBOOT_INVALID_VALUE                       0xFFFFFFFF
#define SECBOOT_ILLEGAL_BASE_ADDR                   0xFFFFFFFF

#define SECBOOT_SPLICING_RET_BASE_ADDR              0xAAAAAA00

#define SECBOOT_USE_DEFAULT_MAGICNUM                0
#define SECBOOT_ILLEGAL_CMA_SIZE                    0U
#define IS_MODEM_IMG                                1
#define VRL_MAGIC_NUMBER_DEFAULT_VALUE              0xE59FF052

#define SECBOOT_PART_NAMELEN                        32

enum secboot_seccfg {
	SECBOOT_SECCFG_SECURE = 0,
	SECBOOT_SECCFG_INTEGRITY = 1,
	SECBOOT_SECCFG_NONE = 2,
	SECBOOT_SECCFG_ERROR = 3,
};

struct secboot_vrlinfo {
	UINT32 have_vrl;
	UINT32 vrl_buf[0x800]; /* 0x800 int for vrlinfo */
};

/* Hold system when verification error. */
typedef void (*HOLD_SYSTEM)(void);

/* Copy the provision key to secure os. */
typedef UINT32 (*COPY_PROVKEY)(void);

/* Clean provision key. */
typedef void (*CLEAN_PROVKEY)(void);

/* Check the basic partition is ok or not. */
typedef UINT32 (*CHECK_BASEPTN)(void);

/* Get the system secure configuration, for example: lcs, lock status... */
typedef UINT32 (*GET_SECINFO)(char *secinfo);

/* Get the current Lcs. */
typedef UINT32 (*GET_SECCFG)(enum secboot_seccfg *seccfgptr);

/* Used to backup and/or restore the secure data. */
typedef UINT32 (*BACKANDRESTORE)(UINT32 srcaddress, UINT32 dstaddress,
				 UINT32 blocksize, UINT32 issrambackup);

/* Update the bootloader secure version number. */
typedef UINT32 (*UPDATE_FBVERSION)(UINT32 magicnumber);

/* Used to verify the images that have been load to RAM. */
typedef UINT32 (*PRELOAD_VERIFICATION)(UINT32 imageaddress,
				       const char *imagenameptr,
				       UINT32 magicnumber);

/*
 * Used to verify the images that cannot load to RAM
 * and must verify through EMMC.
 */
typedef UINT32 (*BOOTUP_VERIFICATION)(UINT32 imageaddress,
				      const char *imagenameptr,
				      UINT32 magicnumber);

/*
 * This used to process the images that have already load to specify address,
 * verify it and return the result with information if it has VRL and its
 * VRL data in SECBOOT_VRLINFO.
 */
typedef UINT32 (*DOWNLOAD_VERIFICATION)(UINT32 *imageaddressptr,
					UINT32 *imagelengthptr,
					const char *imagenameptr,
					UINT32 magicnumber,
					struct secboot_vrlinfo *vrlinfo);

/*
 * Write VRL to specified position due to isPrimVRL
 * (True for primary VRL, and False for backup VRL.).
 */
typedef UINT32 (*WRITE_VRL)(UINT32 vrladdress, const char *imagenameptr,
			    UINT32 isprimvrl);

/* Additional data structure(Total 128 bytes) */
struct vrl_additiondata {
	UINT32 oem_id; /* OemID */
	UINT32 hwid; /* HwID */
	UINT32 burncheckflag; /* Programing check Flag */
	UINT32 bootmodeflag; /* Boot check mode Flag */
	UINT64 additionbitmap; /* AdditionBitMap */
	UINT32 sec2curver; /* second software version */
	UINT8 partitionname[SECBOOT_PART_NAMELEN]; /* partition name */
	UINT8 reservedone[32]; /* reserved 32 for historical reason */
	UINT8 verifyflag; /* reserved for verify flag */
	/*
	 * reserved for Version to distinguish enginering
	 * version and release version
	 */
	UINT8 version;
	/*
	 * platform information to distinguish different
	 * chip platform, use 16bits for 4-bytes aligned
	 */
	UINT16 platinfo;
	UINT8 reserved[64 - SECBOOT_PART_NAMELEN]; /* (64 - 32)reserved */
};

struct secboot_operators {
	HOLD_SYSTEM hold_system;
	COPY_PROVKEY copy_provkey;
	CLEAN_PROVKEY clean_provkey;
	CHECK_BASEPTN check_baseptn;
	GET_SECINFO get_secinfo;
	GET_SECCFG get_seccfg;
	BACKANDRESTORE backandrestore;
	UPDATE_FBVERSION update_fbversion;
	WRITE_VRL write_vrl;
	PRELOAD_VERIFICATION preload_verification;
	BOOTUP_VERIFICATION bootup_verification;
	DOWNLOAD_VERIFICATION download_verification;
};

#ifdef __cplusplus
}
#endif

#endif
