/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2018. All rights reserved.
 * Description: tee securemem test
 * Create: 2017
 */

#ifndef __SECUREMEM_H
#define __SECUREMEM_H

#define SECBOOT_CMD_ID_MEM_ALLOCATE 0x1

#define MEDIADRMSERVER_NAME "/system/bin/mediadrmserver"
#define MEDIA_UID 1013

#define MEDIASERVER_NAME "/system/bin/mediaserver"
#define MEDIA_UID 1013

#define SAMPLE_OMXVDEC_NAME "/vendor/bin/sample_omxvdec"
#define ROOT_UID 0

#define SECMEM_TEST_UID 2000
#define MEDIA_CODEC_UID 1046
#define SYSTEM_SERVER_UID 1000

enum ion_ta_tag {
	ION_SEC_CMD_PGATBLE_INIT = 0,
	ION_SEC_CMD_ALLOC,
	ION_SEC_CMD_FREE,
	ION_SEC_CMD_MAP_IOMMU,
	ION_SEC_CMD_UNMAP_IOMMU,
	ION_SEC_CMD_MAP_USER,
	ION_SEC_CMD_UNMAP_USER,
	ION_SEC_CMD_TABLE_SET,
	ION_SEC_CMD_TABLE_CLEAN,
	ION_SEC_CMD_VLTMM,
#ifdef SECMEM_UT
	ION_SEC_CMD_TEST,
	ION_SEC_CMD_TEST_RECY,
#endif
	ION_SEC_CMD_MAX,
};

/* sec_feature same as fastboot */
enum SEC_FEATURE {
/* sub region feature */
	DDR_SEC_TINY = 1,
	DDR_SEC_TUI = 2,
	DDR_SEC_EID = 5,

/*
 * mixed feature
 * include 2D_FACE, 3D_FACE_ISP(64M), 3D_FACE_CAMERA(108M),
 * 3D_FACE_ALGO(NORMAL_RGN)
 */
	DDR_SEC_FACE = 0x10,

/* normal region feature */
	DDR_SEC_PGTABLE = 0x20,
	DDR_SEC_HIFI_RESET = 0x21,

/* mpu protect */
	DDR_DRM_PRO = 0x40,

/* to be deleted */
	DDR_SEC_SION,
	DDR_SEC_MAX,
};

enum DDR_CFG_TYPE {
	DDR_SET_SEC,
	DDR_UNSET_SEC,
	DDR_CHECK_SEC,
	DDR_CHECK_UNSEC, /* use internally */
};

struct mem_chunk_list {
	unsigned int protect_id;
	union {
		unsigned int nents;
		unsigned int buff_id;
	};
	unsigned int va;
	void *buffer_addr; /* Must be the start addr of struct tz_pageinfo */
	unsigned int size;
	unsigned int cache;
	int prot;
	int mode;
	unsigned int smmuid;
	unsigned int sid;
	unsigned int ssid;
};

enum {
	SUB_CMD_FREE,
	SUB_CMD_DUMP,
	SUB_CMD_UT_MALLOC,
	SUB_CMD_UT_FREE,
	SUB_CMD_UT_SHAREMEM,
	SUB_CMD_UT_PERF,     /* malloc N timer, then all free */
	SUB_CMD_UT_PERF_EXT, /* malloc-free N times*/
};
#define SHRINKER_MAX   8

#define VLTMM_TEST_256M   0x10000000
#define VLTMM_TEST_MACCNT 128
#define VLTMM_TEST_PRINTCNT 10

#endif
