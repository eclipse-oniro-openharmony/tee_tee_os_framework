/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: FBE3 driver code
 * Create: 2020/02/27
 */

#ifndef _SEC_FBE3_KM_H_
#define _SEC_FBE3_KM_H_

#include <stdint.h>

#define __unused __attribute__((unused))

#define AES_IV_LEN       32
#define AES_TAG_LEN      8
#define MAGIC_LEN        16
#define KEY_LEN          64
#define KEK_LEN          64
#define MAX_KEY_NUM      32
#define MAX_PRIVKEY_NUM  16
/* ufs config ID: [32, 64) */
#define MAX_KEY_IDX      (MAX_KEY_NUM + MAX_KEY_NUM)
/* ckey read ID: [64, 96) */
#define MAX_CKEY_IDX     (MAX_KEY_IDX + MAX_KEY_NUM)
/* IV read ID: [96, 128) */
#define MAX_IV_READ      (MAX_CKEY_IDX + MAX_KEY_NUM)
/* IV write ID: [128, 160) */
#define MAX_IV_WRITE     (MAX_IV_READ + MAX_KEY_NUM)
/* privkey handle ID, split 32 as 16 + 16 */
#define MAX_SECE_WRITE   (MAX_IV_WRITE + MAX_PRIVKEY_NUM) /* 160 + 16 */
#define MAX_SECE_READ    (MAX_SECE_WRITE + MAX_PRIVKEY_NUM) /* 176 + 16 */
/* privkey clean ID, split 32 as 16 + 16 */
#define MAX_SECE_CLEAN   (MAX_SECE_READ + MAX_PRIVKEY_NUM) /* 192 + 16 */
#define MAX_SECE_NOUSE    (MAX_SECE_CLEAN + MAX_PRIVKEY_NUM) /* no use */

#define CHIPID_MASK      0xF000
#define CHIPID_SHIFT     12

#ifdef FILE_ENCRY_P384_USING
#define PUB_KEY_LEN      0x61 /* 0x41 for p256; 0x61 for p384*/
#define PRIV_KEY_LEN     0x30 /* 0x20 for p256; 0x30 for p384*/
#else
#define PUB_KEY_LEN      0x41 /* 0x41 for p256; 0x61 for p384*/
#define PRIV_KEY_LEN     0x20 /* 0x20 for p256; 0x30 for p384*/
#endif

#ifdef FILE_ENCRY_KEY_HASH_ENABLE
#define HASH_LEN         0x20 /* HASH length for SHA256 */
#endif

#define FILE_ENCRY_ENABLE_KDF       0x6C01
#define FILE_ENCRY_UFS_READ         0x6C02
#define FILE_ENCRY_CHIPID_READ      0x6C03
#define FILE_ENXRY_DRIVER_MAX_ID    0xA

/* 0xFBE0001XX: Error number from FBE3 driver */
#define FILE_ENCRY_INIT_FAIL        0xFBE00101
#define FILE_ENCRY_LOCK_FAIL        0xFBE00102
#define FILE_ENCRY_MEMSET_FAIL      0xFBE00103
#define FILE_ENCRY_INDEX_INVALID    0xFBE00104
#define FILE_ENCRY_BUFF_INVALID     0xFBE00105
#define FILE_ENCRY_MEMCPY_FAIL      0xFBE00106
#define FILE_ENCRY_CLEAN_PRIVKEY    0xFBE00107

/* Note: the handle to FBE driver is grouped as 32 */
#define id_to_index(id)       (id >> 5) /* index == (id / 32) */
#define id_to_err_num(id)     (id << 12) /* 0xFBE(id)1XX */

#define CALLBACK_FN(num, name) [num] = file_encry_##name,
typedef uint32_t (*file_encry_cb)(uint32_t id, uint8_t *buf, uint32_t len);

/*
 * the index 0x0 to 0xA is actually from (0x0 to 0xA) * 32
 * we used id_to_index(idx) to evaluate it to 0x0 to 0xA
 */
#define FILE_ENCRY_CB_LIST \
	CALLBACK_FN(0x00, config_ufsc) \
	CALLBACK_FN(0x01, ufs_config)  \
	CALLBACK_FN(0x02, ckey_read)   \
	CALLBACK_FN(0x03, iv_read)     \
	CALLBACK_FN(0x04, iv_write)    \
	CALLBACK_FN(0x05, privkey_handle)   \
	CALLBACK_FN(0x06, privkey_clean)   \
	CALLBACK_FN(0x07, undefined)   \
	CALLBACK_FN(0x08, undefined)   \
	CALLBACK_FN(0x09, undefined)   \
	CALLBACK_FN(0x0A, undefined)

struct ufs_info {
	uint32_t user; /* user id */
	uint32_t file; /* A/B/C/D */
	uint32_t status; /* UFS slot status, see enum UFS_SLOT_STATUS */
	uint8_t iv_value[KEY_LEN]; /* unlock screen, decry ECE key */
	uint8_t ckey[KEY_LEN]; /* unlock screen, recover ckey */
#ifdef FILE_ENCRY_KEY_HASH_ENABLE
	uint8_t ckey_hash[HASH_LEN]; /* ckey hash value */
#endif
};

struct aes_ccm {
	uint8_t magic[AES_IV_LEN];
	uint8_t tag[AES_TAG_LEN];
};

struct privkey_info {
	uint8_t privkey[KEY_LEN];
	struct aes_ccm tag_iv;
};

#endif
