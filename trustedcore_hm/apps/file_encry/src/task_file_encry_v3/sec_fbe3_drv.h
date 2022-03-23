/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Library for FBE3
 * Create: 2020/01/07
 */
#ifndef __SEC_FBE3_DRV_H__
#define __SEC_FBE3_DRV_H__

#include "sre_typedef.h"
#include "crys_ecpki_types.h"
#include "sec_fbe3_interface.h"
#include "sec_fbe3_derive_key.h"

#define MAIN_USER_ID     0
#define WORDS_LEN        4
#define MAX_USER_NUM     10
#define MAX_SECE_NUM     MAX_USER_NUM
#define AES_KEY_LEN      32
#define AES_IV_LEN       32
#define AES_NONCE_LEN    8
#define AES_ADD_LEN      8
#define AES_TAG_LEN      8
#define AES_KEK_LEN      (AES_KEY_LEN + AES_NONCE_LEN + AES_ADD_LEN)
#define MAGIC_LEN        16 /* magic num len to MSP */
#define MATA_LEN         16 /* metadata len = 128bits */
#define KEY_LEN          64 /* key len = 521bits */
#define INVALID_ID       0xffff
#define IV_MAGIC0        0xfb
#define IV_MAGIC1        0x30
#define SECE_READY       0x6c6c
#define FBEX_FILE_LEN    0x8
#define FBEX_CKEY_ONLY   0xA5
#define FBEX_FILE_MASK   0xFF
#define FBEX_IV_UPDATE   0x6C
#define CHIPID_ASIC_ES   0x0
#define CHIPID_ASIC_CS   0x1
#define MSP_CHECKED      0x5A
#define MSP_CHECKING     0x55
#define MSP_ONLINE       0x78
#define MSP_OFFLINE      0x87
#define HASH_VERIFY      0xA5
#define USER_LOGOUT      0xA6
#define USER_LOCK        0xA9
#define U16_SHIFT        16

#ifdef FILE_ENCRY_P384_USING
#define FILE_ECDH_DOMAIN CRYS_ECPKI_DomainID_secp384r1
#define ECDH_KEY_LEN     0x30 /* 0x20 for p256; 0x30 for p384*/
#define PUB_KEY_LEN      0x61 /* 0x41 for p256; 0x61 for p384*/
#define PRIV_KEY_LEN     0x30 /* 0x20 for p256; 0x30 for p384*/
#else
#define FILE_ECDH_DOMAIN CRYS_ECPKI_DomainID_secp256r1
#define ECDH_KEY_LEN     0x20 /* 0x20 for p256; 0x30 for p384*/
#define PUB_KEY_LEN      0x41 /* 0x41 for p256; 0x61 for p384*/
#define PRIV_KEY_LEN     0x20 /* 0x20 for p256; 0x30 for p384*/
#endif

#define HASH_LEN         0x20 /* HASH length for SHA256 */

#define MAX_KEY_NUM_SUPPORT    32
#define MAX_KEY_NUM            32
#define MAX_PRIVKEY_NUM        16
/* Note: the handle to FBE driver is grouped as 32 */
#define MAX_KEY_IDX            (MAX_KEY_NUM + MAX_KEY_NUM)  /* 64 */
#define MAX_CKEY_IDX           (MAX_KEY_IDX + MAX_KEY_NUM)  /* 96 */
#define MAX_KEK_READ           (MAX_CKEY_IDX + MAX_KEY_NUM) /* 128 */
#define MAX_KEK_WRITE          (MAX_KEK_READ + MAX_KEY_NUM) /* 160 */
/* privkey handle ID, split 32 as 16 + 16 */
#define MAX_SECE_WRITE         (MAX_KEK_WRITE + MAX_PRIVKEY_NUM) /* 160 + 16 */
#define MAX_SECE_READ          (MAX_SECE_WRITE + MAX_PRIVKEY_NUM) /* 176 + 16 */
/* privkey clean ID, split 32 as 16 + 16 */
#define MAX_SECE_CLEAN         (MAX_SECE_READ + MAX_PRIVKEY_NUM) /* 192 + 16 */
#define MAX_SECE_NOUSE         (MAX_SECE_CLEAN + MAX_PRIVKEY_NUM) /* no use */

#define FILE_ENCRY_ENABLE_KDF  0x6C01
#define FILE_ENCRY_UFS_READ    0x6C02
#define FILE_ENCRY_CHIPID_READ 0x6C03

/* ufs config ID: [32, 64) */
#define idx_to_ufs_slot(idx)   (idx + MAX_KEY_NUM)
/* ckey read ID: [64, 96) */
#define idx_to_ckey_read(idx)  (idx + MAX_KEY_IDX)
/* iv read ID: [96, 128) */
#define idx_to_iv_read(idx)    (idx + MAX_CKEY_IDX)
/* iv write ID: [128, 160) */
#define idx_to_iv_write(idx)   (idx + MAX_KEK_READ)
/* privkey handle ID: [160, 192) */
#define idx_to_priv_write(idx) (idx + MAX_KEK_WRITE)
#define idx_to_priv_read(idx)  (idx + MAX_SECE_WRITE)
/* privkey handle ID: [192, 224) */
#define idx_to_priv_clean(idx) (idx + MAX_SECE_READ)

/* do not change the enum value */
enum SECE_KEY_STATUS {
	SECE_KEY_NONE = 0x0,
	SECE_KEY_AVAILABLE = 0x10,
	SECE_KEY_SUSPEND = 0x20,
	SECE_KEY_LOGOUT = 0x40,
};

enum UFS_SLOT_STATUS {
	UFS_KEY_NONE = 0,
	UFS_KEY_USING = 0x1,
	UFS_KEY_SUSPEND = 0x2,
	UFS_KEY_LOGOUT = 0x4,
};

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

struct sece_info {
	uint32_t user;
	uint32_t ufs_slot;  /* UFSC slot id, used as index */
	uint32_t avail; /* key: available or not, see enum SECE_KEY_STATUS */
	uint8_t pubkey[PUB_KEY_LEN]; /* SECE create: pubkey */
	uint8_t privkey[PRIV_KEY_LEN]; /* SECE create: privkey */
#ifdef FILE_ENCRY_KEY_HASH_ENABLE
	uint8_t privkey_hash[HASH_LEN]; /* privkey hash value */
#endif
};

struct aes_ccm {
	uint8_t iv[AES_IV_LEN];
	uint8_t tag[AES_TAG_LEN];
};

uint32_t file_encry_reset_keys(void);
uint32_t file_encry_restore_iv(void);
uint32_t file_encry_enable_kdf_ta(void);
uint32_t file_encry_rpmb_times(void);
bool file_encry_msp_available(void);
uint32_t file_encry_lock_screen(uint32_t user, uint32_t file);
uint32_t file_encry_prefetch_key(uint32_t user);
uint32_t file_encry_user_logout(uint32_t user, uint32_t file,
				uint8_t *iv_buf, uint32_t length);
uint32_t file_encry_unlock_screen(uint32_t user, uint32_t file,
				  uint8_t *iv_buf, uint32_t length);
uint32_t file_encry_add_key(uint32_t user, uint32_t file,
			    uint8_t *iv_buf, uint32_t length);
uint32_t file_encry_delete_key(uint32_t user, uint32_t file,
			       uint8_t *iv_buf, uint32_t length);
uint32_t file_encry_new_sece(uint32_t index, uint8_t *pubkey, uint32_t key_len,
			     uint8_t *metadata, uint32_t iv_len);
uint32_t file_encry_open_sece(uint32_t index, uint8_t *pubkey, uint32_t key_len,
			      uint8_t *metadata, uint32_t iv_len);
#ifdef FILE_ENCRY_USING_RPMB
uint32_t file_encry_derive_rpmb_kek(uint32_t user_id, uint32_t file, uint8_t *kek,
			uint32_t kek_len, struct aes_info *info);
#else
static inline uint32_t file_encry_derive_rpmb_kek(uint32_t user_id __unused,
			uint32_t file __unused, uint8_t *kek __unused,
			uint32_t kek_len __unused, struct aes_info *info __unused)
			{return 0;}
#endif
#endif
