/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Library for FBE3
 * Create: 2020/01/11
 */
#ifndef __SEC_FBE3_DERIVE_KEY_H__
#define __SEC_FBE3_DERIVE_KEY_H__

#include <stdint.h>
#include "sre_typedef.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))

#define MAX_KEY_SIZE   512
#define BLOCK_SIZE_MAX 256
#define MAX_ECC_SIZE   256
/* rotate 32-bits word by 16 bits */
#define ROT32(x)      ((x) >> 16 | (x) << 16)
/* inverse the bytes order in a word */
#define REVERSE32(x)  (((ROT32((x)) & 0xff00ff00UL) >> 8) | \
		       ((ROT32((x)) & 0x00ff00ffUL) << 8))

#define EC_PUB_KEY_SIZE (CRYS_ECPKI_MODUL_MAX_LENGTH_IN_WORDS * 8 + 1)

struct aes_info {
	uint8_t *magic;
	uint32_t magic_len;
	uint8_t *nonce;
	uint32_t nonce_len;
	uint8_t *add;
	uint32_t add_len;
	uint8_t *key;
	uint32_t key_len;
	uint8_t *tag;
	uint32_t tag_len;
};

void file_encry_gen_random(uint32_t len, uint8_t *buf);
uint32_t file_encry_config_driver(uint32_t slot, uint8_t *key, uint32_t length);
uint32_t file_encry_keypair_using_hw(uint8_t *pubkey, uint32_t publen,
				     uint8_t *privkey, uint32_t privlen);
uint32_t file_encry_keypair_using_sw(uint8_t *pubkey, uint32_t publen,
				    uint8_t *privkey, uint32_t privlen);
uint32_t file_encry_root_derive_key(uint8_t *secret, uint32_t secret_len,
				    uint8_t *key, uint32_t key_len);
uint32_t file_encry_gen_metadata(uint8_t *pubkey, uint32_t pub_len,
				 uint8_t *privkey, uint32_t priv_len,
				 uint8_t *metadata, uint32_t len);
uint32_t file_encry_do_aes_ccm(uint32_t mode, struct aes_info input);
uint32_t file_encry_calc_hash(const uint8_t *src, uint32_t src_len,
			      uint8_t *dest, uint32_t dest_len);
uint32_t file_encry_do_aes_cbc(uint32_t mode, struct aes_info input);
#endif
