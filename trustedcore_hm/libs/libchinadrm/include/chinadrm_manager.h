/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Crypto API at driver manager.
 * Create: 2020/05/07
 */
#ifndef __CHINADRM_MANAGER_H__
#define __CHINADRM_MANAGER_H__

#include <stdint.h>
#define CDRM_VIDEO_CTX_SIZE_IN_BYTES (80 * 8)
#ifndef BSP_RET_OK
#define BSP_RET_OK                   0x5A5A
#endif

enum cdrm_video_algorithm {
	CDRM_VIDEO_ALGORITHM_AES = 0,
	CDRM_VIDEO_ALGORITHM_SM4 = 1,
};

enum cdrm_video_direction {
	CDRM_VIDEO_DIRECTION_DECRYPT = 0,
	CDRM_VIDEO_DIRECTION_ENCRYPT = 1,
};

enum cdrm_video_mode {
	CDRM_VIDEO_MODE_CBC = 1,
	CDRM_VIDEO_MODE_CTR = 4,
};

enum cdrm_video_padding_type {
	CDRM_VIDEO_PADDING_TYPE_NONE = 0,
};

enum cdrm_video_keytype {
	CDRM_VIDEO_KEYTYPE_USER = 4,
};

enum cdrm_video_keylen {
	CDRM_VIDEO_KEYLEN_16 = 16,
	CDRM_VIDEO_KEYLEN_24 = 24,
	CDRM_VIDEO_KEYLEN_32 = 32,
};

enum cdrm_video_ivlen {
	CDRM_VIDEO_IVLEN_16 = 16,
};

enum cdrm_video_type {
	CDRM_VIDEO_TYPE_PATTERN = 0xA55A,
	CDRM_VIDEO_TYPE_NOPATTERN = 0x5AA5,
};

struct cdrm_hisee_video_init_param {
	uint32_t algorithm;
	uint32_t direction;
	uint32_t mode;
	uint32_t padding_type;
	uint32_t keytype;
	uint32_t keylen;
	uint32_t ivlen;
	const uint8_t  *pkey;
	const uint8_t  *piv;

	uint32_t video_type;
	uint32_t cipher_blk_size; /* ciphered data size must n*16bytes */
	uint32_t plain_blk_size; /* plain data size  must be bigger than cipher blk */
	uint32_t buffer_id;
	uint32_t size;
	uint8_t  *outva_base;
};

int32_t cdrm_hisee_video_init(void *pctx, struct cdrm_hisee_video_init_param *param);

int32_t cdrm_hisee_video_update(void *pctx, const uint8_t *pdin, uint32_t dinlen,
				uint8_t *pdout, uint32_t *pdoutlen);

int32_t cdrm_hisee_video_dofinal(void *pctx, const uint8_t *pdin, uint32_t dinlen,
				 uint8_t *pdout, uint32_t *pdoutlen);

int32_t cdrm_hisee_video_deinit(void *pctx);

#endif
