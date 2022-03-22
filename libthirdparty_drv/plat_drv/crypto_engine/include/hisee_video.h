/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cdrm video api, provied for user.
 * Author: SecurityEngine
 * Create: 2020/03/06
 */
#ifndef __HISEE_VIDEO_H__
#define __HISEE_VIDEO_H__
#include <common_sce.h>
#include <pal_types.h>

/* video_type */
#define HISEE_VIDEO_TYPE_PATTERN       0xA55A
#define HISEE_VIDEO_TYPE_NOPATTERN     0x5AA5

/*
 * pattern_ration
 * 16byte ciphertext, 144byte plaintext
 */
#define HISEE_VIDEO_PATTERN_RATION_1_9 0xAA55

#define PATTERN_1_9_CIPHERLEN          16
#define PATTERN_1_9_PLAINLEN           144

/* update support maxlen: 512kbytes */
#define HISEE_VIDEO_PATTERN_MAXLEN     (512 * 1024)

#define HISEE_CIPHER_CTX_SIZE_IN_WORDS 64
#define HISEE_VIDEO_CTX_SIZE_IN_WORDS  16

struct hisee_video_ctx {
	u32 cipher_ctx[HISEE_CIPHER_CTX_SIZE_IN_WORDS];
	u32 video_ctx[HISEE_VIDEO_CTX_SIZE_IN_WORDS];
};

struct hisee_video_init_param {
	u32 algorithm;
	u32 direction;
	u32 mode;
	u32 padding_type;
	u32 keytype;
	u32 keylen;
	u32 ivlen;
	const u8  *pkey;
	const u8  *piv;

	u32 video_type;
	u32 pattern_ratio;
	u32 buffer_id;
	u32 size;
	u8  *outva_base;
};

err_bsp_t hisee_video_init(struct hisee_video_ctx *pctx,
			   struct hisee_video_init_param *init_param);
/*
 * decrypt video stream, dinlen MUST be multiple of block size.
 * support AES-CBC-NOPAD/AES-CTR.
 * you need call it after hisee_init/hisee_set_key/hisee_set_iv
 */
err_bsp_t hisee_video_update(struct hisee_video_ctx *pctx,
			     const u8 *pdin, u32 dinlen,
			     u8 *pdout, u32 *pdoutlen);

/*
 * decrypt video stream.
 * for AES-CBC-NOPAD: dinlen MUST be multiple of block size.
 * for AES-CTR: no need of multiple of block size.
 * you call it to finish decryption operation
 */
err_bsp_t hisee_video_dofinal(struct hisee_video_ctx *pctx,
			      const u8 *pdin, u32 dinlen,
			      u8 *pdout, u32 *pdoutlen);

err_bsp_t hisee_video_deinit(struct hisee_video_ctx *pctx);

/* get video type */
u32 hisee_video_get_type(struct hisee_video_ctx *pctx);

#endif

