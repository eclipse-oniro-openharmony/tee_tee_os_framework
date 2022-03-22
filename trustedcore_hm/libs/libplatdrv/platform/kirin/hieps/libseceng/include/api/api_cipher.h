/**
 * @file   : api_cipher.h
 * @brief  : declare of cipher interface
 *           AES/DES/SM4, ECB/CBC/CTR
 * @par    : Copyright (c) 2018-2018, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/18
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __API_CIPHER_H__
#define __API_CIPHER_H__
#include <common_symm.h>

typedef enum {
	API_CIPHER_KEYTYPE_USER_KEY  = 0,
	API_CIPHER_KEYTYPE_CEK_VIDEO = 1,
	API_CIPHER_KEYTYPE_CEK_AUDIO = 2,
	API_CIPHER_KEYTYPE_USER_VIDEO = 3,
	API_CIPHER_KEYTYPE_NUMS,
} api_cipher_keytype_e;

/**
 * @brief      : context for multi-part cipher
 */
typedef struct {
	u32        algorithm;
	u32        direction;
	u32        mode;
	u32        keytype;
	u32        width;
	u8         key[BIT2BYTE(SYMM_WIDTH_256)];
	u8         iv[SYMM_IVLEN_AES];
	u32        blen;
	u8         buf[SYMM_BLKLEN_AES];
} api_cipher_ctx_s;

typedef struct {
	u32        algorithm; /* AES/DES/SM4 */
	u32        direction; /* enc/dec */
	u32        mode;      /* ECB/CBC/CTR */
	u32        keytype;   /* USER/VIDEO/AUDIO */
	u8        *pkey;      /* pointer to key */
	u32        width;     /* 64,128,192,256 */
	u8        *piv;       /* pointer to iv */
	u32        ivlen;     /* byte length of piv */
} api_cipher_init_s;

err_bsp_t api_cipher_init(api_cipher_ctx_s *pctx, const api_cipher_init_s *pcipher_s);

/**
 * @brief      : api_cipher_update
 *               generic update, in/out MUST be in shared DDR(both arc and ap can access)
 *               support AES/DES/SM4, ECB/CBC/CTR
 * @param[in]  : pctx
 *               pointer to user buffer
 * @param[in]  : pdin
 *               pointer to data
 * @param[in]  : dinlen
 *               length in bytes of pdin
 * @param[out] : pdout
 *               pointer to outbuff
 * @param[io]  : pdoutlen
 *               in: inbuf length
 *               out:current outlen
 * @return     : BSP_RET_OK if successful, others if fail
 */
err_bsp_t api_cipher_update(api_cipher_ctx_s *pctx,
		pal_master_addr_t pdin,  u32 dinlen,
		pal_master_addr_t pdout, u32 *pdoutlen);

/**
 * @brief      : api_cipher_update_blocks
 *               video cipher without MMU, in/out MUST be PA(in 512k buffer)
 * @param[in]  : pctx
 *               pointer to context
 * @param[in]  : pdin
 *               MUST be PA
 * @param[in]  : dinlen
 *               multiple of blklen
 * @param[out] : pdout
 *               MUST be PA
 * @param[io]  : pdoutlen
 *               indicates byte lenght of outbuffer
 * @return     : BSP_RET_OK if success, others fail
 */
err_bsp_t api_cipher_update_blocks(api_cipher_ctx_s *pctx,
		pal_master_addr_t pdin,  u32 dinlen,
		pal_master_addr_t pdout, u32 *pdoutlen);

/**
 * @brief      : api_cipher_update_video
 *               cipher for video (MMU is enabled)
 * @param[in]  : pctx
 *               pointer to user buffer
 * @param[in]  : pdin
 *               pointer to indata, MUST be CMA (PA)
 * @param[in]  : dinlen
 *               multiple of blocks
 * @param[out] : pdout
 *               MUST be ION (IOVA)
 * @param[io]  : pdoutlen
 *               in: inbuf length
 *               out:current outlen
 * @return     : BSP_RET_OK if successful, others if fail
 */
err_bsp_t api_cipher_update_video(api_cipher_ctx_s *pctx,
		pal_master_addr_t pdin,  u32 dinlen,
		pal_master_addr_t pdout, u32 *pdoutlen);

/**
 * @brief      : api_cipher_dofinal
 *               for ECB/CBC, is't same to api_cipher_update
 *               for CTR, it can process non-multiple-block data
 * @param[in]  : pctx
 *               pointer to user buffer
 * @param[in]  : pdin
 *               pointer to data, MUST be PA
 * @param[in]  : dinlen
 *               length in bytes of pdin
 * @param[in]  : pdout
 *               pointer to outbuff, MUST be VA(Media SMMU), secure os cant access
 * @param[in]  : pdoutlen
 *               in: outbuflen in bytes
 *               out: real outlen
 * @return     : BSP_RET_OK if successful, others if fail
 */
err_bsp_t api_cipher_dofinal(api_cipher_ctx_s *pctx, pal_master_addr_t pdin, u32 dinlen, pal_master_addr_t pdout, u32 *pdoutlen);

#endif
