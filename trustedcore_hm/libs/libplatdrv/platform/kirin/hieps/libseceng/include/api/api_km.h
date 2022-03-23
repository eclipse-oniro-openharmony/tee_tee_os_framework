/**
 * @file   : api_km.h
 * @brief  : declare of km interface
 * @par    : Copyright (c) 2018-2018, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/18
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __API_KM_H__
#define __API_KM_H__
#include <common_symm.h>
#include <hal_rsa.h>

typedef struct cipher_client_prvk {
	u8     key[BIT2BYTE(SYMM_WIDTH_128)];
	u8     iv[SYMM_IVLEN_AES];
	u8    *pdin;
	u32    dinlen;
	u8    *pdout;
	u32   *pdoutlen;
} api_enc_client_privk_s;

err_bsp_t api_encrypt_client_privk(api_enc_client_privk_s *pprivk);

err_bsp_t api_decrypt_rsastd_key(const hal_rsa_key_s *pkeyin, hal_rsa_key_s *pkeyout);

err_bsp_t api_decrypt_rsacrt_key(const hal_rsa_crtkey_s *pkeyin, hal_rsa_crtkey_s *pkeyout);

err_bsp_t api_decrypt_licence_hmack(hal_rsa_key_s *pkey, u8 *pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);

err_bsp_t api_decrypt_session_key(hal_rsa_key_s *pkey, u8 *pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);

err_bsp_t api_decrypt_cek(u8 *pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);

u8 *api_get_licence_hmac_key(u32 *keylen);

u8 *api_get_cek(u32 *width);

err_bsp_t api_store_cek_hook(u8 aobuf[BIT2BYTE(SYMM_WIDTH_256)]);

err_bsp_t api_restore_cek_hook(const u8 aobuf[BIT2BYTE(SYMM_WIDTH_256)]);
#endif
