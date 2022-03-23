/**
 * @file   : api_rsaes_kem.h
 * @brief  : declare of rsaes_kem
 * @par    : Copyright (c) 2018-2018, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/18
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __API_RSAES_KEM_H__
#define __API_RSAES_KEM_H__
#include <common_rsa.h>
#include <hal_rsa.h>

typedef struct rsaes_kem {
	u32            direction;  /* encryption/decryption */
	hal_rsa_key_s *pkey;       /* pointer to RSA private/public key */
	u32            keklen;     /* byte length of kek */
	u8            *pdin;       /* pointer to data to be decrypted/encrypted */
	u32            dinlen;     /* byte length of pdin */
	u8            *pdout;      /* pointer to out buffer */
	u32           *pdoutlen;   /* indicates byte length of out buffer */
} api_rsaes_kem_s;

err_bsp_t api_rsaes_kem(api_rsaes_kem_s *prsakem_s);

#endif
