/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: declare of km api(parallel with dx)
 * Author     : l00370476
 * Create     : 2018/12/28
 */

#ifndef __ADAPT_KM_H__
#define __ADAPT_KM_H__

#include "cc_rsa_kg.h"
#include <api_km.h>

typedef api_enc_client_privk_s EPSEncPrivK_t;

CCError_t EPS_EncryptClientPrivK(EPSEncPrivK_t *pprivk);

CCError_t EPS_DecryptLicenceHmacK(CCRsaUserPrivKey_t *pkey, uint8_t *pdin, uint32_t dinlen, uint8_t *pdout,
				  uint32_t *pdoutlen);

CCError_t EPS_DecryptSessionKey(CCRsaUserPrivKey_t *pkey, uint8_t *pdin, uint32_t dinlen, uint8_t *pdout,
				uint32_t *pdoutlen);

CCError_t EPS_DecryptCek(uint8_t *pdin, uint32_t dinlen, uint8_t *pdout, uint32_t *pdoutlen);

#endif

