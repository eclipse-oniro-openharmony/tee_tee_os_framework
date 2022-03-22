/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SaSi_FIPS_RSA_DEFS_H
#define _SaSi_FIPS_RSA_DEFS_H

#include "sasi_rnd.h"
#include "sasi_rsa_types.h"
#include "sasi_rsa_schemes.h"

/* ************************************************************************** */
/*
 * The function runs the conditional test for RSA key generation
 *
 *
 * @param pRndContext - pointer to RND context
 * @param pCcUserPrivKey - pointer to the private key data structure
 * @param pCcUserPubKey  - pointer to the public key data structure
 * @param pFipsCtx  - pointer to RSA fips structure used for conditional test
 *
 * @return SaSiError_t
 */
SaSiError_t SaSi_FipsRsaConditionalTest(SaSi_RND_Context_t *pRndContext, SaSi_RSAUserPrivKey_t *pCcUserPrivKey,
                                        SaSi_RSAUserPubKey_t *pCcUserPubKey, SaSi_RSAKGFipsContext_t *pFipsCtx);

/* ************************************************************************** */
/*
 * The function runs the conditional test for RSA key generation
 *
 *
 * @param pRndContext - pointer to RND context
 * @param pFipsCtx  - pointer to RSA fips structure used for KAT test
 *
 * @return SaSiError_t
 */
CC_FipsError_t SaSi_FipsRsaKat(SaSi_RND_Context_t *rndContext_ptr, SaSi_RSAFipsKatContext_t *pFipsCtx);

#endif // _SaSi_FIPS_RSA_DEFS_H
