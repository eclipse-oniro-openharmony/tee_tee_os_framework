/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SaSi_FIPS_ECC_DEFS_H
#define _SaSi_FIPS_ECC_DEFS_H

#include "sasi_rnd.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_ecdsa.h"

SaSiError_t SaSi_FipsEccConditionalTest(SaSi_RND_Context_t *pRndContext, SaSi_ECPKI_UserPrivKey_t *pUserPrivKey,
                                        SaSi_ECPKI_UserPublKey_t *pUserPublKey, SaSi_ECPKI_KG_FipsContext_t *pFipsCtx);

CC_FipsError_t SaSi_FipsEcdsaKat(SaSi_RND_Context_t *pRndContext, SaSi_ECDSAFipsKatContext_t *pFipsCtx);

CC_FipsError_t SaSi_FipsEcdhKat(SaSi_ECDHFipsKatContext_t *pFipsCtx);

#endif // _SaSi_FIPS_ECC_DEFS_H
