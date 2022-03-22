/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_ECPKI_KG_H
#define SaSi_ECPKI_KG_H

/* ! @file
@brief Defines the API for generation of ECC private and public keys.
*/

#include "sasi_error.h"
#include "sasi_rnd.h"
#include "sasi_ecpki_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ****************  SaSi_ECPKI_GenKeyPair_MTK function   ******************** */
/* !
@brief Generates a pair of private and public keys in internal representation according to [ANSI X9.62].

@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_ecpki_error.h.
*/
CIMPORT_C SaSiError_t SaSi_ECPKI_GenKeyPair_MTK(
    SaSi_RND_Context_t *pRndContext,        /* !< [in/out] Pointer to the RND context buffer. */
    const SaSi_ECPKI_Domain_t *pDomain,     /* !< [in]  Pointer to EC domain (curve). */
    SaSi_ECPKI_UserPrivKey_t *pUserPrivKey, /* !< [out] Pointer to the private key structure. This structure is used as
               input to the ECPKI cryptographic primitives. */
    SaSi_ECPKI_UserPublKey_t *pUserPublKey, /* !< [out] Pointer to the public key structure. This structure is used as
               input to the ECPKI cryptographic primitives. */
    SaSi_ECPKI_KG_TempData_t
        *pTempData, /* !< [in] Temporary buffers for internal use, defined in ::SaSi_ECPKI_KG_TempData_t. */
    SaSi_ECPKI_KG_FipsContext_t
        *pFipsCtx /* !< [in] Pointer to temporary buffer used in case FIPS certification if required. */
);

#ifdef __cplusplus
}
#endif

#endif
