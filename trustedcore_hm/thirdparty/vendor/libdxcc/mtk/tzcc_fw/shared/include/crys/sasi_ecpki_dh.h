/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_ECPKI_DH_H
#define SaSi_ECPKI_DH_H

/* ! @file
@brief Defines the API that supports EC Diffie-Hellman shared secret value derivation primitives.
*/

#include "sasi_ecpki_types.h"
#include "sasi_ecpki_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* **********************************************************************
 *                 SaSi_ECDH_SVDP_DH_MTK function                    *
 * ******************************************************************** */
/* !
@brief Creates the shared secret value according to [IEEE1363] and [ANS X9.63]:

<ol><li> Checks input-parameter pointers and EC Domain in public and private
keys.</li>
<li> Derives the partner public key and calls the LLF_ECPKI_SVDP_DH
function, which performs EC SVDP operations.</li></ol>
\note The term "User"
refers to any party that calculates a shared secret value using this primitive.
The term "Partner" refers to any other party of shared secret value calculation.
Partner's public key shall be validated before using in this primitive.

@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_ecpki_error.h.
*/
CIMPORT_C SaSiError_t
SaSi_ECDH_SVDP_DH_MTK(SaSi_ECPKI_UserPublKey_t *PartnerPublKey_ptr, /* !< [in]  Pointer to a partner public key. */
                      SaSi_ECPKI_UserPrivKey_t *UserPrivKey_ptr,    /* !< [in]  Pointer to a user private key. */
                      uint8_t *SharedSecretValue_ptr,  /* !< [out] Pointer to an output buffer that contains the shared
                           secret value. */
                      uint32_t *SharedSecrValSize_ptr, /* !< [in/out] Pointer to the size of user-passed buffer (in) and
                                                                     actual size of output of calculated shared secret
                         value (out). */
                      SaSi_ECDH_TempData_t *TempBuff_ptr /* !< [in]  Pointer to a temporary buffer. */);

#ifdef __cplusplus
}
#endif

#endif
