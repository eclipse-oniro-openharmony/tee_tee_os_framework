/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_ECPKI_DOMAIN_H
#define SaSi_ECPKI_DOMAIN_H

/* !
@file
@brief Defines the ecpki build domain API.
*/

#include "sasi_error.h"
#include "sasi_ecpki_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************************************************************************
 *                SaSi_ECPKI_BuildEcDomain function               *
 * ******************************************************************************* */
/* !
@brief The function builds (imports) the ECC Domain structure from EC parameters given
by the user in big endian order of bytes in arrays.

When operating the ECC cryptographic operations this function should be called first.
The function performs the following operations:
<ul><li>Checks pointers and sizes of incoming parameters.</li>
<li> Converts parameters from big endian bytes arrays into little endian words arrays, where
the left word is the last significant.</li></ul>
\note
Domain parameters should be validated by the user, prior to calling this function

@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_ecpki_error.h.
 */
CIMPORT_C SaSiError_t SaSi_ECPKI_BuildEcDomain(
    uint8_t *pMod,                 /* !< [in]  A pointer to EC modulus. */
    uint8_t *pA,                   /* !< [in]  A pointer to parameter A of elliptic curve.
                                               The size of the buffer must be the same as EC modulus. */
    uint8_t *pB,                   /* !< [in]  A pointer to parameter B of elliptic curve.
                                               The size of the buffer must be the same as EC modulus. */
    uint8_t *pOrd,                 /* !< [in]  A pointer to order of generator (point G). */
    uint8_t *pGx,                  /* !< [in]  A pointer to coordinate X of generator G.
                                               The size of the buffer must be the same as EC modulus. */
    uint8_t *pGy,                  /* !< [in]  A pointer to coordinate Y of generator G.
                                               The size of the buffer must be the same as EC modulus. */
    uint8_t *pCof,                 /* !< [in]  A pointer to EC cofactor - optional. If the pointer
                                               and the size are set to null, the given curve has
                                               cofactor = 1 or cofactor should not be included in the calculations. */
    uint32_t modSizeBytes,         /* !< [in]  A size of the EC modulus buffer in bytes.
                                               \note The sizes of the buffers: pA, pB, pGx, pGx are equal to pMod size. */
    uint32_t ordSizeBytes,         /* !< [in]  A size of the generator order in bytes. */
    uint32_t cofSizeBytes,         /* !< [in]  A size of cofactor buffer in bytes. According to our
                                               implementation cofactorSizeBytes must be not great, than 4 bytes.
                                               If cofactor = 1, then, the size and the pointer may be set to null. */
    uint32_t securityStrengthBits, /* !< [in]  Optional security strength level S in bits:
                                                 see ANS X9.62-2005 A.3.1.4. If this parameter is equal to 0, then
                                                 it is ignored, else the function checks the EC order size. If the order
                                                 is less than max(S-1, 160), then the function returns an error. */
    SaSi_ECPKI_Domain_t *pDomain   /* !< [out] A pointer to EC domain structure. */
);

/* *********************************************************************************
 *                SaSi_ECPKI_GetEcDomain function                     *
 * ******************************************************************************* */

/* !
 * @brief  The function returns a pointer to an ECDSA saved domain (one of the supported domains)
 *
 * @return Domain pointer on success.
 * @return NULL on failure.
 */

const SaSi_ECPKI_Domain_t *SaSi_ECPKI_GetEcDomain(
    SaSi_ECPKI_DomainID_t domainId /* !< [in] Index of one of the domain Id (must be one of the supported domains). */);

#ifdef __cplusplus
}
#endif

#endif
