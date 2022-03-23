/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_H
#define _SSI_UTIL_H

/* !
@file
@brief This file contains CryptoCell Util functions and definitions.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_util_defs.h"
#include "ssi_util_error.h"
#include "ssi_pal_types.h"
#include "sasi_rnd.h"
#include "sasi_ecpki_types.h"

/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */

/* ************************************** */
/* Endorsement key derivation definitions */
/* ************************************** */
typedef enum {
    SASI_UTIL_EK_DomainID_secp256k1 = 1,
    SASI_UTIL_EK_DomainID_secp256r1 = 2,
    SASI_UTIL_EK_DomainID_Max,
    SASI_UTIL_EK_DomainID_Last = 0x7FFFFFFF,
} SASI_UTIL_EK_DomainID_t;

#define SASI_UTIL_EK_MODUL_MAX_LENGTH 32 // 256 bit modulus size

typedef uint8_t SASI_UTIL_EK_Point_t[SASI_UTIL_EK_MODUL_MAX_LENGTH];

typedef SASI_UTIL_EK_Point_t SASI_UTIL_EK_Privkey_t;

typedef struct {
    SASI_UTIL_EK_Point_t PublKeyX;
    SASI_UTIL_EK_Point_t PublKeyY;
} SASI_UTIL_EK_Pubkey_t;

/* ! Required for internal FIPS verification for Endorsement key derivation. */
typedef SaSi_ECPKI_KG_FipsContext_t SASI_UTIL_EK_FipsContext_t;

/* ! Required for  Endorsement key derivation. */
typedef SaSi_ECPKI_KG_TempData_t SASI_UTIL_EK_TempData_t;

/* !
 * @brief This function computes the device unique endorsement key, as an ECC256 key pair, derived from the device root
 * key (KDR). Prior to using this ECC key pair with SaSi ECC APIs, translate the domain ID that was used to create it,
 * to a SaSi domain ID: <ul><li>SSI_UTIL_EK_DomainID_secp256r1 - SaSi_ECPKI_DomainID_secp256r1.</li>
 *      <li>SSI_UTIL_EK_DomainID_secp256k1 - SaSi_ECPKI_DomainID_secp256k1.</li></ul>
 *
 *
 * @return SASI_UTIL_OK on success.
 * @return A non-zero value on failure as defined ssi_util_error.h.
 *
 */
SaSiUtilError_t SaSi_UtilDeriveEndorsementKey(
    SASI_UTIL_EK_DomainID_t
        domainID, /* !< [in] Selection of domain ID for the key. The following domain IDs are supported:
   <ul><li> SSI_UTIL_EK_DomainID_secp256r1 (compliant with [TBBR_C].)</li>
   <li> SSI_UTIL_EK_DomainID_secp256k1. </li></ul> */
    SASI_UTIL_EK_Privkey_t *pPrivKey_ptr,  /* !< [out] Pointer to the derived private key. To use this private key with
                           SaSi ECC,  use ::SaSi_ECPKI_BuildPrivKey_MTK (SaSidomainID, pPrivKey_ptr,
                           sizeof(*pPrivKey_ptr),  UserPrivKey_ptr) to convert to SaSi ECC private key format. */
    SASI_UTIL_EK_Pubkey_t *pPublKey_ptr,   /* !< [out] Pointer to the derived public key, in [X||Y] format (X and Y being
                          the point   coordinates). To use this public key with SaSi ECC:   <ul><li> Concatenate a single byte
                          with value 0x04 (indicating uncompressed   format) with pPublKey_ptr in the following order
                          [0x04||X||Y].</li>   <li> Call ::SaSi_ECPKI_BuildPublKey (SaSidomainID, [PC || pPublKey_ptr],
                              1+sizeof(*pPublKey_ptr), UserPublKey_ptr) to convert to SaSi_ECC public key
                              format.</li></ul> */
    SASI_UTIL_EK_TempData_t *pTempDataBuf, /* !< [in] Temporary buffers for internal use. */
    SaSi_RND_Context_t
        *pRndContext, /* !< [in/out] Pointer to the RND context buffer used in case FIPS certification if required. */
    SASI_UTIL_EK_FipsContext_t
        *pEkFipsCtx /* !< [in]  Pointer to temporary buffer used in case FIPS certification if required. */
);

/* ************************************** */
/*   SESSION key settings definitions    */
/* ************************************** */

/* !
 * @brief This function builds a random session key (KSESS), and sets it to the session key registers.
 *        It must be used as early as possible during the boot sequence, but only after the RNG is initialized.
 *
 * \note
 *    <ul id="noteb"><li>If this API is called more than once, each subsequent call invalidates any prior
 * session-key-based authentication. These prior authentications have to be authenticated again.</li> <li>Whenever the
 * device reconfigures memory buffers previously used for secure content, to become accessible from non-secure context,
 *     ::SaSi_UtilSetSessionKey must be invoked to set a new session key, and thus invalidate any existing secure key
 * packages.</li></ul>
 *
 * @return SASI_UTIL_OK on success.
 * @return A non-zero value on failure as defined ssi_util_error.h.
 */
SaSiUtilError_t
SaSi_UtilSetSessionKey(SaSi_RND_Context_t *pRndContext /* !< [in,out] Pointer to the RND context buffer. */);

/* !
 * @brief This function disables the device security. The function does the following:
 *      <ol><li> Sets the security disabled register.</li>
 *      <li>Sets the session key register to 0.</li></ol>
 * \note If ARM SDER register is to be set the user must set the device to temporary Security Disabled by calling
 *     this API prior to setting the register.
 *
 * @return SASI_UTIL_OK on success.
 * @return A non-zero value on failure as defined ssi_util_error.h.
 */
SaSiUtilError_t SaSi_UtilSetSecurityDisable(void);

#ifdef __cplusplus
}
#endif

#endif /* _SSI_UTIL_H */
