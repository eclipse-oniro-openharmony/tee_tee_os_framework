/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_ECPKI_BUILD_H
#define SaSi_ECPKI_BUILD_H

/* !
@file
@brief This module defines functions for building key structures used in Elliptic Curves Cryptography (ECC).
*/

#include "sasi_error.h"
#include "sasi_ecpki_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************************************************************************
 *                    SaSi_ECPKI_BuildPrivKey_MTK function                            *
 * ******************************************************************************* */
/* !
@brief Builds (imports) the user private key structure from an existing private key so
that this structure can be used by other EC primitives.
This function should be called before using of the private key. Input
domain structure must be initialized by EC parameters and auxiliary
values, using SaSi_ECPKI_GetDomain or SaSi_ECPKI_SetDomain functions.

@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_ecpki_error.h.
*/
CIMPORT_C SaSiError_t SaSi_ECPKI_BuildPrivKey_MTK(
    const SaSi_ECPKI_Domain_t *pDomain,    /* !< [in] The EC domain (curve). */
    const uint8_t *pPrivKeyIn,             /* !< [in] Pointer to private key data. */
    uint32_t PrivKeySizeInBytes,           /* !< [in] Size of private key data (in bytes). */
    SaSi_ECPKI_UserPrivKey_t *pUserPrivKey /* !< [out] Pointer to the private key structure.
                          This structure is used as input to the ECPKI cryptographic primitives. */
);

/* *********************************************************************************
 *                  _DX_ECPKI_BuildPublKey_MTK function                             *
 * ******************************************************************************* */
/* !
@brief Builds a user public key structure from an imported public key,
so it can be used by other EC primitives.
When operating the EC cryptographic algorithms with imported EC public
key, this function should be called before using of the public key.

\note The Incoming public key PublKeyIn structure is big endian bytes array, containing
concatenation of PC||X||Y, where:
<ul id="noteb"><li> PC - point control single byte, defining the type of point: 0x4 - uncompressed,
06,07 - hybrid, 2,3 - compressed. </li>
<li>X,Y - EC point coordinates of public key (y is omitted in compressed form),
size of X and Y must be equal to size of EC modulus. </li></ul>

The user may call this function by appropriate macros, according to necessary validation level [SEC1. ECC standard: 3.2]
and [ANSI X9.62]: <ul><li>Checking the input pointers and sizes only - ::SaSi_ECPKI_BuildPublKey.</li> <li>Partially
checking of public key - ::SaSi_ECPKI_BuildPublKeyPartlyCheck. </li> <li>Full checking of public key -
::SaSi_ECPKI_BuildPublKeyFullCheck. </li></ul>

\note Full check mode takes long time and should be used only when it is actually needed.

@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_ecpki_error.h.
*/
/*
The function performs the following operations:
- Checks validity of incoming variables and pointers;
- Converts incoming key data from big endian into little endian;
- If public key is given in compressed form (i.e. byte[0] = 2 or 3 and
  coordinate Y is omitted), then the function uncompress it;
- Performs checking of input key according to CheckMode parameter.
- Initializes variables and structures.
*/
CIMPORT_C SaSiError_t _DX_ECPKI_BuildPublKey_MTK(
    const SaSi_ECPKI_Domain_t *pDomain,     /* !< [in]  The EC domain (curve). */
    uint8_t *PublKeyIn_ptr,                 /* !< [in]  Pointer to the input public key data, in compressed or
                       uncompressed or hybrid form:
                       [PC||X||Y] Big-Endian representation, structured according to
                       [IEEE1363], where:
                       <ul><li>X and Y are the public key's EC point coordinates.
                       In compressed form, Y is omitted.</li>
                       <li> The sizes of X and Y are equal to the size of the EC modulus.</li>
                       <li> PC is a one-byte point control that defines the type of point
                       compression. </li></ul> */
    uint32_t PublKeySizeInBytes,            /* !< [in]  The size of public key data (in bytes). */
    EC_PublKeyCheckMode_t CheckMode,        /* !< [in]  The required level of public key verification
                (higher verification level means longer verification time):
                <ul><li> 0 = preliminary validation. </li>
                <li> 1 = partial validation. </li>
                <li> 2 = full validation. </li></ul> */
    SaSi_ECPKI_UserPublKey_t *pUserPublKey, /* !< [out] Pointer to the output public key structure.
                    This structure is used as input to the ECPKI cryptographic primitives. */
    SaSi_ECPKI_BUILD_TempData_t *pTempBuff /* !< [in]  Pointer for a temporary buffer required for the build function. */
);

/* *********************************************************************************
 *                   SaSi_ECPKI_BuildPublKey macro                              *
 * ******************************************************************************* */
/* !
@brief This macro calls _DX_ECPKI_BuildPublKey_MTK function for building the public key
while checking input pointers and sizes. For a description of the parameters see ::_DX_ECPKI_BuildPublKey_MTK.
*/
#define SaSi_ECPKI_BuildPublKey(pDomain, PublKeyIn_ptr, PublKeySizeInBytes, pUserPublKey)                   \
    _DX_ECPKI_BuildPublKey_MTK((pDomain), (PublKeyIn_ptr), (PublKeySizeInBytes), CheckPointersAndSizesOnly, \
                               (pUserPublKey), NULL)

/* *********************************************************************************
 *                   SaSi_ECPKI_BuildPublKeyPartlyCheck macro                         *
 * ******************************************************************************* */
/* !
@brief This macro calls _DX_ECPKI_BuildPublKey_MTK function for building the public key with partial validation of the
key [SEC1] - 3.2.3. For a description of the parameters see ::_DX_ECPKI_BuildPublKey_MTK.
*/
#define SaSi_ECPKI_BuildPublKeyPartlyCheck(pDomain, PublKeyIn_ptr, PublKeySizeInBytes, pUserPublKey, pTempBuff)        \
    _DX_ECPKI_BuildPublKey_MTK((pDomain), (PublKeyIn_ptr), (PublKeySizeInBytes), ECpublKeyPartlyCheck, (pUserPublKey), \
                               (pTempBuff))

/* *********************************************************************************
 *                   SaSi_ECPKI_BuildPublKeyFullCheck macro                     *
 * ******************************************************************************* */
/* !
@brief This macro calls _DX_ECPKI_BuildPublKey_MTK function for building the public key with full validation of the key
[SEC1] - 3.2.2. For a description of the parameters and return values see _DX_ECPKI_BuildPublKey_MTK.
*/
#define SaSi_ECPKI_BuildPublKeyFullCheck(pDomain, PublKeyIn_ptr, PublKeySizeInBytes, pUserPublKey, pTempBuff)          \
    _DX_ECPKI_BuildPublKey_MTK((pDomain), (PublKeyIn_ptr), (PublKeySizeInBytes), (ECpublKeyFullCheck), (pUserPublKey), \
                               (pTempBuff))

/* **********************************************************************************
 *                     SaSi_ECPKI_ExportPublKey_MTK function                           *
 * ******************************************************************************** */
/* !
@brief Converts an existing public key from internal representation to Big-Endian export representation.
The function converts the X,Y coordinates of public key EC point to big endianness,
and sets the public key as follows:
<ul><li>In case "Uncompressed" point:  PubKey = PC||X||Y, PC = 0x4 - single byte;</li>
<li>In case of "Hybrid" key PC = 0x6.</li>
<li>In case of "Compressed" key PC = 0x2.</li></ul>
\note Size of output X and Y coordinates is equal to ModSizeInBytes.
@return SaSi_OK on success.
@return A non-zero value on failure as defined sasi_ecpki_error.h.
*/
CIMPORT_C SaSiError_t SaSi_ECPKI_ExportPublKey_MTK(
    SaSi_ECPKI_UserPublKey_t
        *pUserPublKey, /* !< [in]  Pointer to the input public key structure (in Little-Endian form). */
    SaSi_ECPKI_PointCompression_t compression, /* !< [in]  Compression mode: Compressed, Uncompressed or Hybrid. */
    uint8_t *pExternPublKey,    /* !< [out] Pointer to the exported public key array, in compressed or uncompressed
         or hybrid form:
      [PC||X||Y] Big-Endian representation, structured according to [IEEE1363].
      In compressed form, Y is omitted. */
    uint32_t *pPublKeySizeBytes /* !< [in/out] Pointer used for the input of the user public key buffer size
         (in bytes), and the output of the size of the converted public key in bytes. */
);

#ifdef __cplusplus
}
#endif

#endif
