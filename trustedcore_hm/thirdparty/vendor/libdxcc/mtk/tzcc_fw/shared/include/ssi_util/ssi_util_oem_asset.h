/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_OEM_ASSET_H
#define _SSI_UTIL_OEM_ASSET_H

/* !
@file
@brief This file contains the functions and definitions for the OEM Asset provisioning.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_util_defs.h"

/* ! Defines the OEM key buffer. */
typedef SaSiUtilAesCmacResult_t SaSiUtilOemKey_t;

/* !
 * @brief This API provides a means of secure provisioning of OEM assets to devices using ARM TrustZone CryptoCell TEE.
 *        It takes an encrypted and authenticated asset package produced by the OEM Asset Packing offline utility
 *        (using AES-CCM with key derived from KOEM and the asset identifier), authenticates and decrypts it.
 *        The decrypted asset data, and optional user data parameter, are returned to the caller.
 * \note  The device must be in Secure LCS, otherwise error is returned.
 *
 * @return SASI_UTIL_OK on success.
 * @return A non-zero value on failure as defined in ssi_util_error.h.
 */
SaSiUtilError_t SaSi_UtilOemAssetUnpack(
            SaSiUtilOemKey_t          pOemKey,      /* !< [in] KOEM 16 bytes buffer, in big-endian order. KOEM was previously computed during
                                      first stage boot, and stored in secure SRAM. */
            uint32_t           assetId,      /* !< [in] 32bit index identifying the asset, big-endian order. Must match the asset ID embedded
                                      in the asset package. */
            uint8_t             *pAssetPackage,     /* !< [in] The encrypted and authenticated asset package. */
            uint32_t          assetPackageLen, /* !< [in] Length of the asset package. */
            uint8_t             *pAssetData,      /* !< [out] Buffer for retrieving the decrypted asset data. */
            uint32_t          *pAssetDataLen,  /* !< [in, out] Input: Size of the available asset data buffer.
                                        Output: Pointer to actual length of the decrypted asset data.
                                        Maximal size is 512 bytes. */
            uint32_t             *pUserData     /* !< [out] Pointer to 32bit integer for retrieval of the user data that was optionally
                                        embedded in the package. May be NULL, in which case the user data is not returned. */);

#ifdef __cplusplus
}
#endif

#endif /* _SSI_UTIL_ASSET_H */
