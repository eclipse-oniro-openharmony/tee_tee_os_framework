/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef _BOOT_IMAGES_VERIFIER_SWCOMP_H
#define _BOOT_IMAGES_VERIFIER_SWCOMP_H

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

/* *********************** Public Functions **************************** */
/*
 * @brief This function is responsible to verification of the SW components.
 *        The function will go over the SW components load each component,
 *        compute its HASH and compare it with the HASH saved in the certificate.
 *
 *
 * @param[in] flashRead_func - User's Flash read function used to read data from the flash to memory location
 * @param[in] userContext - User's context for the usage of flashRead_func
 * @param[in] pSwImagesData - s/w comps data, pointers to certificate locations of the s/w comps HASH data
 * @param[in] pSwImagesAddData - s/w comps additional data, pointers to certificate locations of the s/w comps
 * additional data
 * @param[in] workspace_ptr - temporary buffer to load the SW components to (SW components without
 *            loading address).
 * @param[in] workspaceSize - the temporary buffer size in bytes
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from BootImagesVerifier_error.h
 */
DxError_t DxCertValidateSWComps(DxSbFlashReadFunc flashRead_func, void *userContext,

                                DxSbCertParserSwCompsInfo_t *pSwImagesData, uint32_t *pSwImagesAddData,
                                uint32_t *workspace_ptr, uint32_t workspaceSize);

#ifdef __cplusplus
}
#endif

#endif
