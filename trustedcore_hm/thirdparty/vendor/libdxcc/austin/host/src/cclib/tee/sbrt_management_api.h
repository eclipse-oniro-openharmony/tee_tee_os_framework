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

#ifndef _SBRT_MNG_API_H
#define _SBRT_MNG_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include "dx_pal_types.h"
#include "sbrt_management_defs.h"
#include "secureboot_defs.h"

/* Life cycle state definitions */
#define DX_SBRT_CHIP_MANUFACTURE_LCS   0x0
#define DX_SBRT_DEVICE_MANUFACTURE_LCS 0x1
#define DX_SBRT_SECURITY_DISABLED_LCS  0x3
#define DX_SBRT_SECURE_LCS             0x5
#define DX_SBRT_RMA_LCS                0x7

/* AES definitions */
#define DX_SBRT_AES_BLOCK_SIZE_IN_WORDS 4
#define DX_SBRT_AES_BLOCK_SIZE_IN_BYTES (DX_SBRT_AES_BLOCK_SIZE_IN_WORDS * sizeof(uint32_t))

/* definition for NONCE array */
#define DX_SBRT_MAX_NONCE_ARRAY_SIZE_WORDS 4
#define DX_SBRT_MAX_KDR_SIZE_WORDS         8

typedef uint8_t DxMngAesCmacResult_t[DX_SBRT_AES_BLOCK_SIZE_IN_BYTES];
typedef uint32_t DxMngAesKey_t[DX_SBRT_AES_BLOCK_SIZE_IN_WORDS];

/* Max size of ram buffer for RND usage */
#define DX_RND_MAX_SIZE_OF_RAM_BUFFER_WORDS 1024
#define DX_RND_MAX_SIZE_OF_RAM_BUFFER_BYTES (DX_RND_MAX_SIZE_OF_RAM_BUFFER_WORDS * sizeof(uint32_t))

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

/* !
 * @brief This function retrieves the security lifecycle from the HW register (when it is valid).
 *        If the lifecycle is "secure" the function also needs to verify that the security disable flag
 *        (word 0x18 in OTP) is set to 4'b0011.
 *
 * @param[in/out] pLcs        - pointer to copy of current lifecycle state
 *
 * @return DxError_t         - On success: the value DX_OK is returned,
 *                       On failure: a value from sbrom_management_error.h
 */
DxError_t DX_SBRT_GetLcs(uint32_t *pLcs);

/* !
 * @brief This function reads the public key from OTP memory by key index
 *        (index can be select Hbk, Hbk0, or Hbk1). Returns an error if the
 *        requested hash field does not match its zero count.
 *
 * @param[in] keyIndex         - the index of the key HASH in the OTP (should be DxSbPubKeyIndexType_t)
 * @param[out] hashedPubKey    - the HASH of the public key
 * @param[in] hashResultSizeWord- the HASH buffer size in words
 *
 * @return DxError_t         - On success: the value DX_OK is returned,
 *                       On failure: a value from sbrom_management_error.h
 */
DxError_t DX_SBRT_GetPubKeyHash(DxSbPubKeyIndexType_t keyIndex, uint32_t *hashedPubKey, uint32_t hashResultSizeWords);

/* !
 * @brief This function retrieves the minimum SW version from the OTP memory.
 *        It receives a counter index (indicating whether to read the counter for trusted firmware upgrades or
 *        non-trusted firmware upgrades), and returns the requested version (number of bits set within the
 *        specified field).
 *
 * @param[in] counterId     - sw revocation counter ID
 * @param[out] swVersion    - the sw version value (number of bits set in the OTP )
 *
 * @return DxError_t         - On success: the value DX_OK is returned,
 *                       On failure: a value from sbrom_management_error.h
 */
DxError_t DX_SBRT_GetSwVersion(DxSbSwVersionId_t counterNum, uint32_t *swVersion);

/* !
 * @brief This function writes the minimum SW version to the OTP memory.
 *        It receives a counter index (indicating whether to read the counter for trusted firmware upgrades or
 *        non-trusted firmware upgrades), and encodes the given counter value to base-1 representation
 *        (This is monotonic anti-rollback counter).
 *
 * @param[in] counterId     - sw revocation counter ID
 * @param[in] swVersion        - the new sw version
 *                   (note: it is the number of bits that should be set in the OTP memory)
 *
 * @return DxError_t         - On success: the value DX_OK is returned,
 *                       On failure: a value from sbrom_management_error.h
 */
DxError_t DX_SBRT_SetSwVersion(DxSbSwVersionId_t counterId, uint32_t swVersion);

/* !
 * @brief This function retrieves the code encryption key (Kce) from the OTP memory,
 *        returning either the key or an error indication if the number of zero bits in Kce does not
 *        match the zero-count field in the OEM flags word in OTP memory.
 *
 * @param[out] codeEncryptionKey- a pointer to store the Kce buffer
 *
 * @return DxError_t         - On success: the value DX_OK is returned,
 *                       On failure: a value from sbrom_management_error.h
 */
DxError_t DX_SBRT_GetCodeEncryptionKey(DxMngAesKey_t codeEncryptionKey);

#ifdef __cplusplus
}
#endif

#endif
