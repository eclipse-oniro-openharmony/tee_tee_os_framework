/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the function required for creating PHASE 1 KEY
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */

#ifndef HWAA_KDF_H
#define HWAA_KDF_H

#include "securec.h"
#include "tee_internal_api.h"
#include "bdkernel_utils.h"

#define SHA256_MAX_OBJECT_LENGTH 256
#define SHA256_HASH_BYTES 32
#define ATTRIBUTE_COUNT_ONE 1
#define SHA512_OBJECT_MAX_LENGTH 64
#define SHA256_LEN 32
#define AES256_KEY_LEN 32
#define SALT_LEN 32

/*
 * Description: Takes the users cred, and the hardware key and performs a key derivation
 * to generate a "phase 1" key psuedorandom key as the output.
 *
 * The output key can be cached as long as the user is logged into the device.  The phase1_key
 * key will last as long as the device is powered on.
 *
 * Params
 *
 *    hardware_key - input, plaintext hardware key (or derivied based upon hardware)
 *    hardware_key_len - input, the number of bytes in hardware_key
 *    output_phase1_key - output, pass in an UNINITIALIZED TEE_ObjectHandle.  This
 *                          will allocated new storage that must be free'd by a call
 *                          to KDF_FreeKeySeed.
 *
 *
 * Returns
 *    TEE_SUCCESS and life is good.  Anything else, indicates failure.
 *
 */
TEE_Result KdfAllocateKeySeed(const uint8_t * const hardwareKey, uint32_t hardwareKeyLen,
                              TEE_ObjectHandle *outputPhaseOneKey);

/*
 * HKDF_256 - A TEE implementation of RFC 5869 HMAC Based Extract and Expand KDF
 *
 * This implementation is limited to HMAC_SHA256 as an underlying HMAC function
 *
 * HKDF (salt, IKM, info) -> OKM where
 *    salt is a public random number
 *    IKM is input key material (secret)
 *    info is public application/context specific data
 *
 * Params:
 *    salt - input - salt value for HKDF
 *      input_key_material - input - the IKM valud for the HKDF
 *      info - input - context specific data
 *      output_key - output - the output derived key
 *    output_key_len - input/output - on input this represents the size of the
 *      output_key buffer, and the number of bytes of the desired key length.
 *
 * Returns:
 *    TEE_SUCCESS on success, and anything else on failure.
 */
TEE_Result Hkdf256(const TEE_ObjectHandle salt, const uint8_t * const inputKeyMaterial,
                   uint32_t inputKeyMaterialLen, uint8_t *outputKey, uint32_t *outputKeyLen);

#endif
