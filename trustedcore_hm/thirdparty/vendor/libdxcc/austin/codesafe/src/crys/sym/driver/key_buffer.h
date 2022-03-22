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

#ifndef __KEY_BUFFER_H__
#define __KEY_BUFFER_H__

#include "key_buffer_plat.h"

#define KDF_LABEL_SIZE   4
#define KDF_CONTEXT_SIZE 16

typedef enum KeyPtrType { KEY_BUF_NULL, KEY_BUF_SEP, KEY_BUF_DLLI } KeyPtrType_t;

typedef struct KeyBuffer {
    uint8_t *pKey; /* A pointer to the key data. May be SRAM/DCACHE/ICACHE/DLLI */
    enum sep_crypto_key_type cryptoKeyType;
    KeyPtrType_t keyPtrType;
} KeyBuffer_s;

/* Key derivation function (KDF) struct according to nist 800-108 */
typedef struct KdfInputBuff {
    uint8_t iterationCount;
    uint8_t label[KDF_LABEL_SIZE];
    uint8_t separator;
    uint8_t context[KDF_CONTEXT_SIZE];
    uint8_t kdfOutSize[sizeof(uint16_t)];
} KdfInputBuff_s;

/* !
 * Parse user buffer information that may be smart key pointer (key object)
 * Return uniform Key information
 *
 *
 * \param [in]  keyObj - the key buffer
 * \param [out] keyAddr - key pointer
 * \param [out] cryptoKeyType - type of key (ROOT, USER,PROVISIONING ...)
 * \param [out] keyPtrType  - type of pointer (SRAM ptr, DCAHE ptr, DLLI ptr)
 *
 * \return 0 on success, (-1) on error
 */
int getKeyDataFromKeyObj(uint8_t *keyObj, uint8_t **keyAddr, enum sep_crypto_key_type *cryptoKeyType,
                         KeyPtrType_t *keyPtrType, enum dx_data_key_obj_api cryptoObjApi);

/* !
 * Build Key internal
 *
 * \param  pAesContext - aes context for AES_CMAC operation
 * \param  KeySize - the key size
 * \param  keyAddr - key pointer
 * \param  cryptoObjApi  - the API we are coming from.
 * \param  cryptoKeyType - type of key (ROOT, USER,PROVISIONING ...)
 * \param  keySizeBytes  - the Of the key, in bytes)
 *
 */
int buildKeyInt(struct sep_ctx_cipher *AesContext, CRYS_AES_KeySize_t *KeySize, keyBuffer_t keyBuff, uint8_t **keyAddr,
                enum dx_data_key_obj_api cryptoObjApi, enum sep_crypto_key_type cryptoKeyType, uint32_t *keySizeBytes);

#endif /* __KEY_BUFFER_H__ */
