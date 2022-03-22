/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "ssi_aes.h"
#include "sasi_aesccm.h"
#include "sasi_des.h"
#include "sasi_hash.h"
#include "sasi_hmac.h"
#include "sasi_fips_defs.h"
#include "sasi_fips_sym_data.h"

#define FIPS_SYM_PUT_MAX_TEST_DATA_SIZE      32
#define FIPS_SYM_PUT_MAX_HMAC_TEST_DATA_SIZE 128
#define FIPS_SYM_COND_MAX_BLOCK_SIZE         0x100000

typedef struct _FipsAesData {
    SaSiAesKeyBuffer_t key;
    uint32_t keySize;
    SaSiAesIv_t iv;
    SaSiAesEncryptMode_t encMode;
    SaSiAesOperationMode_t oprMode;
    uint8_t dataIn[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
    uint8_t dataOut[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
    uint32_t dataInSize;
    uint32_t dataOutSize;
    CC_FipsError_t error;
} FipsAesData;

typedef struct _FipsAesCcmData {
    SaSi_AESCCM_Key_t key;
    uint32_t keySize;
    uint8_t nonce[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
    uint8_t nonceSize;
    SaSiAesEncryptMode_t encMode;
    uint8_t AData[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
    uint32_t ADataSize;
    uint8_t textData[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
    uint32_t textDataSize;
    uint8_t textDataOut[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
    uint8_t tagSize;
    SaSi_AESCCM_Mac_Res_t macResOut;
    CC_FipsError_t error;
} FipsAesCcmData;

typedef struct _FipsDesData {
    SaSi_DES_Key_t key;
    SaSi_DES_NumOfKeys_t numOfKeys;
    SaSi_DES_Iv_t iv;
    SaSi_DES_EncryptMode_t encMode;
    SaSi_DES_OperationMode_t oprMode;
    uint8_t dataIn[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
    uint8_t dataOut[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
    uint32_t dataInSize;
    CC_FipsError_t error;
} FipsDesData;

typedef struct _FipsHashData {
    SaSi_HASH_OperationMode_t oprMode;
    uint8_t dataIn[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
    uint32_t dataInSize;
    uint8_t HashResultBuff[SaSi_HASH_SHA512_DIGEST_SIZE_IN_BYTES]; /* maximum required size */
    uint32_t HmacResultSize;
    CC_FipsError_t error;
} FipsHashData;

typedef struct _FipsHmacData {
    SaSi_HASH_OperationMode_t oprMode;
    uint8_t key[SaSi_HMAC_KEY_SIZE_IN_BYTES]; /* maximum required size */
    uint32_t keySize;
    uint8_t dataIn[FIPS_SYM_PUT_MAX_HMAC_TEST_DATA_SIZE];
    uint32_t dataInSize;
    uint8_t HmacResultBuff[SaSi_HASH_SHA512_DIGEST_SIZE_IN_BYTES]; /* maximum required size */
    uint32_t HmacResultSize;
    CC_FipsError_t error;
} FipsHmacData;

/* test data tables */
static const FipsAesData FipsAesDataTable[] = {
    { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_ECB,
      NIST_AES_PLAIN_DATA, NIST_AES_128_ECB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_ECB_PUT },
    { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_DECRYPT, SASI_AES_MODE_ECB,
      NIST_AES_128_ECB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_ECB_PUT },
    { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_ECB,
      NIST_AES_PLAIN_DATA, NIST_AES_192_ECB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_ECB_PUT },
    { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_DECRYPT, SASI_AES_MODE_ECB,
      NIST_AES_192_ECB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_ECB_PUT },
    { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_ECB,
      NIST_AES_PLAIN_DATA, NIST_AES_256_ECB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_ECB_PUT },
    { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_DECRYPT, SASI_AES_MODE_ECB,
      NIST_AES_256_ECB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_ECB_PUT },
    { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CBC_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CBC, NIST_AES_PLAIN_DATA,
      NIST_AES_128_CBC_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_PUT },
    { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CBC_IV, SASI_AES_DECRYPT, SASI_AES_MODE_CBC,
      NIST_AES_128_CBC_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_CBC_PUT },
    { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_CBC_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CBC, NIST_AES_PLAIN_DATA,
      NIST_AES_192_CBC_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_PUT },
    { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_CBC_IV, SASI_AES_DECRYPT, SASI_AES_MODE_CBC,
      NIST_AES_192_CBC_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_CBC_PUT },
    { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_CBC_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CBC, NIST_AES_PLAIN_DATA,
      NIST_AES_256_CBC_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_PUT },
    { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_CBC_IV, SASI_AES_DECRYPT, SASI_AES_MODE_CBC,
      NIST_AES_256_CBC_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_CBC_PUT },
    { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_OFB_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_OFB, NIST_AES_PLAIN_DATA,
      NIST_AES_128_OFB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_OFB_PUT },
    { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_OFB_IV, SASI_AES_DECRYPT, SASI_AES_MODE_OFB,
      NIST_AES_128_OFB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_OFB_PUT },
    { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_OFB_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_OFB, NIST_AES_PLAIN_DATA,
      NIST_AES_192_OFB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_OFB_PUT },
    { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_OFB_IV, SASI_AES_DECRYPT, SASI_AES_MODE_OFB,
      NIST_AES_192_OFB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_OFB_PUT },
    { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_OFB_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_OFB, NIST_AES_PLAIN_DATA,
      NIST_AES_256_OFB_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_OFB_PUT },
    { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_OFB_IV, SASI_AES_DECRYPT, SASI_AES_MODE_OFB,
      NIST_AES_256_OFB_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_OFB_PUT },
    { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CTR_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CTR, NIST_AES_PLAIN_DATA,
      NIST_AES_128_CTR_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CTR_PUT },
    { NIST_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CTR_IV, SASI_AES_DECRYPT, SASI_AES_MODE_CTR,
      NIST_AES_128_CTR_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_CTR_PUT },
    { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_CTR_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CTR, NIST_AES_PLAIN_DATA,
      NIST_AES_192_CTR_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CTR_PUT },
    { NIST_AES_192_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_CTR_IV, SASI_AES_DECRYPT, SASI_AES_MODE_CTR,
      NIST_AES_192_CTR_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_CTR_PUT },
    { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_CTR_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CTR, NIST_AES_PLAIN_DATA,
      NIST_AES_256_CTR_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE, CC_TEE_FIPS_ERROR_AES_CTR_PUT },
    { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_CTR_IV, SASI_AES_DECRYPT, SASI_AES_MODE_CTR,
      NIST_AES_256_CTR_CIPHER, NIST_AES_PLAIN_DATA, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_CTR_PUT },
    { RFC3962_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CBC_CTS,
      RFC3962_AES_PLAIN_DATA, RFC3962_AES_128_CBC_CTS_CIPHER, RFC3962_AES_VECTOR_SIZE, RFC3962_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_CBC_CTS_PUT },
    { RFC3962_AES_128_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_DECRYPT, SASI_AES_MODE_CBC_CTS,
      RFC3962_AES_128_CBC_CTS_CIPHER, RFC3962_AES_PLAIN_DATA, RFC3962_AES_VECTOR_SIZE, RFC3962_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_CBC_CTS_PUT },
    { NIST_AES_128_CBC_MAC_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CBC_MAC_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CBC_MAC,
      NIST_AES_128_CBC_MAC_ONE_BLOCK_PLAIN_DATA, NIST_AES_128_CBC_MAC_ONE_BLOCK_OUTPUT,
      NIST_AES_128_CBC_MAC_ONE_BLOCK_VECTOR_SIZE, NIST_AES_128_CBC_MAC_OUTPUT_SIZE, CC_TEE_FIPS_ERROR_AES_CBC_MAC_PUT },
    { NIST_AES_128_CBC_MAC_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_CBC_MAC_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CBC_MAC,
      NIST_AES_128_CBC_MAC_TWO_BLOCKS_PLAIN_DATA, NIST_AES_128_CBC_MAC_TWO_BLOCKS_OUTPUT,
      NIST_AES_128_CBC_MAC_TWO_BLOCKS_VECTOR_SIZE, NIST_AES_128_CBC_MAC_OUTPUT_SIZE,
      CC_TEE_FIPS_ERROR_AES_CBC_MAC_PUT },
    { NIST_AES_256_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_CBC_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CBC_MAC,
      NIST_AES_PLAIN_DATA, NIST_AES_256_CBC_CIPHER, NIST_AES_VECTOR_SIZE, NIST_AES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_CBC_MAC_PUT },
    { NIST_AES_256_XTS_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_256_XTS_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_XTS,
      NIST_AES_256_XTS_PLAIN, NIST_AES_256_XTS_CIPHER, NIST_AES_256_XTS_VECTOR_SIZE, NIST_AES_256_XTS_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_XTS_PUT },
    { NIST_AES_256_XTS_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_256_XTS_IV, SASI_AES_DECRYPT, SASI_AES_MODE_XTS,
      NIST_AES_256_XTS_CIPHER, NIST_AES_256_XTS_PLAIN, NIST_AES_256_XTS_VECTOR_SIZE, NIST_AES_256_XTS_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_XTS_PUT },
    { NIST_AES_512_XTS_KEY, AES_512_BIT_KEY_SIZE, NIST_AES_512_XTS_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_XTS,
      NIST_AES_512_XTS_PLAIN, NIST_AES_512_XTS_CIPHER, NIST_AES_512_XTS_VECTOR_SIZE, NIST_AES_256_XTS_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_XTS_PUT },
    { NIST_AES_512_XTS_KEY, AES_512_BIT_KEY_SIZE, NIST_AES_512_XTS_IV, SASI_AES_DECRYPT, SASI_AES_MODE_XTS,
      NIST_AES_512_XTS_CIPHER, NIST_AES_512_XTS_PLAIN, NIST_AES_512_XTS_VECTOR_SIZE, NIST_AES_256_XTS_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_AES_XTS_PUT },
    { NIST_AES_128_CMAC_KEY, AES_128_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CMAC,
      NIST_AES_128_CMAC_PLAIN_DATA, NIST_AES_128_CMAC_MAC, NIST_AES_128_CMAC_VECTOR_SIZE, NIST_AES_128_CMAC_OUTPUT_SIZE,
      CC_TEE_FIPS_ERROR_AES_CMAC_PUT },
    { NIST_AES_192_CMAC_KEY, AES_192_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CMAC,
      NIST_AES_192_CMAC_PLAIN_DATA, NIST_AES_192_CMAC_MAC, NIST_AES_192_CMAC_VECTOR_SIZE, NIST_AES_192_CMAC_OUTPUT_SIZE,
      CC_TEE_FIPS_ERROR_AES_CMAC_PUT },
    { NIST_AES_256_CMAC_KEY, AES_256_BIT_KEY_SIZE, NIST_AES_DUMMY_IV, SASI_AES_ENCRYPT, SASI_AES_MODE_CMAC,
      NIST_AES_256_CMAC_PLAIN_DATA, NIST_AES_256_CMAC_MAC, NIST_AES_256_CMAC_VECTOR_SIZE, NIST_AES_256_CMAC_OUTPUT_SIZE,
      CC_TEE_FIPS_ERROR_AES_CMAC_PUT },
};
#define FIPS_AES_NUM_OF_TESTS (sizeof(FipsAesDataTable) / sizeof(FipsAesData))

static const FipsAesCcmData FipsAesCcmDataTable[] = {
    { NIST_AESCCM_128_KEY, NIST_AESCCM_128_BIT_KEY_SIZE, NIST_AESCCM_128_NONCE, NIST_AESCCM_NONCE_SIZE,
      SASI_AES_ENCRYPT, NIST_AESCCM_128_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_128_TEXT_DATA,
      NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_128_CIPHER, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_128_MAC,
      CC_TEE_FIPS_ERROR_AESCCM_PUT },
    { NIST_AESCCM_128_KEY, NIST_AESCCM_128_BIT_KEY_SIZE, NIST_AESCCM_128_NONCE, NIST_AESCCM_NONCE_SIZE,
      SASI_AES_DECRYPT, NIST_AESCCM_128_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_128_CIPHER,
      NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_128_TEXT_DATA, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_128_MAC,
      CC_TEE_FIPS_ERROR_AESCCM_PUT },
    { NIST_AESCCM_192_KEY, NIST_AESCCM_192_BIT_KEY_SIZE, NIST_AESCCM_192_NONCE, NIST_AESCCM_NONCE_SIZE,
      SASI_AES_ENCRYPT, NIST_AESCCM_192_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_192_TEXT_DATA,
      NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_192_CIPHER, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_192_MAC,
      CC_TEE_FIPS_ERROR_AESCCM_PUT },
    { NIST_AESCCM_192_KEY, NIST_AESCCM_192_BIT_KEY_SIZE, NIST_AESCCM_192_NONCE, NIST_AESCCM_NONCE_SIZE,
      SASI_AES_DECRYPT, NIST_AESCCM_192_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_192_CIPHER,
      NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_192_TEXT_DATA, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_192_MAC,
      CC_TEE_FIPS_ERROR_AESCCM_PUT },
    { NIST_AESCCM_256_KEY, NIST_AESCCM_256_BIT_KEY_SIZE, NIST_AESCCM_256_NONCE, NIST_AESCCM_NONCE_SIZE,
      SASI_AES_ENCRYPT, NIST_AESCCM_256_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_256_TEXT_DATA,
      NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_256_CIPHER, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_256_MAC,
      CC_TEE_FIPS_ERROR_AESCCM_PUT },
    { NIST_AESCCM_256_KEY, NIST_AESCCM_256_BIT_KEY_SIZE, NIST_AESCCM_256_NONCE, NIST_AESCCM_NONCE_SIZE,
      SASI_AES_DECRYPT, NIST_AESCCM_256_ADATA, NIST_AESCCM_ADATA_SIZE, NIST_AESCCM_256_CIPHER,
      NIST_AESCCM_TEXT_DATA_SIZE, NIST_AESCCM_256_TEXT_DATA, NIST_AESCCM_TAG_SIZE, NIST_AESCCM_256_MAC,
      CC_TEE_FIPS_ERROR_AESCCM_PUT },
};
#define FIPS_AESCCM_NUM_OF_TESTS (sizeof(FipsAesCcmDataTable) / sizeof(FipsAesCcmData))

static const FipsDesData FipsDesDataTable[] = {
    { { NIST_TDES_ECB3_KEY_1, NIST_TDES_ECB3_KEY_2, NIST_TDES_ECB3_KEY_3 },
      SaSi_DES_3_KeysInUse,
      NIST_TDES_ECB_IV,
      SaSi_DES_Encrypt,
      SaSi_DES_ECB_mode,
      NIST_TDES_ECB3_PLAIN_DATA,
      NIST_TDES_ECB3_CIPHER,
      NIST_TDES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_DES_ECB_PUT },
    { { NIST_TDES_ECB3_KEY_1, NIST_TDES_ECB3_KEY_2, NIST_TDES_ECB3_KEY_3 },
      SaSi_DES_3_KeysInUse,
      NIST_TDES_ECB_IV,
      SaSi_DES_Decrypt,
      SaSi_DES_ECB_mode,
      NIST_TDES_ECB3_CIPHER,
      NIST_TDES_ECB3_PLAIN_DATA,
      NIST_TDES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_DES_ECB_PUT },
    { { NIST_TDES_ECB2_KEY_1, NIST_TDES_ECB2_KEY_2, NIST_TDES_ECB2_KEY_1 },
      SaSi_DES_3_KeysInUse,
      NIST_TDES_ECB_IV,
      SaSi_DES_Encrypt,
      SaSi_DES_ECB_mode,
      NIST_TDES_ECB2_PLAIN_DATA,
      NIST_TDES_ECB2_CIPHER,
      NIST_TDES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_DES_ECB_PUT },
    { { NIST_TDES_ECB2_KEY_1, NIST_TDES_ECB2_KEY_2, NIST_TDES_ECB2_KEY_1 },
      SaSi_DES_3_KeysInUse,
      NIST_TDES_ECB_IV,
      SaSi_DES_Decrypt,
      SaSi_DES_ECB_mode,
      NIST_TDES_ECB2_CIPHER,
      NIST_TDES_ECB2_PLAIN_DATA,
      NIST_TDES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_DES_ECB_PUT },
    { { NIST_TDES_CBC3_KEY_1, NIST_TDES_CBC3_KEY_2, NIST_TDES_CBC3_KEY_3 },
      SaSi_DES_3_KeysInUse,
      NIST_TDES_CBC3_IV,
      SaSi_DES_Encrypt,
      SaSi_DES_CBC_mode,
      NIST_TDES_CBC3_PLAIN_DATA,
      NIST_TDES_CBC3_CIPHER,
      NIST_TDES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_DES_CBC_PUT },
    { { NIST_TDES_CBC3_KEY_1, NIST_TDES_CBC3_KEY_2, NIST_TDES_CBC3_KEY_3 },
      SaSi_DES_3_KeysInUse,
      NIST_TDES_CBC3_IV,
      SaSi_DES_Decrypt,
      SaSi_DES_CBC_mode,
      NIST_TDES_CBC3_CIPHER,
      NIST_TDES_CBC3_PLAIN_DATA,
      NIST_TDES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_DES_CBC_PUT },
    { { NIST_TDES_CBC2_KEY_1, NIST_TDES_CBC2_KEY_2, NIST_TDES_CBC2_KEY_1 },
      SaSi_DES_3_KeysInUse,
      NIST_TDES_CBC2_IV,
      SaSi_DES_Encrypt,
      SaSi_DES_CBC_mode,
      NIST_TDES_CBC2_PLAIN_DATA,
      NIST_TDES_CBC2_CIPHER,
      NIST_TDES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_DES_CBC_PUT },
    { { NIST_TDES_CBC2_KEY_1, NIST_TDES_CBC2_KEY_2, NIST_TDES_CBC2_KEY_1 },
      SaSi_DES_3_KeysInUse,
      NIST_TDES_CBC2_IV,
      SaSi_DES_Decrypt,
      SaSi_DES_CBC_mode,
      NIST_TDES_CBC2_CIPHER,
      NIST_TDES_CBC2_PLAIN_DATA,
      NIST_TDES_VECTOR_SIZE,
      CC_TEE_FIPS_ERROR_DES_CBC_PUT },
};
#define FIPS_DES_NUM_OF_TESTS (sizeof(FipsDesDataTable) / sizeof(FipsDesData))

static const FipsHashData FipsHashDataTable[] = {
    { SaSi_HASH_SHA1_mode, NIST_SHA_1_MSG, NIST_SHA_MSG_SIZE, NIST_SHA_1_MD, SaSi_HASH_SHA1_DIGEST_SIZE_IN_BYTES,
      CC_TEE_FIPS_ERROR_SHA1_PUT },
    { SaSi_HASH_SHA256_mode, NIST_SHA_256_MSG, NIST_SHA_MSG_SIZE, NIST_SHA_256_MD,
      SaSi_HASH_SHA256_DIGEST_SIZE_IN_BYTES, CC_TEE_FIPS_ERROR_SHA256_PUT },
    { SaSi_HASH_SHA512_mode, NIST_SHA_512_MSG, NIST_SHA_MSG_SIZE, NIST_SHA_512_MD,
      SaSi_HASH_SHA512_DIGEST_SIZE_IN_BYTES, CC_TEE_FIPS_ERROR_SHA512_PUT },
};
#define FIPS_HASH_NUM_OF_TESTS (sizeof(FipsHashDataTable) / sizeof(FipsHashData))

static const FipsHmacData FipsHmacDataTable[] = {
    { SaSi_HASH_SHA256_mode, NIST_HMAC_SHA256_KEY, NIST_HMAC_SHA256_KEY_SIZE, NIST_HMAC_SHA256_PLAIN_DATA,
      NIST_HMAC_SHA256_VECTOR_SIZE, NIST_HMAC_SHA256_MAC, NIST_HMAC_SHA256_OUTPUT_SIZE,
      CC_TEE_FIPS_ERROR_HMAC_SHA256_PUT },
};
#define FIPS_HMAC_NUM_OF_TESTS (sizeof(FipsHmacDataTable) / sizeof(FipsHmacData))

/* internal function prototypes */
static SaSiError_t FIPS_RunAes(uint8_t *pKey, uint32_t keySize, uint8_t *pIv, SaSiAesEncryptMode_t encMode,
                               SaSiAesOperationMode_t oprMode, uint8_t *dataIn, uint32_t dataInSize, uint8_t *dataOut);

static SaSi_AESCCM_KeySize_t FIPS_AesCcmToEnumKeySize(uint32_t keySize);

/* **** AES ************ */
CC_FipsError_t SaSi_FipsAesRunTests(void)
{
    SaSiError_t error    = SaSi_OK;
    FipsAesData *aesData = NULL;
    uint32_t i;
    uint8_t dataOutActual[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];

    for (i = 0; i < FIPS_AES_NUM_OF_TESTS; ++i) {
        aesData = (FipsAesData *)&FipsAesDataTable[i];
        error   = FIPS_RunAes(aesData->key, aesData->keySize, aesData->iv, aesData->encMode, aesData->oprMode,
                            aesData->dataIn, aesData->dataInSize, dataOutActual);
        if (error != SaSi_OK) {
            return aesData->error;
        }
        if (SaSi_PalMemCmp(dataOutActual, aesData->dataOut, aesData->dataOutSize) != 0) {
            return aesData->error;
        }
    }

    FipsSetTrace(CC_FIPS_TRACE_AES_PUT);

    return CC_TEE_FIPS_ERROR_OK;
}

static SaSiError_t FIPS_RunAes(uint8_t *pKey, uint32_t keySize, uint8_t *pIv, SaSiAesEncryptMode_t encMode,
                               SaSiAesOperationMode_t oprMode, uint8_t *dataIn, uint32_t dataInSize, uint8_t *dataOut)
{
    SaSiError_t error = SaSi_OK;

    SaSiAesUserContext_t aesContext;
    SaSiAesUserKeyData_t keyData;
    uint32_t dataOutSize = dataInSize;

    /* Encrypt (K,IV) by AES-CBC using output buff */
    error = SaSi_AesInit(&aesContext, encMode, oprMode, SASI_AES_PADDING_NONE);
    if (error != SaSi_OK) {
        return error;
    }

    keyData.pKey    = pKey;
    keyData.keySize = keySize;
    error           = SaSi_AesSetKey(&aesContext, SASI_AES_USER_KEY, (void *)&keyData, sizeof(keyData));
    if (error != SaSi_OK) {
        return error;
    }

    if (oprMode != SASI_AES_MODE_ECB && oprMode != SASI_AES_MODE_CMAC) {
        error = SaSi_AesSetIv(&aesContext, pIv);
        if (error != SaSi_OK) {
            return error;
        }
    }

    error = SaSi_AesFinish(&aesContext, dataInSize, dataIn /* in */, dataInSize, dataOut, /* out */
                           (size_t *)&dataOutSize);

    return error;
}

/* **** AES-CCM ************ */
CC_FipsError_t SaSi_FipsAesCcmRunTests(void)
{
    SaSiError_t error          = SaSi_OK;
    FipsAesCcmData *aesCcmData = NULL;
    uint32_t i;
    uint8_t dataOutActual[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];
    SaSi_AESCCM_Mac_Res_t macResActual;

    for (i = 0; i < FIPS_AESCCM_NUM_OF_TESTS; ++i) {
        aesCcmData = (FipsAesCcmData *)&FipsAesCcmDataTable[i];
        if (aesCcmData->encMode == SASI_AES_DECRYPT) {
            SaSi_PalMemCopy(macResActual, aesCcmData->macResOut, sizeof(SaSi_AESCCM_Mac_Res_t));
        }
        error = SaSi_AESCCM_MTK(aesCcmData->encMode, aesCcmData->key, FIPS_AesCcmToEnumKeySize(aesCcmData->keySize),
                                aesCcmData->nonce, aesCcmData->nonceSize, aesCcmData->AData, aesCcmData->ADataSize,
                                aesCcmData->textData, aesCcmData->textDataSize, dataOutActual, aesCcmData->tagSize,
                                macResActual);
        if (error != SaSi_OK) {
            return aesCcmData->error;
        }
        if (SaSi_PalMemCmp(dataOutActual, aesCcmData->textDataOut, aesCcmData->textDataSize) != 0) {
            return aesCcmData->error;
        }
        if (aesCcmData->encMode == SASI_AES_ENCRYPT &&
            SaSi_PalMemCmp(macResActual, aesCcmData->macResOut, sizeof(SaSi_AESCCM_Mac_Res_t)) != 0) {
            return aesCcmData->error;
        }
    }

    FipsSetTrace(CC_FIPS_TRACE_AESCCM_PUT);

    return CC_TEE_FIPS_ERROR_OK;
}

static SaSi_AESCCM_KeySize_t FIPS_AesCcmToEnumKeySize(uint32_t keySize)
{
    SaSi_AESCCM_KeySize_t AesCcmKeySize = SaSi_AES_KeySizeNumOfOptions;
    switch (keySize) {
    case NIST_AESCCM_128_BIT_KEY_SIZE:
        AesCcmKeySize = SaSi_AES_Key128BitSize;
        break;
    case NIST_AESCCM_192_BIT_KEY_SIZE:
        AesCcmKeySize = SaSi_AES_Key192BitSize;
        break;
    case NIST_AESCCM_256_BIT_KEY_SIZE:
        AesCcmKeySize = SaSi_AES_Key256BitSize;
        break;
    default:
        AesCcmKeySize = SaSi_AES_KeySizeNumOfOptions;
        break;
    }
    return AesCcmKeySize;
}

/* **** TDES ************ */
CC_FipsError_t SaSi_FipsDesRunTests(void)
{
    SaSiError_t error    = SaSi_OK;
    FipsDesData *desData = NULL;
    uint32_t i;
    uint8_t dataOutActual[FIPS_SYM_PUT_MAX_TEST_DATA_SIZE];

    for (i = 0; i < FIPS_DES_NUM_OF_TESTS; ++i) {
        desData = (FipsDesData *)&FipsDesDataTable[i];
        error   = SaSi_DES_MTK(desData->iv, &(desData->key), desData->numOfKeys, desData->encMode, desData->oprMode,
                             desData->dataIn, desData->dataInSize, dataOutActual);
        if (error != SaSi_OK) {
            return desData->error;
        }
        if (SaSi_PalMemCmp(dataOutActual, desData->dataOut, desData->dataInSize) != 0) {
            return desData->error;
        }
    }

    FipsSetTrace(CC_FIPS_TRACE_DES_PUT);

    return CC_TEE_FIPS_ERROR_OK;
}

/* **** HASH ************ */
CC_FipsError_t SaSi_FipsHashRunTests(void)
{
    SaSiError_t error      = SaSi_OK;
    FipsHashData *hashData = NULL;
    uint32_t i;
    SaSi_HASH_Result_t hashResultBuffActual;

    for (i = 0; i < FIPS_HASH_NUM_OF_TESTS; ++i) {
        hashData = (FipsHashData *)&FipsHashDataTable[i];
        error    = SaSi_HASH_MTK(hashData->oprMode, hashData->dataIn, hashData->dataInSize, hashResultBuffActual);
        if (error != SaSi_OK) {
            return hashData->error;
        }
        if (SaSi_PalMemCmp(hashResultBuffActual, hashData->HashResultBuff, hashData->HmacResultSize) != 0) {
            return hashData->error;
        }
    }

    FipsSetTrace(CC_FIPS_TRACE_HASH_PUT);

    return CC_TEE_FIPS_ERROR_OK;
}

/* **** HMAC ************ */
CC_FipsError_t SaSi_FipsHmacRunTests(void)
{
    SaSiError_t error      = SaSi_OK;
    FipsHmacData *hmacData = NULL;
    uint32_t i;
    SaSi_HASH_Result_t hmacResultBuffActual;

    for (i = 0; i < FIPS_HMAC_NUM_OF_TESTS; ++i) {
        hmacData = (FipsHmacData *)&FipsHmacDataTable[i];
        error    = SaSi_HMAC_MTK(hmacData->oprMode, hmacData->key, hmacData->keySize, hmacData->dataIn,
                              hmacData->dataInSize, hmacResultBuffActual);
        if (error != SaSi_OK) {
            return hmacData->error;
        }
        if (SaSi_PalMemCmp((uint8_t *)hmacResultBuffActual, hmacData->HmacResultBuff, hmacData->HmacResultSize) != 0) {
            return hmacData->error;
        }
    }

    FipsSetTrace(CC_FIPS_TRACE_HMAC_PUT);

    return CC_TEE_FIPS_ERROR_OK;
}
