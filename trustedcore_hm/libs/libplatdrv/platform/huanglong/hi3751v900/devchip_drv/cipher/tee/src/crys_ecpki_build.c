/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: ecpki build
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "crys.h"
#include "crys_common.h"
#include "crys_common_math.h"
#include "crys_cipher_common.h"
#include "crys_ecpki_error.h"
#include "crys_ecpki_local.h"
#include "mbedtls/ecdsa.h"

#define NUM_2 2
#define NUM_3 3
#define OFFSET_7 7
#define BYTE_BIT_WIDTH 8

/**********************************************************************************
 *                    CRYS_ECPKI_BuildPrivKey function                            *
 **********************************************************************************/
/* !\brief Builds (imports) the user private key structure from an existing
            private key so that this structure can be used by other EC
            primitives.

            When operating the EC cryptographic operations with existing and saved
            EC private keys, this function should be called first.

            The function performs the following operations:
              - Checks validity of incoming variables and pointers.
              - Checks, that 0 < PrivKey < r (r - EC generator order).
              - Converts incoming key data from big endian into little endian form.
              - Initializes variables and structures.

   @param[in]  domain_id           The enumerator variable defines current EC domain.
   @param[in]  PrivKeyIn_ptr      Pointer to private key data.
   @param[in]  PrivKeySizeInBytes Size of private key data in bytes. Must be great than null and
                                  less or equall to EC order_size_in_bytes.
   @param[out] Userprivate_key    Pointer to the private key structure.
                                  This structure is used as input to the ECPKI
                                  cryptographic primitives.
   @return   CRYSError_t:
            CRYS_OK
            CRYS_ECPKI_BUILD_KEY_INVALID_PRIV_KEY_IN_PTR_ERROR
            CRYS_ECPKI_BUILD_KEY_INVALID_USER_PRIV_KEY_PTR_ERROR
            CRYS_ECPKI_BUILD_KEY_ILLEGAL_DOMAIN_ID_ERROR
 */
CEXPORT_C CRYSError_t CRYS_ECPKI_BuildPrivKey(CRYS_ECPKI_DomainID_t domain_id, /* in */
                                              DxUint8_t *PrivKeyIn_ptr,      /* in */
                                              DxUint32_t PrivKeySizeInBytes, /* in */
                                              CRYS_ECPKI_UserPrivKey_t *Userprivate_key /* out */)
{
    CRYS_ECPKI_PrivKey_t *priv_key_db = HI_NULL;
    DxUint32_t order_size_in_bytes;
    CRYSError_t error;
    ecc_param_t ecc;
    hi_u32 pad_len = 0;

    /* ...... checking the key database handle pointer .................... */
    if (PrivKeyIn_ptr == DX_NULL) {
        return CRYS_ECPKI_BUILD_KEY_INVALID_PRIV_KEY_IN_PTR_ERROR;
    }

    /* ...... checking the validity of the User Private Key pointer ........... */
    if (Userprivate_key == DX_NULL) {
        return CRYS_ECPKI_BUILD_KEY_INVALID_USER_PRIV_KEY_PTR_ERROR;
    }

    error = crys_ecp_load_group(domain_id, &ecc, &pad_len);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_ecp_load_group, error);
        return CRYS_ECPKI_BUILD_KEY_ILLEGAL_DOMAIN_ID_ERROR;
    }

    /* EC order size in bytes */
    order_size_in_bytes = ecc.ksize - pad_len;

    if (PrivKeySizeInBytes == 0 || PrivKeySizeInBytes > order_size_in_bytes) {
        return CRYS_ECPKI_BUILD_KEY_INVALID_PRIV_KEY_SIZE_ERROR;
    }

    /* setting the pointer to the key database */
    priv_key_db = (CRYS_ECPKI_PrivKey_t *)((void *)Userprivate_key->PrivKeyDbBuff);

    /* clear the private key db */
    error = memset_s(Userprivate_key, sizeof(CRYS_ECPKI_UserPrivKey_t), 0, sizeof(CRYS_ECPKI_UserPrivKey_t));
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        return error;
    }

    /* loading the private key db to little endian and domain ID */
    error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(priv_key_db->PrivKey, sizeof(priv_key_db->PrivKey),
                                                        PrivKeyIn_ptr, PrivKeySizeInBytes);
    if (error != CRYS_OK) {
        return error;
    }

    priv_key_db->DomainID = domain_id;
    Userprivate_key->valid_tag = CRYS_ECPKI_PRIV_KEY_VALIDATION_TAG;

    return CRYS_OK;
} /* End of CRYS_ECPKI_BuildPrivKey() */

/**********************************************************************************
 *                  _DX_ECPKI_BuildPublKey function                                *
 **********************************************************************************/
/**
   @brief The _DX_ECPKI_BuildPublKey function checks the validity and builds the user public
          key structure from imported public key data for using  it in other ECC primitives.

    When operating the EC cryptographic algorithms with imported EC public
    key, this function should be called before using of the public key.

    The user must call this function by appropriate macros, according to necessary
    validation level [SEC1. ECC standard: 3.2]:
    - full checking of public key - CRYS_ECPKI_BuildPublKeyFullCheck,
    - partly checking of public key - CRYS_ECPKI_BuildPublKeyPartCheck,
    - checking the input pointers and sizes only - CRYS_ECPKI_BuildPublKey.

    The function performs the following operations:
    - Checks validity of incoming variables and pointers;
    - Converts incoming key data from big endian into little endian as follows:
      If public key is given in uncompressed form the function converts
      coordinates X and Y separately to words arrays with little endian order of
      the wordsand copies them in output buffer, else returns an error;
    -   according to CheckMode parameter performs full or partly checking of public
        key validaty by calling the LLF function.
    -   Initializes variables and structures.

    Incoming public key PublKeyIn is given in big endianness as butes array, containing
    concatenation PC||X||Y, where:
        PC - point control single byte, defining the type of point: 0x4 - uncompressed,
             other types not supported.
        X,Y - EC point coordinates of public key,  size of X and Y equal to size of EC modulus,
              Size of buffers for X and also Y must be equal mod_size_in_bytes.

   @param[in]  ECPKI_DomainID  - The enumerator variable defines current EC domain.
   @param[in]  PublKeyIn_ptr   - The pointer to private key data.
   @param[in]  PublKeySizeInBytes - Size of private key data in bytes 2*modulusSize + 1byte.
   @param[in]  CheckMode       - The parameter defining what checking of public key is necessary:
                                 preliminary check - 0, partly check - 1, full check - 2 .
   @param[out] Userpub_key - A pointer to the private key structure.
   @param[in]  temp_buff    - A pointer to the temp buffer structure for build function.

   @return CRYSError_t - CRYS_OK,
            CRYS_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_IN_PTR_ERROR
            CRYS_ECPKI_BUILD_KEY_INVALID_USER_PUBL_KEY_PTR_ERROR
            CRYS_ECPKI_BUILD_KEY_ILLEGAL_DOMAIN_ID_ERROR
            CRYS_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_DATA_ERROR
            CRYS_ECPKI_BUILD_KEY_INVALID_COMPRESSION_MODE_ERROR
 */
CEXPORT_C CRYSError_t _DX_ECPKI_BuildPublKey(CRYS_ECPKI_DomainID_t domain_id, /* in */
                                             DxUint8_t *PublKeyIn_ptr,        /* in */
                                             DxUint32_t PublKeySizeInBytes,   /* in */
                                             EC_PublKeyCheckMode_t CheckMode, /* in */
                                             CRYS_ECPKI_UserPublKey_t *Userpub_key, /* out */
                                             CRYS_ECPKI_BUILD_TempData_t *temp_buff /* in */)
{
    CRYS_ECPKI_PublKey_t *pub_key = HI_NULL;
    DxUint32_t mod_size_in_bytes;
    DxUint8_t pc;
    DxUint8_t pc1;
    CRYSError_t error;
    ecc_param_t ecc;
    hi_u32 pad_len = 0;

    /* ...... checking the validity of the User Private Key pointer ......... */
    if (Userpub_key == DX_NULL) {
        return CRYS_ECPKI_BUILD_KEY_INVALID_USER_PUBL_KEY_PTR_ERROR;
    }

    /* ...... checking the key database handle pointer .................... */
    if (PublKeyIn_ptr == DX_NULL) {
        return CRYS_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_IN_PTR_ERROR;
    }

    /* ...... checking the EC domain ID.................... */
    if (domain_id >= CRYS_ECPKI_DomainID_OffMode) {
        return CRYS_ECPKI_BUILD_KEY_ILLEGAL_DOMAIN_ID_ERROR;
    }

    if (CheckMode >= PublKeyChecingOffMode) {
        return CRYS_ECPKI_BUILD_KEY_INVALID_CHECK_MODE_ERROR;
    }

    if (CheckMode != CheckPointersAndSizesOnly && temp_buff == DX_NULL) {
        return CRYS_ECPKI_BUILD_KEY_INVALID_TEMP_BUFF_PTR_ERROR;
    }

    error = crys_ecp_load_group(domain_id, &ecc, &pad_len);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_ecp_load_group, error);
        return CRYS_ECPKI_BUILD_KEY_ILLEGAL_DOMAIN_ID_ERROR;
    }

    /* EC order size in bytes */
    mod_size_in_bytes = ecc.ksize - pad_len;

    /* point control */
    pc = PublKeyIn_ptr[0];
    pc1 = pc & 0x6;

    /* preliminary check key size */
    if (PublKeySizeInBytes != 2 * mod_size_in_bytes + 1) { /* key size is 2 times of mode size */
        return CRYS_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_SIZE_ERROR;
    }

    /* setting the pointer to the key database */
    pub_key = (CRYS_ECPKI_PublKey_t *)((void *)Userpub_key->PublKeyDbBuff);

    /* clear the public key db */
    error = memset_s((DxUint8_t *)Userpub_key, sizeof(CRYS_ECPKI_UserPublKey_t), 0,
                     sizeof(CRYS_ECPKI_UserPublKey_t));
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        return error;
    }

    /* Set domain_id into Builded public key */
    pub_key->DomainID = domain_id;

    if (pc1 == CRYS_EC_PointUncompressed || pc1 == CRYS_EC_PointHybrid) { /* descript: pc1 = 4 or pc1 = 6 */
        /* Reverse mem copy public key Xin to X, Yin to Y */
        error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(pub_key->PublKeyX, sizeof(pub_key->PublKeyX),
            PublKeyIn_ptr + 1, mod_size_in_bytes);
        if (error != CRYS_OK) {
            return error;
        }

        error = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(pub_key->PublKeyY, sizeof(pub_key->PublKeyY),
            PublKeyIn_ptr + 1 + mod_size_in_bytes, mod_size_in_bytes);
        if (error != CRYS_OK) {
            return error;
        }
    } else {
        return CRYS_ECPKI_BUILD_KEY_INVALID_COMPRESSION_MODE_ERROR;
    }

    /* ................ set the private key validation tag ................... */
    Userpub_key->valid_tag = CRYS_ECPKI_PUBL_KEY_VALIDATION_TAG;

    return CRYS_OK;
} /* End of _DX_ECPKI_BuildPublKey() */

/***********************************************************************************
  *                     CRYS_ECPKI_ExportPublKey function                           *
  ***********************************************************************************/
/**
   @brief The function converts an existed public key into the big endian and outputs it.

          The function performs the following steps:
          - checks input parameters,
          - Converts the X,Y coordinates of public key EC point to big endianness.
          - Sets the public key as follows:
               In case "Uncompressed" point:  PubKey = PC||X||Y, PC = 0x4 - single byte;
                   In other cases returns an error.
          - Exits.

              NOTE: - At this stage supported only uncompressed point form,
                - Size of output X and Y coordinates is equal to mod_size_in_bytes.

   @param[in]  Userpub_key -   A pointer to the public key structure initialized by CRYS.
   @param[in]  Compression     -   An enumerator parameter, defines point compression.
   @param[out] Externpub_key - A pointer to the buffer for export the public key bytes array in big
                                   endian order of bytes. Size of buffer must be not less than:
                   2*ModSiseInBytes+1 bytes.
   @param[in/out] PublKeySizeInBytes - A pointer to size of user passed public key buffer (in) and
                   the actual size of exported public key (out).

   @return CRYSError_t - CRYS_OK,
                         CRYS_ECPKI_EXPORT_PUBL_KEY_INVALID_USER_PUBL_KEY_PTR_ERROR
                         CRYS_ECPKI_EXPORT_PUBL_KEY_ILLEGAL_COMPRESSION_MODE_ERROR
                         CRYS_ECPKI_EXPORT_PUBL_KEY_INVALID_EXTERN_PUBL_KEY_PTR_ERROR
                         CRYS_ECPKI_EXPORT_PUBL_KEY_INVALID_PUBL_KEY_SIZE_PTR_ERROR
                         CRYS_ECPKI_EXPORT_PUBL_KEY_INVALID_PUBL_KEY_SIZE_ERROR
                         CRYS_ECPKI_EXPORT_PUBL_KEY_ILLEGAL_DOMAIN_ID_ERROR
 */
CEXPORT_C CRYSError_t CRYS_ECPKI_ExportPublKey(CRYS_ECPKI_UserPublKey_t *Userpub_key, /* in */
                                               CRYS_ECPKI_PointCompression_t Compression, /* in */
                                               DxUint8_t *Externpub_key, /* in */
                                               DxUint32_t *PublKeySizeInBytes_ptr /* in/out */)
{
    CRYS_ECPKI_PublKey_t *pub_key = HI_NULL;
    CRYS_ECPKI_DomainID_t domain_id;
    DxUint32_t mod_size_in_bytes;
    CRYSError_t error;
    ecc_param_t ecc;
    hi_u32 pad_len = 0;

    /* ...... checking the key database handle pointer .................... */
    if (Userpub_key == DX_NULL) {
        return CRYS_ECPKI_EXPORT_PUBL_KEY_INVALID_USER_PUBL_KEY_PTR_ERROR;
    }

    /* ...... checking the validity of the extern Public Key pointer ........ */
    if (Externpub_key == DX_NULL) {
        return CRYS_ECPKI_EXPORT_PUBL_KEY_INVALID_EXTERN_PUBL_KEY_PTR_ERROR;
    }

    /* ... checking the validity of the extern Public Key size pointer ...... */
    if (PublKeySizeInBytes_ptr == DX_NULL) {
        return CRYS_ECPKI_EXPORT_PUBL_KEY_INVALID_PUBL_KEY_SIZE_PTR_ERROR;
    }

    pub_key = (CRYS_ECPKI_PublKey_t *)((void *)Userpub_key->PublKeyDbBuff);
    domain_id = pub_key->DomainID;

    /* ...... checking the EC domain ID...................................... */
    if (domain_id >= CRYS_ECPKI_DomainID_OffMode) {
        return CRYS_ECPKI_EXPORT_PUBL_KEY_ILLEGAL_DOMAIN_ID_ERROR;
    }

    error = crys_ecp_load_group(domain_id, &ecc, &pad_len);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_ecp_load_group, error);
        return CRYS_ECPKI_BUILD_KEY_ILLEGAL_DOMAIN_ID_ERROR;
    }

    /* EC order size in bytes */
    mod_size_in_bytes = ecc.ksize - pad_len;

    /* Convert public key to big endianness export form */
    switch (Compression) {
        case CRYS_EC_PointUncompressed:
            /* check uzer passed size of buffer for public key */
            if (*PublKeySizeInBytes_ptr < 2 * mod_size_in_bytes + 1) { /* key size is 2 times of mode size */
                return CRYS_ECPKI_EXPORT_PUBL_KEY_INVALID_PUBL_KEY_SIZE_ERROR;
            }

            Externpub_key[0] = 4; /* PC is 4 */

            error = CRYS_COMMON_ConvertLswMswWordsToMsbLsbBytes(Externpub_key + 1,
                WORD_WIDTH * ((mod_size_in_bytes + NUM_3) / WORD_WIDTH),
                pub_key->PublKeyX, mod_size_in_bytes);
            if (error != CRYS_OK) {
                return error;
            }
            error = CRYS_COMMON_ConvertLswMswWordsToMsbLsbBytes(Externpub_key + 1 + mod_size_in_bytes,
                WORD_WIDTH * ((mod_size_in_bytes + NUM_3) / WORD_WIDTH),
                pub_key->PublKeyY, mod_size_in_bytes);
            if (error != CRYS_OK) {
                return error;
            }

            /* Set PublKeySizeInBytes */
            *PublKeySizeInBytes_ptr = NUM_2 * mod_size_in_bytes + 1;
            break;

        case CRYS_EC_PointHybrid:
        case CRYS_EC_PointCompressed:
        case CRYS_EC_PointContWrong:
        case CRYS_EC_PointCompresOffMode:
        default:

            return CRYS_ECPKI_EXPORT_PUBL_KEY_ILLEGAL_COMPRESSION_MODE_ERROR;
    }

    return CRYS_OK;
} /* End of CRYS_ECPKI_ExportPublKey */


