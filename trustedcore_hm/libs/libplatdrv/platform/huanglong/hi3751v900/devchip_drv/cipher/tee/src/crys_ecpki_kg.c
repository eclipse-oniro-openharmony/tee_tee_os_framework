/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: for ecpki_kg
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "crys.h"
#include "crys_common_math.h"
#include "crys_ecpki_error.h"
#include "crys_ecpki_local.h"
#include "crys_cipher_common.h"
#include "drv_osal_lib.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"

#define OFFSET_31 31

extern int mbedtls_get_random(void *param, u8 *rand, size_t size);

/**
   @brief Generates a pair of private and public keys
          in little endian ordinary (non-Montgomery) form.

      This function generates a new key pair and initializes
      the variables and structures so that these can be used by other EC primitives.
      The function performs the following:
        1. Checks the validity of all of the function inputs. If one of the received
            parameters is not valid, it returns an error. The major checks are:
           - Whether domain_id is valid
           - Whether the user private key pointer(Userprivate_key) is not NULL
           - Whether the User Public Key pointer (Userpub_key) is not NULL
           - Whether the User passed temp data buffer is not NULL.
        2. Cleans buffers for private and public key structures.
        3. Calls the low level function  LLF_ECPKI_GenKeyPair.
        4. Outputs user public and private key structures in little endian form.
        5. Cleans temporary buffers.
        6. Exits.

   @param[in]  domain_id        - The enumerator variable defines current EC domain.
   @param[out] Userprivate_key - A pointer to the private key structure.
   @param[out] Userpub_key  - A pointer to the public key structure.
   @param[in]  TempData_ptr    - Temporary buffers of size defined in CRYS_ECPKI_KG_TempData_t.

   @return <b>CRYSError_t</b>: <br>
             CRYS_OK<br>
                         CRYS_ECPKI_GEN_KEY_ILLEGAL_D0MAIN_ID_ERROR<br>
             CRYS_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR<br>
             CRYS_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR<br>
             CRYS_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR<br>
 */
CEXPORT_C CRYSError_t CRYS_ECPKI_GenKeyPair(CRYS_ECPKI_DomainID_t domain_id, /* in */
                                            CRYS_ECPKI_UserPrivKey_t *Userprivate_key, /* out */
                                            CRYS_ECPKI_UserPublKey_t *Userpub_key, /* out */
                                            CRYS_ECPKI_KG_TempData_t *TempData_ptr)    /* in */
{
    CRYSError_t error;
    CRYS_ECPKI_PrivKey_t *private_key = HI_NULL;
    CRYS_ECPKI_PublKey_t *pub_key = HI_NULL;
    DxUint8_t *temp_buff = HI_NULL;
    DxUint32_t mod_size_in_byte;
    hi_u32 pad_len = 0;
    hi_u8 *key = HI_NULL;
    ecc_param_t ecc;

    /* ...... checking the validity of the user private key pointer .......... */
    if (Userprivate_key == DX_NULL) {
        hi_log_print_err_code(CRYS_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR);
        return CRYS_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR;
    }

    /* ...... checking the validity of the user public key pointer ........... */
    if (Userpub_key == DX_NULL) {
        hi_log_print_err_code(CRYS_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR);
        return CRYS_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR;
    }

    /* ...... checking the validity of temp buffers         .................. */
    if (TempData_ptr == DX_NULL) {
        hi_log_print_err_code(CRYS_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR);
        return CRYS_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR;
    }

    error = memset_s(Userprivate_key, sizeof(CRYS_ECPKI_UserPrivKey_t), 0, sizeof(CRYS_ECPKI_UserPrivKey_t));
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        goto End;
    }

    error = memset_s(Userpub_key, sizeof(CRYS_ECPKI_UserPublKey_t), 0, sizeof(CRYS_ECPKI_UserPublKey_t));
    if (error != 0) {
        hi_log_print_func_err(memset_s, error);
        goto End;
    }

    temp_buff = (hi_u8 *)TempData_ptr->crysKGIntBuff;
    pub_key = (CRYS_ECPKI_PublKey_t *)Userpub_key->PublKeyDbBuff;
    private_key = (CRYS_ECPKI_PrivKey_t *)Userprivate_key->PrivKeyDbBuff;
    private_key->DomainID = domain_id;
    pub_key->DomainID = domain_id;

    error = crys_ecp_load_group(domain_id, &ecc, &pad_len);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_ecp_load_group, error);
        goto End;
    }

    mod_size_in_byte = ecc.ksize;
    error = kapi_ecc_gen_key(&ecc, HI_NULL, (hi_u8*)pub_key->PublKeyX,  /* temporary store the private key */
        temp_buff, temp_buff + mod_size_in_byte);
    if (error != CRYS_OK) {
        hi_log_print_func_err(mbedtls_ecdh_gen_public, error);
        goto End;
    }

    key = (hi_u8*)pub_key->PublKeyX;
    error = crys_bin2bn(private_key->PrivKey, key + pad_len, mod_size_in_byte - pad_len);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_bin2bn, error);
        goto End;
    }

    error = crys_bin2bn(pub_key->PublKeyX, temp_buff + pad_len, mod_size_in_byte - pad_len);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_bin2bn, error);
        goto End;
    }

    error = crys_bin2bn(pub_key->PublKeyY, temp_buff + mod_size_in_byte + pad_len, mod_size_in_byte - pad_len);
    if (error != CRYS_OK) {
        hi_log_print_func_err(crys_bin2bn, error);
        goto End;
    }

    /* set the key valid tags */
    Userprivate_key->valid_tag = CRYS_ECPKI_PRIV_KEY_VALIDATION_TAG;
    Userpub_key->valid_tag = CRYS_ECPKI_PUBL_KEY_VALIDATION_TAG;
End:
    /* clear the KG data structure */
    (void)memset_s(TempData_ptr, sizeof(CRYS_ECPKI_KG_TempData_t), 0, sizeof(CRYS_ECPKI_KG_TempData_t));

    return error;
} /* END OF CRYS_ECPKI_GenKeyPair */
