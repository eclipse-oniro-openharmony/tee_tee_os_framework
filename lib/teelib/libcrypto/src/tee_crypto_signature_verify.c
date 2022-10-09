/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: For signature verify
 * Author: yuanhao34@huawei.com
 * Create: 2021-07-31
 */

#include "tee_crypto_signature_verify.h"
#ifdef OPENSSL_ENABLE
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <evp/evp_local.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#endif
#include "ta_lib_img_unpack.h"
#include "tee_log.h"

uint32_t get_effective_size(const uint8_t *buff, uint32_t len)
{
    if (buff == NULL)
        return 0;

    while (len != 0) {
        if (buff[len - 1] == 0)
            len--;
        else
            break;
    }
    return len;
}

static void free_rsa_bn_n(BIGNUM *bn_n, BIGNUM *bn_e, BIGNUM *bn_d, BIGNUM *bn_p)
{
    BN_free(bn_n);
    BN_free(bn_p);
    BN_free(bn_e);
    BN_free(bn_d);
}

RSA *rsa_build_public_key(const rsa_pub_key_t *pub_key)
{
    if (pub_key == NULL)
        return NULL;

    BIGNUM *bn_n = BN_bin2bn(pub_key->n, get_effective_size(pub_key->n, pub_key->n_len), NULL);
    BIGNUM *bn_e = BN_bin2bn(pub_key->e, get_effective_size(pub_key->e, pub_key->e_len), NULL);
    if ((bn_n == NULL) || (bn_e == NULL)) {
        tloge("Change pub buffer num to big num failed\n");
        free_rsa_bn_n(bn_n, bn_e, NULL, NULL);
        return NULL;
    }
    RSA *rsa_key = RSA_new();
    if (rsa_key == NULL) {
        tloge("Malloc memory for rsa key failed\n");
        free_rsa_bn_n(bn_n, bn_e, NULL, NULL);
        return NULL;
    }
    int32_t ret = RSA_set0_key(rsa_key, bn_n, bn_e, NULL);
    if (ret != 1) {
        tloge("Set rsa key failed\n");
        free_rsa_bn_n(bn_n, bn_e, NULL, NULL);
        RSA_free(rsa_key);
        return NULL;
    }
    return rsa_key;
}

/* Process steps:
 * 1, Get public key,
 * 2, Verify the signature using the public key,
 */
TEE_Result tee_secure_img_release_verify(const uint8_t *hash, uint32_t hash_size, const uint8_t *signature,
    uint32_t signature_size, RSA *pub_key)
{
    bool check = (hash == NULL || signature == NULL || signature_size == 0 || hash_size == 0);
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    if (pub_key == NULL) {
        tloge("get public key fail");
        return TEE_ERROR_GENERIC;
    }
    /* the sign len should equals rsa pub key's n size */
    uint32_t modulus_size = RSA_size(pub_key);
    if (signature_size < modulus_size) {
        tloge("Invalid signature size: 0x%x\n", signature_size);
        RSA_free(pub_key);
        pub_key = NULL;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t result = RSA_verify(NID_sha256, hash, RSA_DIGEST_LEN, signature, signature_size, pub_key);
    RSA_free(pub_key);
    pub_key = NULL;

    /* GCC complain about pragma optimize */
    if (result != 1) {
        tloge("signature VerifyDigest fail\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

