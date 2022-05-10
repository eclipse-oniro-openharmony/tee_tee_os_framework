/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: swcrypto engine implementation
 * Create: 2022-03-30
 */
#ifndef EC_WRAPPER_H
#define EC_WRAPPER_H
struct ecc_derive_public_key_t {
    BIGNUM *priv_bn;
    EC_POINT *pub_pt;
    EC_GROUP *group;
    BIGNUM *x_bn;
    BIGNUM *y_bn;
    BN_CTX *ctx;
};

struct sign_pkcs10_t {
    EVP_PKEY *signing_key;
    EVP_PKEY *subject_pk;
    X509 *x;
    X509_NAME *subject_name;
    X509_NAME *issuer_name;
    BIGNUM *serial;
};

struct recover_root_cert_t {
    EVP_PKEY *pk;
    X509 *x;
    BIGNUM *serial;
    X509_NAME *name;
    uint8_t *orig;
};

struct derive_ecc_private_key_from_huk_t {
    BIGNUM *x;
    BIGNUM *ord;
    BN_CTX *ctx;
};
#endif

