/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include <stdbool.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <rsa/rsa_local.h>
#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <securec.h>
#include <tee_log.h>
#include "ec_wrapper.h"
#include "crypto_inner_interface.h"
#include "soft_common_api.h"

static unsigned char g_org_unit[] = "Consumer Business Group";
static unsigned char g_org[]      = "huawei";
static unsigned char g_country[]  = "CN";
static unsigned char g_common[]   = "hisi kirin 955";
static uint8_t g_root_serial[]    = { 0x10, 0x00 };

static int32_t ec_convert_swkey2boring(const void *priv, EVP_PKEY *pkey)
{
    int ret = -1;
    const ecc_priv_key_t *ecc_priv = (const ecc_priv_key_t *)priv;
    int ec_nid = ec_nid_tom2boringssl(ecc_priv->domain);
    if (ec_nid < 0) {
        tloge("soft_enine: %s\n", "get ec nid fail");
        return ret;
    }
    EC_POINT *ecc_pub_boring = NULL;
    BIGNUM *ecc_priv_boring  = BN_bin2bn(ecc_priv->r, ecc_priv->r_len, NULL);
    EC_GROUP *group          = EC_GROUP_new_by_curve_name(ec_nid);
    EC_KEY *ecc_key          = EC_KEY_new_by_curve_name(ec_nid);
    if (ecc_priv_boring == NULL || group == NULL || ecc_key == NULL) {
        tloge("ecc_priv_boring group ecc_key is null");
        goto ec_error;
    }
    ecc_pub_boring = EC_POINT_new(group);
    if (ecc_pub_boring == NULL) {
        tloge("ecc_pub_boring is null");
        goto ec_error;
    }
    /* Multiply ecc_pub_boring = ecc_priv_boring*G, where G is generator of group */
    if (EC_POINT_mul(group, ecc_pub_boring, ecc_priv_boring, NULL, NULL, NULL) != 1) {
        tloge("ecc_pub_boring is null");
        goto ec_error;
    }
    if (EC_KEY_set_private_key(ecc_key, ecc_priv_boring) != 1) {
        tloge("set private key fail");
        goto ec_error;
    }
    if (EC_KEY_set_public_key(ecc_key, ecc_pub_boring) != 1) {
        tloge("set public key fail");
        goto ec_error;
    }
    EC_KEY_set_asn1_flag(ecc_key, OPENSSL_EC_NAMED_CURVE);
    if (EVP_PKEY_assign_EC_KEY(pkey, ecc_key) == 0) {
        tloge("assign ec key fail");
        goto ec_error;
    }
    ret = 0;
    goto ec_ok;
ec_error:
    /* Free resources for key */
    EC_KEY_free(ecc_key);
ec_ok:
    BN_free(ecc_priv_boring);
    EC_GROUP_free(group);
    EC_POINT_free(ecc_pub_boring);
    return ret;
}

static int32_t rsa_convert_swkey2boring(const void *priv, EVP_PKEY *pkey)
{
    const rsa_priv_key_t *rsa_priv = (const rsa_priv_key_t *)priv;
    RSA *rsa                 = RSA_new();
    if (rsa == NULL) {
        tloge("soft_enine: %s\n", "new rsa key fail");
        return -1;
    }
    rsa->n     = BN_new();
    rsa->e     = BN_new();
    rsa->d     = BN_new();
    rsa->p     = BN_new();
    rsa->q     = BN_new();
    rsa->dmp1  = BN_new();
    rsa->dmq1  = BN_new();
    rsa->iqmp  = BN_new();
    bool check = (rsa->n == NULL || rsa->e == NULL || rsa->d == NULL || rsa->p == NULL || rsa->q == NULL ||
                  rsa->dmp1 == NULL || rsa->dmq1 == NULL || rsa->iqmp == NULL);
    if (check) {
        goto rsa_error;
    }
    (void)BN_bin2bn(rsa_priv->n, rsa_priv->n_len, rsa->n);
    (void)BN_bin2bn(rsa_priv->e, rsa_priv->e_len, rsa->e);
    (void)BN_bin2bn(rsa_priv->d, rsa_priv->d_len, rsa->d);
    /* If 1 CRT factor exist all must exist */
    if (rsa_priv->p_len > 0) {
        (void)BN_bin2bn(rsa_priv->p, rsa_priv->p_len, rsa->p);
        (void)BN_bin2bn(rsa_priv->q, rsa_priv->q_len, rsa->q);
        (void)BN_bin2bn(rsa_priv->dp, rsa_priv->dp_len, rsa->dmp1);
        (void)BN_bin2bn(rsa_priv->dq, rsa_priv->dq_len, rsa->dmq1);
        (void)BN_bin2bn(rsa_priv->qinv, rsa_priv->qinv_len, rsa->iqmp);
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) == 0) {
        tloge("assign rsa key fail");
        goto rsa_error;
    }
    return 0;
rsa_error:
    RSA_free(rsa);
    return -1;
}

static EVP_PKEY *convert_swkey2boring(const void *priv, uint32_t keytype)
{
    int32_t ret;
    if (priv == NULL) {
        tloge("soft_enine: %s\n", "convert swkey2boring input error");
        return NULL;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        tloge("soft_enine: %s\n", "new evp key fail");
        return NULL;
    }
    switch (keytype) {
    case ECC_ALG:
        ret = ec_convert_swkey2boring(priv, pkey);
        break;
    case RSA_ALG:
        ret = rsa_convert_swkey2boring(priv, pkey);
        break;
    default:
        ret = -1;
        break;
    }
    if (ret < 0) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

static int add_ext(X509 *cert, int nid, const char *value)
{
    X509_EXTENSION *ex = NULL;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (ex == NULL) {
        tloge("soft_enine: conf nid fail\n");
        return 0;
    }
    if (X509_add_ext(cert, ex, -1) == 0) {
        tloge("add ext failed");
        X509_EXTENSION_free(ex);
        return 0;
    }
    X509_EXTENSION_free(ex);
    return 1;
}

static int32_t creat_v3_extensions(int32_t ca_purpose, X509 *x)
{
    int32_t ret;
    if (ca_purpose != 0) {
        ret = add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
        if (ret != 1) {
            tloge("add ext critical fail");
            return ret;
        }
        ret = add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");
        if (ret != 1) {
            tloge("add ext key usage fail");
            return ret;
        }
    } else {
        ret = add_ext(x, NID_basic_constraints, "critical,CA:FALSE");
        if (ret != 1) {
            tloge("add ext critical fail");
            return ret;
        }
        ret = add_ext(x, NID_key_usage, "critical,digitalSignature");
        if (ret != 1) {
            tloge("add ext key usage fail");
            return ret;
        }
    }
    return ret;
}

static X509 *build_x509_cert(BIGNUM *serial, const validity_period_t *vd, X509_NAME *subject_name,
                             X509_NAME *issuer_name, EVP_PKEY *subject_pk, EVP_PKEY *signing_key, uint32_t ca_purpose)
{
    char tmp_start[VALIDITY_TIME_SIZE + 1] = { 0 };
    char tmp_end[VALIDITY_TIME_SIZE + 1] = { 0 };
    X509 *x = X509_new();
    if (x == NULL) {
        tloge("soft_enine: new x509 fail\n");
        return NULL;
    }

    /* add '\0' */
    (void)memcpy_s(tmp_start, VALIDITY_TIME_SIZE, vd->start, VALIDITY_TIME_SIZE);
    (void)memcpy_s(tmp_end, VALIDITY_TIME_SIZE, vd->end, VALIDITY_TIME_SIZE);

    ASN1_INTEGER *ser = BN_to_ASN1_INTEGER(serial, NULL);
    if (ser == NULL) {
        tloge("soft_enine: serial bn to asn1 integer fail\n");
        goto error;
    }
    char pub_k[CER_PUBLIC_KEY_MAX_LEN] = { 0 };
    bool check = (X509_set_serialNumber(x, ser) == 0 || X509_set_version(x, CRYPTO_NUMBER_TWO) == 0 ||
        ASN1_TIME_set_string(X509_get_notBefore(x), tmp_start) == 0 ||
        ASN1_TIME_set_string(X509_get_notAfter(x), tmp_end) == 0 ||
        i2d_PUBKEY(subject_pk, (unsigned char **)&pub_k) == 0 || X509_set_issuer_name(x, issuer_name) == 0 ||
        X509_set_pubkey(x, subject_pk) == 0 || X509_set_subject_name(x, subject_name) == 0);
    ASN1_STRING_free(ser);
    if (check) {
        tloge("x509 set error");
        goto error;
    }

    /* Create v3 extensions */
    int32_t ret = creat_v3_extensions(ca_purpose, x);
    if (ret != 1) {
        tloge("creat extensions fail");
        goto error;
    }
    ret = add_ext(x, NID_subject_key_identifier, "hash");
    if (ret != 1) {
        tloge("add ext 5 fail");
        goto error;
    }
    ret = X509_sign(x, signing_key, EVP_sha256());
    if (ret == 0) {
        tloge("soft_enine: %s\n", "x509 sign fail");
        goto error;
    }
    return x;
error:
    X509_free(x);
    return NULL;
}

static X509_NAME *new_dn(const dn_name_t *dn)
{
    int32_t ret;
    X509_NAME *name = NULL;
    name            = X509_NAME_new();
    if (name == NULL) {
        tloge("soft_enine: %s\n", "new name fail");
        return NULL;
    }
    ret = X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, dn->ou, -1, -1, 0);
    if (ret != 1) {
        tloge("add ou fail");
        goto error;
    }
    ret = X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, dn->o, -1, -1, 0);
    if (ret != 1) {
        tloge("add o fail");
        goto error;
    }
    ret = X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, dn->c, -1, -1, 0);
    if (ret != 1) {
        tloge("add c fail");
        goto error;
    }
    ret = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, dn->cn, -1, -1, 0);
    if (ret != 1) {
        tloge("add CN fail");
        goto error;
    }
    return name;
error:
    X509_NAME_free(name);
    return NULL;
}

static int32_t set_root_cert_info(struct recover_root_cert_t *root_cert, const void *priv, uint32_t keytype,
    const validity_period_t *valid)
{
    dn_name_t dn = {
        .ou = g_org_unit,
        .o = g_org,
        .c = g_country,
        .cn = g_common
    };
    root_cert->pk = convert_swkey2boring(priv, keytype);
    if (root_cert->pk == NULL) {
        tloge("soft_enine: %s\n", "convert swkey to boring fail");
        return -1;
    }
    root_cert->serial = BN_bin2bn(g_root_serial, sizeof(g_root_serial), NULL);
    if (root_cert->serial == NULL) {
        tloge("serial is null");
        EVP_PKEY_free(root_cert->pk);
        return -1;
    }

    root_cert->name = new_dn(&dn);
    if (root_cert->name == NULL) {
        EVP_PKEY_free(root_cert->pk);
        BN_free(root_cert->serial);
        return -1;
    }

    root_cert->x = build_x509_cert(root_cert->serial, valid, root_cert->name, root_cert->name, root_cert->pk,
        root_cert->pk, 1);
    if (root_cert->x == NULL) {
        tloge("x is null");
        EVP_PKEY_free(root_cert->pk);
        BN_free(root_cert->serial);
        X509_NAME_free(root_cert->name);
        return -1;
    }
    return 1;
}

int32_t recover_root_cert(uint8_t *cert, uint32_t cert_len, const void *priv, uint32_t keytype)
{
    const char *start_time  = "160101000000Z";
    const char *end_time    = "261231235959Z";
    validity_period_t valid = { { 0 }, { 0 } };
    int32_t tmp_len;
    struct recover_root_cert_t root_cert = {0};
    if (cert == NULL || priv == NULL)
        return -1;

    errno_t rc = memcpy_s(valid.start, VALIDITY_TIME_SIZE, start_time, strlen(start_time));
    if (rc != EOK) {
        tloge("soft_enine: %s\n", "mem cpy fail 1");
        return -1;
    }
    rc = memcpy_s(valid.end, VALIDITY_TIME_SIZE, end_time, strlen(end_time));
    if (rc != EOK) {
        tloge("soft_enine: %s\n", "mem cpy fail 2");
        return -1;
    }
    int32_t ret = set_root_cert_info(&root_cert, priv, keytype, &valid);
    if (ret != 1)
        return -1;
    tmp_len = i2d_X509(root_cert.x, NULL);
    if (tmp_len <= 0 || tmp_len > (int32_t)cert_len) {
        tloge("tmp_len is error");
        ret = -1;
        goto error;
    }
    root_cert.orig = cert;
    ret  = i2d_X509(root_cert.x, &(root_cert.orig));

error:
    if (root_cert.serial != NULL)
        BN_free(root_cert.serial);
    if (root_cert.name != NULL)
        X509_NAME_free(root_cert.name);
    EVP_PKEY_free(root_cert.pk);
    if (root_cert.x != NULL)
        X509_free(root_cert.x);
    return ret;
}

static int32_t set_pkcs_cert_info(struct sign_pkcs10_t *pkcs, X509_REQ *req, const void *priv, uint32_t keytype)
{
    dn_name_t dn = {
        .ou = g_org_unit,
        .o = g_org,
        .c = g_country,
        .cn = g_common
    };
    pkcs->subject_name = X509_REQ_get_subject_name(req);
    if (pkcs->subject_name == NULL) {
        tloge("sub ject name error");
        return -1;
    }

    pkcs->issuer_name = new_dn(&dn);
    if (pkcs->issuer_name == NULL) {
        tloge("issuer_name error");
        return -1;
    }

    pkcs->signing_key = convert_swkey2boring(priv, keytype);
    if (pkcs->signing_key == NULL) {
        tloge("signing_key error");
        X509_NAME_free(pkcs->issuer_name);
        pkcs->issuer_name = NULL;
        return -1;
    }

    /* Get subject public key from request */
    pkcs->subject_pk = X509_REQ_get_pubkey(req);
    if (pkcs->subject_pk == NULL) {
        tloge("subject_pk error");
        X509_NAME_free(pkcs->issuer_name);
        pkcs->issuer_name = NULL;
        EVP_PKEY_free(pkcs->signing_key);
        pkcs->signing_key = NULL;
        return -1;
    }
    return 1;
}

int32_t sign_pkcs10(uint8_t *cert, uint32_t cert_len, const uint8_t *csr, uint32_t csr_len,
    const validity_period_t *valid, const uint8_t *serial_number, uint32_t serial_length,
    const void *priv, uint32_t keytype)
{
    bool check =  (valid == NULL || serial_number == NULL || serial_length == 0 || priv == NULL);
    if (check) {
        printf("soft_enine: invalid params!");
        return -1;
    }
    struct sign_pkcs10_t pkcs = {0};
    int32_t ret;
    X509_REQ *req = d2i_X509_REQ(NULL, (const unsigned char **)&csr, csr_len);
    if (req == NULL) {
        tloge("soft_enine: %s\n", "d2i req fail");
        return -1;
    }
    ret = set_pkcs_cert_info(&pkcs, req, priv, keytype);
    if (ret != 1)
        goto error;

    pkcs.serial = BN_bin2bn(serial_number, serial_length, NULL);
    if (pkcs.serial == NULL) {
        tloge("serial error");
        ret = -1;
        goto error;
    }

    pkcs.x = build_x509_cert(pkcs.serial, valid, pkcs.subject_name, pkcs.issuer_name, pkcs.subject_pk,
        pkcs.signing_key, 0);
    if (pkcs.x == NULL) {
        tloge("x error");
        ret = -1;
        goto error;
    }

    if ((int)cert_len < i2d_X509(pkcs.x, NULL)) {
        tloge("cert_len error");
        ret = -1;
        goto error;
    }
    ret = i2d_X509(pkcs.x, &cert);

error:
    if (pkcs.x != NULL)
        X509_free(pkcs.x);
    if (pkcs.issuer_name != NULL)
        X509_NAME_free(pkcs.issuer_name);
    EVP_PKEY_free(pkcs.signing_key);
    BN_free(pkcs.serial);
    if (req != NULL)
        X509_REQ_free(req);
#ifdef OPENSSL_ENABLE
    free_openssl_drbg_mem();
#endif
    return ret;
}
