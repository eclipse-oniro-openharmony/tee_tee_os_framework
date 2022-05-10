/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: extension certification api
 * Create: 2020-06-08
 */
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <rsa/rsa_local.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_ext_api.h>
#include <tee_private_api.h>
#include <tee_property_inner.h>
#include <tee_trusted_storage_api.h>
#include <crypto_ext_api.h>
#include "crypto_inner_interface.h"

#define EXT_RET_ERROR            (-1)
#define EXT_RET_SUCCESS          0

#define ONE_BYTE_BIT_COUNT       8
#define RSA_2048_KEY_BIT_SIZE    2048
#define RSA_4096_KEY_BIT_SIZE    4096
#define RSA_2048_KEY_BYTE_SIZE   (RSA_2048_KEY_BIT_SIZE / ONE_BYTE_BIT_COUNT)
#define RSA_4096_KEY_BYTE_SIZE   (RSA_4096_KEY_BIT_SIZE / ONE_BYTE_BIT_COUNT)
#define KEY_SIZE_MAX             32
#define BLOCK_SIZE_MAX           0x7F000
#define DERIVED_KEY_SIZE         32
#define SHA256_BYTE_SIZE         32
#define DOUBLE_OPERATION         2
#define AES_CRYPTO_IV_SIZE       16

#define RSA_KEY_ELEMENT_COUNT    3 /* include e d n */
#define KEY_MODULUS_INDEX        0
#define KEY_PRI_EXPONENT_INDEX   1
#define KEY_PUB_EXPONENT_INDEX   2

#define UUID_DRIVE_KEY_SIZE      64
#define KEY_DERIVE_BLOCK_SIZE    16
#define LOOP_COUNT_FOR_ROOT_KEY  3
#define HALF_BYTE_SIZE           4

#define KEY_SALT                 "salt for ecc device key"

#define PERSISTENT_KEY_MAIN      1
#define PERSISTENT_KEY_BACKUP    2
#define INSE_CRYPTO_SRC_LEN      64
#define INSE_CRYPTO_DEST_LEN     32
#define KEY_SIZE_FOR_CERT        32
#define PUB_KEY_SUBJECT_SIZE     300
#define SSL_LIB_OP_SUCC          1
#define EMPTY_LEN                0
#define SECRET_KEY_ATTR_COUNT    1
#define X509_LASTPOS_VALUE       (-1)
#define X509_SET_VALUE           0
#define HALF_BYTE_LOW_MASK       0x0F
#define DEVICE_UNIQUE_ID_STR_LEN (SHA256_BYTE_SIZE * DOUBLE_OPERATION + 1)
#define DEVICE_ROOT_FLAG         1
#define ECC_DRIVE_KEY_FAIL       (-1)
#define UC_CORE_ID               0
#define UC_CHANNEL_ID            1
#define HALF_BYTE_MAX            17

#define PERSISTENT_KEY_ID        "sec_storage/authentication/id_rsa_2048_pair"
#define PERSISTENT_BACKUP_KEY_ID "sec_storage/authentication/id_rsa_2048_pair_bak"

#define HALF_BYTE_HIGH(x)        ((uint8_t)(x) >> HALF_BYTE_SIZE)
#define HALF_BYTE_LOW(x)         ((uint8_t)(x) & HALF_BYTE_LOW_MASK)

static const uint8_t g_key_salt[] = KEY_SALT;

static TEE_Result get_ecc_public_key(const uint8_t *priv, uint32_t priv_len, uint32_t nid, BIGNUM **priv_bn,
                                     EC_POINT **ecc_pub)
{
    BN_CTX *ctx = NULL;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        tloge("group is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        tloge("ctx is NULL\n");
        goto error;
    }

    *ecc_pub = EC_POINT_new(group);
    if (*ecc_pub == NULL) {
        tloge("ecc_pub is NULL\n");
        goto error;
    }

    *priv_bn = BN_bin2bn(priv, priv_len, NULL);
    if (*priv_bn == NULL) {
        tloge("priv_bn is NULL\n");
        goto error;
    }

    if (EC_POINT_mul(group, *ecc_pub, *priv_bn, NULL, NULL, ctx) != SSL_LIB_OP_SUCC) {
        tloge("ec mul failed\n");
        goto error;
    }

    BN_CTX_free(ctx);
    ctx = NULL;
    EC_GROUP_free(group);
    return TEE_SUCCESS;

error:
    BN_CTX_free(ctx);
    ctx = NULL;
    EC_POINT_free(*ecc_pub);
    *ecc_pub = NULL;
    BN_free(*priv_bn);
    *priv_bn = NULL;
    EC_GROUP_free(group);
    return TEE_ERROR_GENERIC;
}

static EVP_PKEY *ecc_bin_to_pkey(const uint8_t *priv, uint32_t priv_len, uint32_t nid)
{
    EC_KEY *ecc_key = NULL;
    BIGNUM *priv_bn = NULL;
    EC_POINT *ecc_pub = NULL;
    EVP_PKEY *pkey = NULL;

    if (get_ecc_public_key(priv, priv_len, nid, &priv_bn, &ecc_pub) != TEE_SUCCESS) {
        tloge("get ecc pub key failed\n");
        return NULL;
    }

    ecc_key = EC_KEY_new_by_curve_name(nid);
    if (ecc_key == NULL) {
        tloge("ecc_key is NULL\n");
        goto error;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        tloge("pkey is NULL\n");
        goto error;
    }

    if (EC_KEY_set_private_key(ecc_key, priv_bn) != SSL_LIB_OP_SUCC) {
        tloge("ec set priv key failed\n");
        goto error;
    }

    if (EC_KEY_set_public_key(ecc_key, ecc_pub) != SSL_LIB_OP_SUCC) {
        tloge("ec set pub key failed\n");
        goto error;
    }

    EC_KEY_set_asn1_flag(ecc_key, OPENSSL_EC_NAMED_CURVE);
    if (EVP_PKEY_assign_EC_KEY(pkey, ecc_key) != SSL_LIB_OP_SUCC) {
        tloge("ec assign pkey failed\n");
        goto error;
    }
    goto success;

error:
    /* boringssl API will judge if pointer is NULL */
    EC_KEY_free(ecc_key);
    ecc_key = NULL;
    EVP_PKEY_free(pkey);
    pkey = NULL;
success:
    EC_POINT_free(ecc_pub);
    ecc_pub = NULL;
    BN_free(priv_bn);
    return pkey;
}

static RSA *rsa_create(void)
{
    RSA *rsa = RSA_new();
    if (rsa == NULL)
        return NULL;

    rsa->n = BN_new();
    rsa->e = BN_new();
    rsa->d = BN_new();
    rsa->p = BN_new();
    rsa->q = BN_new();
    rsa->dmp1 = BN_new();
    rsa->dmq1 = BN_new();
    rsa->iqmp = BN_new();
    bool check_flag = ((rsa->n == NULL) || (rsa->e == NULL) || (rsa->d == NULL) || (rsa->p == NULL) ||
                       (rsa->q == NULL) || (rsa->dmp1 == NULL) || (rsa->dmq1 == NULL) || (rsa->iqmp == NULL));
    if (check_flag) {
        tloge("alloc rsa keys failed\n");
        RSA_free(rsa);
        return NULL;
    }

    return rsa;
}

static EVP_PKEY *rsa_bin_to_pkey(const rsa_priv_key_t *rsa_priv)
{
    RSA *rsa = rsa_create();
    EVP_PKEY *pkey = EVP_PKEY_new();

    bool check = ((rsa == NULL) || (pkey == NULL) || (rsa_priv == NULL));
    if (check)
        goto error;

    check = ((BN_bin2bn(rsa_priv->n, rsa_priv->n_len, rsa->n) == NULL) ||
        (BN_bin2bn(rsa_priv->e, rsa_priv->e_len, rsa->e) == NULL) ||
        (BN_bin2bn(rsa_priv->d, rsa_priv->d_len, rsa->d) == NULL));
    if (check) {
        tloge("bin to bn operation failed\n");
        goto error;
    }

    /* If 1 CRT factor exist all must exist */
    if (rsa_priv->p_len > 0) {
        check = ((BN_bin2bn(rsa_priv->p, rsa_priv->p_len, rsa->p) == NULL) ||
            (BN_bin2bn(rsa_priv->q, rsa_priv->q_len, rsa->q) == NULL) ||
            (BN_bin2bn(rsa_priv->dp, rsa_priv->dp_len, rsa->dmp1) == NULL) ||
            (BN_bin2bn(rsa_priv->dq, rsa_priv->dq_len, rsa->dmq1) == NULL) ||
            (BN_bin2bn(rsa_priv->qinv, rsa_priv->qinv_len, rsa->iqmp) == NULL));
        if (check) {
            tloge("bin to bn operation failed\n");
            goto error;
        }
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) == EXT_RET_SUCCESS) {
        tloge("pkey assign rsa failed\n");
        goto error;
    }

    return pkey;
error:
    RSA_free(rsa);
    rsa = NULL;
    EVP_PKEY_free(pkey);

    return NULL;
}

/* device cert fields's descriptions */
struct x509_dn {
    const char *field;
    const char *name;
};

struct device_cert_dn {
    struct x509_dn c;  /* country */
    struct x509_dn o;  /* org */
    struct x509_dn ou; /* org_unit */
    struct x509_dn cn; /* common */
} g_device_cert_dn = { { "C", "CN" }, { "O", "huawei" }, { "OU", "Consumer Business Group" }, { "CN", NULL } };

static bool x509_name_add_entry(X509_NAME *x_name, const char *name, uint32_t name_len)
{
    bool check = (
        (X509_NAME_add_entry_by_txt(x_name, g_device_cert_dn.c.field, MBSTRING_ASC,
                                    (unsigned char *)g_device_cert_dn.c.name, strlen(g_device_cert_dn.c.name),
                                    X509_LASTPOS_VALUE, X509_SET_VALUE) != SSL_LIB_OP_SUCC) ||
        (X509_NAME_add_entry_by_txt(x_name, g_device_cert_dn.o.field, MBSTRING_ASC,
                                    (unsigned char *)g_device_cert_dn.o.name, strlen(g_device_cert_dn.o.name),
                                    X509_LASTPOS_VALUE, X509_SET_VALUE) != SSL_LIB_OP_SUCC) ||
        (X509_NAME_add_entry_by_txt(x_name, g_device_cert_dn.ou.field, MBSTRING_ASC,
                                    (unsigned char *)g_device_cert_dn.ou.name, strlen(g_device_cert_dn.ou.name),
                                    X509_LASTPOS_VALUE, X509_SET_VALUE) != SSL_LIB_OP_SUCC) ||
        (X509_NAME_add_entry_by_txt(x_name, g_device_cert_dn.cn.field, MBSTRING_ASC, (unsigned char *)name, name_len,
                                    X509_LASTPOS_VALUE, X509_SET_VALUE) != SSL_LIB_OP_SUCC));
    if  (check) {
        tloge("x509 add entry name fail\n");
        return false;
    }

    return true;
}

static int create_x509_pkcs10_req(uint8_t *req, size_t req_len, const char *name, uint32_t name_len, EVP_PKEY *pkey)
{
    X509_NAME *x_name = NULL;
    int len = -1; /* init len with invalid value for exception status return value */
    X509_REQ *x = X509_REQ_new();
    if (x == NULL) {
        tloge("create cert request failed\n");
        return -1;
    }

    if (X509_REQ_set_pubkey(x, pkey) != SSL_LIB_OP_SUCC) {
        tloge("x509 req set pubkey fail\n");
        goto error;
    }

    x_name = X509_REQ_get_subject_name(x);
    if (x_name == NULL) {
        tloge("x509 req get subject name fail\n");
        goto error;
    }

    if (!x509_name_add_entry(x_name, name, name_len))
        goto error;

    /* Sign PKCS10 request */
    if (X509_REQ_sign(x, pkey, EVP_sha256()) == EXT_RET_SUCCESS) {
        tloge("x509 req sign fail\n");
        goto error;
    }

    len = i2d_X509_REQ(x, NULL);
    if ((len < 0) || (len > (int)req_len)) {
        tloge("x509 i2d fail, result len %d, request len %zu\n", len, req_len);
        goto error;
    }

    len = i2d_X509_REQ(x, &req);
    if (len < 0)
        goto error;
error:
    /* NOTE: we can't free name, because it is part of x */
    X509_REQ_free(x);
    return len;
}

static TEE_Result compare_rsa_key(const TEE_ObjectHandle key_origin, const TEE_ObjectHandle key_new)
{
    char buf[RSA_4096_KEY_BYTE_SIZE] = { 0 };
    size_t buf_size = RSA_4096_KEY_BYTE_SIZE;
    TEE_Result ret;
    int32_t ret_s;

    bool check = ((key_origin == NULL) || (key_new == NULL) || (key_origin->Attribute == NULL) ||
                  (key_origin->attributesLen < RSA_KEY_ELEMENT_COUNT));
    if (check) {
        tloge("input invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = TEE_GetObjectBufferAttribute(key_new, TEE_ATTR_RSA_MODULUS, buf, &buf_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get attribute rsa module:ret = 0x%x\n", ret);
        return ret;
    }

    ret_s = TEE_MemCompare(key_origin->Attribute[KEY_MODULUS_INDEX].content.ref.buffer, buf, buf_size);
    if (ret_s != 0) {
        tloge("The persistent key stored failed 1\n");
        return TEE_ERROR_GENERIC;
    }

    buf_size = RSA_4096_KEY_BYTE_SIZE;
    ret = TEE_GetObjectBufferAttribute(key_new, TEE_ATTR_RSA_PUBLIC_EXPONENT, buf, &buf_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get attribute pub exp:ret = 0x%x\n", ret);
        return ret;
    }

    ret_s = TEE_MemCompare(key_origin->Attribute[KEY_PRI_EXPONENT_INDEX].content.ref.buffer, buf, buf_size);
    if (ret_s != 0) {
        tloge("The persistent key stored failed 2\n");
        return TEE_ERROR_GENERIC;
    }

    buf_size = RSA_4096_KEY_BYTE_SIZE;
    ret = TEE_GetObjectBufferAttribute(key_new, TEE_ATTR_RSA_PRIVATE_EXPONENT, buf, &buf_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get attribute pri exp:ret = 0x%x\n", ret);
        return ret;
    }

    ret_s = TEE_MemCompare(key_origin->Attribute[KEY_PUB_EXPONENT_INDEX].content.ref.buffer, buf, buf_size);
    if (ret_s != 0) {
        tloge("The persistent key stored failed 3\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result save_rsa_key(int type, TEE_ObjectHandle key)
{
    uint32_t w_flags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_CREATE;
    uint32_t r_flags = TEE_DATA_FLAG_ACCESS_READ;
    uint32_t storage_id = TEE_OBJECT_STORAGE_PRIVATE;
    char *object_id = NULL;
    TEE_Result ret = TEE_ERROR_GENERIC;
    TEE_ObjectHandle persistent_key = NULL;

    if (key == NULL) {
        tloge("input invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (type == PERSISTENT_KEY_MAIN)
        object_id = PERSISTENT_KEY_ID;
    else if (type == PERSISTENT_KEY_BACKUP)
        object_id = PERSISTENT_BACKUP_KEY_ID;
    else
        return ret;

    ret = TEE_CreatePersistentObject(storage_id, object_id, (size_t)strlen(object_id), w_flags, key, NULL, 0,
                                     (&persistent_key));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to create object:ret = 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    if (TEE_SyncPersistentObject(persistent_key) != TEE_SUCCESS) {
        tloge("sync persistent object failed\n");
        TEE_CloseObject(persistent_key);
        return TEE_ERROR_GENERIC;
    }
    TEE_CloseObject(persistent_key);

    ret = TEE_OpenPersistentObject(storage_id, object_id, strlen(object_id), r_flags, (&persistent_key));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to open persistent object:ret = 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    ret = compare_rsa_key(key, persistent_key);
    TEE_CloseObject(persistent_key);
    if (ret != TEE_SUCCESS)
        tloge("save key error!\n");

    return ret;
}

static TEE_Result get_device_unique_id_str(uint8_t *buff, uint32_t len)
{
    TEE_Result ret;
    uint8_t unique_id[SHA256_BYTE_SIZE] = { 0 };
    uint32_t id_len = (uint32_t)sizeof(unique_id);
    uint8_t ch[HALF_BYTE_MAX] = "0123456789ABCDEF";
    uint32_t i;

    bool check = ((buff == NULL) || (len != (id_len * DOUBLE_OPERATION + 1))); /* 1 for string subfix */
    if (check) {
        tloge("invalid parameter\n");
        return TEE_ERROR_GENERIC;
    }

    ret = tee_ext_get_device_unique_id(unique_id, &id_len);
    check = ((ret != TEE_SUCCESS) || (id_len != SHA256_BYTE_SIZE));
    if (check) {
        tloge("get device unique id is failed\n");
        return TEE_ERROR_GENERIC;
    }

    for (i = 0; i < id_len; i++) {
        *(buff++) = ch[HALF_BYTE_HIGH(unique_id[i])];
        *(buff++) = ch[HALF_BYTE_LOW(unique_id[i])];
    }
    *buff = '\0';

    return TEE_SUCCESS;
}

static TEE_Result write_gp_rsa_key_for_huawei_member(rsa_priv_key_t *rsa)
{
    TEE_Attribute pattrib[RSA_KEY_ELEMENT_COUNT];
    TEE_ObjectHandle key = NULL;
    TEE_Result ret;
    uint32_t key_size = RSA_2048_KEY_BYTE_SIZE;

    (void)memset_s(pattrib, sizeof(pattrib), 0, sizeof(pattrib));
    if (rsa == NULL) {
        tloge("input invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t api_level = tee_get_ta_api_level();
    if (api_level > API_LEVEL1_0)
        key_size = key_size * ONE_BYTE_BIT_COUNT;

    ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &key);
    if (ret != TEE_SUCCESS) {
        tloge("alloc transient object failed, ret 0x%x\n", ret);
        return ret;
    }

    TEE_InitRefAttribute(&pattrib[KEY_MODULUS_INDEX], TEE_ATTR_RSA_MODULUS, rsa->n, rsa->n_len);
    TEE_InitRefAttribute(&pattrib[KEY_PRI_EXPONENT_INDEX], TEE_ATTR_RSA_PRIVATE_EXPONENT, rsa->d, rsa->d_len);
    TEE_InitRefAttribute(&pattrib[KEY_PUB_EXPONENT_INDEX], TEE_ATTR_RSA_PUBLIC_EXPONENT, rsa->e, rsa->e_len);

    ret = TEE_PopulateTransientObject(key, pattrib, RSA_KEY_ELEMENT_COUNT);
    if (ret != TEE_SUCCESS) {
        tloge("populate transient object fail!\n");
        goto clear;
    }

    /* save file */
    ret = save_rsa_key(PERSISTENT_KEY_MAIN, key);
    if (ret != TEE_SUCCESS) {
        tloge("save rsakey failed\n");
        goto clear;
    }
    /* save backup file */
    ret = save_rsa_key(PERSISTENT_KEY_BACKUP, key);
    if (ret != TEE_SUCCESS) {
        tloge("save rsa key backup failed\n");
        goto clear;
    }
clear:
    (void)memset_s(pattrib, sizeof(pattrib), 0, sizeof(pattrib));
    TEE_FreeTransientObject(key);
    return ret;
}

#define SUPPORT_MEMBER
static TEE_Result get_ecc_key(const uint8_t *key, uint32_t key_size, EVP_PKEY **cert_key)
{
    ecc_priv_key_t priv_ecc = { 0, { 0 }, 0 };

    if (derive_ecc_private_key_from_huk(&priv_ecc, key, key_size) < 0) {
        tloge("derive ecc private key is failed\n");
        return TEE_ERROR_GENERIC;
    }

    *cert_key = ecc_bin_to_pkey(priv_ecc.r, priv_ecc.r_len, ec_nid_tom2boringssl(priv_ecc.domain));
    if (*cert_key == NULL) {
        tloge("ecc bin to key failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result get_rsa_key(uint8_t *key, uint32_t key_size, EVP_PKEY **cert_key, const uint8_t *file_name)
{
    rsa_priv_key_t priv_rsa;
    (void)memset_s(&priv_rsa, sizeof(priv_rsa), 0, sizeof(priv_rsa));

    if (derive_private_key_from_secret((void *)&priv_rsa, key, key_size, RSA_2048_KEY_BIT_SIZE, RSA_ALG,
        (uint8_t *)file_name) < 0) {
        tloge("derive private key is failed\n");
        return TEE_ERROR_GENERIC;
    }

#ifdef SUPPORT_MEMBER
    if (write_gp_rsa_key_for_huawei_member(&priv_rsa) != EXT_RET_SUCCESS) {
        tloge("write rsa key is failed\n");
        return TEE_ERROR_GENERIC;
    }
#endif
    *cert_key = rsa_bin_to_pkey(&priv_rsa);
    if (*cert_key == NULL) {
        tloge("rsa bin to key failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result get_key_for_cert_req(uint32_t key_type, EVP_PKEY **cert_key, const uint8_t *file_name)
{
    uint8_t key[DERIVED_KEY_SIZE] = { 0 };
    uint32_t key_size = DERIVED_KEY_SIZE;
    TEE_Result ret;

    ret = tee_ext_root_uuid_derive_key(g_key_salt, sizeof(g_key_salt), key, &key_size);
    if (ret != TEE_SUCCESS) {
        tloge("root uuid derive key is failed\n");
        return ret;
    }

    if (key_type == ECC_ALG)
        return get_ecc_key(key, key_size, cert_key);
    else
        return get_rsa_key(key, key_size, cert_key, file_name);
}

static void rsa_derive_public_key(rsa_pub_key_t *pub, const rsa_priv_key_t *priv)
{
    if (memcpy_s(pub->e, sizeof(pub->e), priv->e, priv->e_len) != EOK)
        return;
    pub->e_len = priv->e_len;

    if (memcpy_s(pub->n, sizeof(pub->n), priv->n, priv->n_len) != EOK)
        return;
    pub->n_len = priv->n_len;
}

union cert_pub_key {
    rsa_pub_key_t rsa_pub_key;
    ecc_pub_key_t ecc_pub_key;
};

static TEE_Result derive_ecc_key_from_huk(uint8_t *key, uint32_t key_size, union cert_pub_key *pub_key)
{
    ecc_priv_key_t ecc_priv = { 0, { 0 }, 0 };
    if (derive_ecc_private_key_from_huk(&ecc_priv, key, key_size) < EXT_RET_SUCCESS) {
        tloge("derive ecc private key is failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (ecc_derive_public_key(&ecc_priv, (ecc_pub_key_t *)pub_key) == EXT_RET_ERROR) {
        tloge("ecc derive public key is failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result derive_rsa_key_from_huk(uint8_t *key, uint32_t key_size, union cert_pub_key *pub_key)
{
    rsa_priv_key_t rsa_priv;
    (void)memset_s(&rsa_priv, sizeof(rsa_priv), 0, sizeof(rsa_priv));

    if (derive_private_key_from_secret(&rsa_priv, key, key_size, RSA_2048_KEY_BIT_SIZE, RSA_ALG, NULL) <
        EXT_RET_SUCCESS) {
        tloge("derive private key from secret failed\n");
        return TEE_ERROR_GENERIC;
    }

    rsa_derive_public_key((rsa_pub_key_t *)pub_key, &rsa_priv);
    return TEE_SUCCESS;
}

static TEE_Result get_derived_pub_key(int32_t key_type, union cert_pub_key *pub_key)
{
    uint8_t key[KEY_SIZE_FOR_CERT] = { 0 };
    uint32_t key_size = KEY_SIZE_FOR_CERT;

    if (tee_ext_root_uuid_derive_key(g_key_salt, sizeof(g_key_salt), key, &key_size) != TEE_SUCCESS) {
        tloge("root uuid derive key failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (key_type == ECC_ALG)
        return derive_ecc_key_from_huk(key, key_size, pub_key);
    else
        return derive_rsa_key_from_huk(key, key_size, pub_key);
}

TEE_Result tee_create_cert_req(uint8_t *buf, size_t length, uint32_t key_type, uint8_t *file_name)
{
    uint8_t unique_id_str[DEVICE_UNIQUE_ID_STR_LEN] = { 0 };
    EVP_PKEY *key = NULL;
    TEE_Result ret;

    bool check = ((buf == NULL) || (length == 0));
    if (check) {
        tloge("buf or length is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_device_unique_id_str(unique_id_str, DEVICE_UNIQUE_ID_STR_LEN);
    if (ret != TEE_SUCCESS) {
        tloge("get device id failed\n");
        return ret;
    }

    ret = get_key_for_cert_req(key_type, &key, file_name);
    if (ret != TEE_SUCCESS) {
        tloge("get key for cert req failed\n");
        return ret;
    }

    if (create_x509_pkcs10_req(buf, length, (char *)unique_id_str, HASH_LEN * DOUBLE_OPERATION, key) <= 0) {
        tloge("create x509 req failed\n");
        ret = TEE_ERROR_GENERIC;
    }

    EVP_PKEY_free(key);
    return ret;
}

TEE_Result TEE_EXT_create_cert_req(uint8_t *buf, size_t length, uint32_t key_type, uint8_t *file_name)
{
    return tee_create_cert_req(buf, length, key_type, file_name);
}

TEE_Result tee_verify_dev_cert(uint8_t *cert, uint32_t cert_len, uint8_t *parent_key, uint32_t parent_key_len)
{
    uint8_t tmp[PUB_KEY_SUBJECT_SIZE] = { 0 };
    int32_t pub_key_len;
    int32_t key_type;
    union cert_pub_key pub1;
    union cert_pub_key pub2;

    (void)memset_s(&pub1, sizeof(pub1), 0, sizeof(pub1));
    (void)memset_s(&pub2, sizeof(pub2), 0, sizeof(pub2));
    bool check = ((cert == NULL) || (cert_len == 0) || (parent_key == NULL) || (parent_key_len == 0));
    if (check) {
        tloge("input params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    key_type = get_keytype_from_sp(parent_key, parent_key_len);
    if (key_type < EXT_RET_SUCCESS) {
        tloge("wrong key type\n");
        return TEE_ERROR_GENERIC;
    }

    if (x509_cert_validate(cert, cert_len, parent_key, parent_key_len) != SSL_LIB_OP_SUCC) {
        tloge("failed to validate the x509 cert\n");
        return TEE_ERROR_GENERIC;
    }

    if (get_derived_pub_key(key_type, &pub1) != TEE_SUCCESS) {
        tloge("get derived pub key failed\n");
        return TEE_ERROR_GENERIC;
    }

    pub_key_len = get_subject_public_key(tmp, cert, cert_len);
    if (pub_key_len < EXT_RET_SUCCESS) {
        tloge("failed to get pub key\n");
        return TEE_ERROR_GENERIC;
    }

    if (import_pub_from_sp(&pub2, tmp, pub_key_len) < EXT_RET_SUCCESS) {
        tloge("failed to export pub key\n");
        return TEE_ERROR_GENERIC;
    }

    if (TEE_MemCompare(&pub1, &pub2, pub_key_len) != EXT_RET_SUCCESS) {
        tloge("failed to compare the pubkey\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_EXT_verify_dev_cert(uint8_t *cert, uint32_t cert_len, uint8_t *parent_key, uint32_t parent_key_len)
{
    return tee_verify_dev_cert(cert, cert_len, parent_key, parent_key_len);
}

