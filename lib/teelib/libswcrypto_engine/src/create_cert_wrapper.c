/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * Description: soft engine of boringssl
 * Create: 2019-05-20
 */
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <securec.h>
#include <tee_log.h>
#include "crypto_inner_interface.h"
#define TLV_TAG       0x30
#define EXTENSION_TAG 0xa3

static int32_t tbs_ele_tlv_type_check(const uint8_t *cert, uint32_t cert_len, const uint8_t **tbs, uint32_t *tbs_len)
{
    uint32_t type = 0;
    uint32_t hlen = 0;
    int32_t len;
    const uint8_t *tmp_tbs = NULL;
    /* Go to tbs */
    len        = get_next_tlv(&type, &hlen, cert, cert_len);
    bool check = (len <= 0 || type != TLV_TAG || cert_len < hlen);
    if (check) {
        tloge("soft_enine: %s\n", "tbs ele tlv type check input error ");
        return -1;
    }
    tmp_tbs  = cert + hlen;
    *tbs_len = cert_len - hlen;
    /* Step into tbs */
    len   = get_next_tlv(&type, &hlen, tmp_tbs, *tbs_len);
    check = (len <= 0 || type != TLV_TAG);
    if (check) {
        tloge("soft_enine: %s\n", "Step into tbs get_next_tlv failed or type is unexpected.\n");
        return -1;
    }
    if (*tbs_len < hlen) {
        tloge("soft_enine: %s\n", "buffer len too short");
        return -1;
    }
    tmp_tbs += hlen;
    *tbs_len -= hlen;
    /* Skip version */
    *tbs = tmp_tbs;
    return 0;
}

static int32_t tbs_ele_proc(uint8_t *tbs, uint32_t tbs_len, uint32_t elem_id, uint8_t **elem)
{
    uint32_t i;
    int32_t len;
    uint32_t hlen = 0;
    uint32_t type = 0;
    uint32_t upper_bound;

    /* Check if we use elem_id > 0x100, which are reserved for CSR */
    if (elem_id < 0x100) {
        /* Skip serial number */
        len = get_next_tlv(&type, &hlen, tbs, tbs_len);
        if ((len < 0) || (type != CRYPTO_NUMBER_TWO)) {
            tloge("soft_enine: %s\n", "get tlv 2 fail");
            return -1;
        }
        if (elem_id == 1) {
            *elem = tbs + hlen;
            return len;
        }
        tbs_len -= ((uint32_t)len + hlen);
        tbs += ((uint32_t)len + hlen);
        i           = CRYPTO_NUMBER_TWO;
        upper_bound = CRYPTO_NUMBER_SIX;
    } else {
        i           = 0x101; /* reserved for CSR */
        upper_bound = i + 1;
    }

    /* Process SEQUENCES: signature, issuer, validity, subject and subjectPublicKeyInfo,
     * for TBS SEQUENCES are subject and subjectPublicKeyInfo */
    for (; i <= upper_bound; i++) {
        len = get_next_tlv(&type, &hlen, tbs, tbs_len);
        if ((len < 0) || (type != TLV_TAG)) {
            tloge("soft_enine: %s\n", "get next tlv 0x30 fail len");
            return -1;
        }
        if (i == elem_id) {
            *elem = tbs;
            return len + (int32_t)hlen;
        }
        tbs_len -= ((uint32_t)len + hlen);
        tbs += ((uint32_t)len + hlen);
    }
    if (i == CRYPTO_NUMBER_SEVEN) {
        /* Only possibility is that we have extension */
        len = get_next_tlv(&type, &hlen, tbs, tbs_len);
        if ((len < 0) || (type != EXTENSION_TAG)) {
            tloge("soft_enine: %s\n", "get next tlv 0xa3 fail len");
            return -1;
        }
        *elem = tbs;
        return len + (int32_t)hlen;
    }
    return -1;
}
/*
 * This function reads element number i from TBSCertificate
 * TBSCertificate  ::=    SEQUENCE  {
 *  version           [0]  EXPLICIT Version DEFAULT v1,
 *  serialNumber           CertificateSerialNumber,
 *  signature              AlgorithmIdentifier,
 *  issuer                 Name,
 *  validity               Validity,
 *  subject                Name,
 *  subjectPublicKeyInfo   SubjectPublicKeyInfo,
 *  issuerUniqueID    [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *               -- If present, version MUST be v2 or v3
 *  subjectUniqueID   [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *               -- If present, version MUST be v2 or v3
 *  extensions        [3]  EXPLICIT Extensions OPTIONAL
 *               -- If present, version MUST be v3
 * }
 * @param elem         [out] points to tbs elem with elem_id
 * @param elem_id      [in]  elem_id is the element index we are looking
 * @param cert         [in]  cert is buffer from where we are looking tbs element
 * @param cert_len     [in]  cert_len is length of certificate in bytes
 * @Return length of element in bytes when found and otherwice -1.
 */
int32_t get_tbs_element(uint8_t **elem, uint32_t elem_id, const uint8_t *cert, uint32_t cert_len)
{
    uint8_t *tbs     = NULL;
    uint32_t tbs_len = 0;
    uint32_t type    = 0;
    uint32_t hlen    = 0;
    int32_t len;
    bool check = (elem == NULL || cert == NULL);
    /* *elem may be null here */
    if (check) {
        tloge("soft_enine: %s\n", "get tbs ele input error ");
        return -1;
    }
    /* Go to tbs */
    check = (tbs_ele_tlv_type_check(cert, cert_len, (const uint8_t **)&tbs, &tbs_len) < 0);
    if (check) {
        tloge("soft_enine: %s\n", "tlv type check fail");
        return -1;
    }
    /* Skip version */
    len   = get_next_tlv(&type, &hlen, tbs, tbs_len);
    check = ((len <= 0) || ((type != 0xa0) && (type != 0x02)));
    if (check) {
        tloge("soft_enine: %s\n", "get 0x2 or 0xa0 type error");
        return -1;
    }
    if (elem_id == 0) {
        *elem = tbs + hlen;
        return len;
    }
    tbs_len -= ((uint32_t)len + hlen);
    tbs += ((uint32_t)len + hlen);
    return tbs_ele_proc(tbs, tbs_len, elem_id, elem);
}

static int cert_set_issuer_name(X509 *x, const uint8_t *issuer_tlv, uint32_t issuer_tlv_len)
{
    X509_NAME *issuer_name = NULL;
    issuer_name            = d2i_X509_NAME(&issuer_name, (const uint8_t **)&issuer_tlv, issuer_tlv_len);
    if (issuer_name == NULL) {
        tloge("issuer tlv is error, len %u", issuer_tlv_len);
        return -1;
    }
    int ret = X509_set_issuer_name(x, issuer_name);
    X509_NAME_free(issuer_name);
    if (ret <= 0) {
        tloge("set issuer name fail");
        return -1;
    }
    return 0;
}

static int cert_set_time(X509 *x, const validity_period_t *valid)
{
    int ret;
    char tmp_start[VALIDITY_TIME_SIZE + 1] = { 0 };
    char tmp_end[VALIDITY_TIME_SIZE + 1]   = { 0 };
    errno_t rc = memcpy_s(tmp_start, VALIDITY_TIME_SIZE + 1, valid->start, VALIDITY_TIME_SIZE);
    if (rc != EOK) {
        tloge("soft_enine: %s\n", "start mem cpy fail");
        return -1;
    }
    rc = memcpy_s(tmp_end, VALIDITY_TIME_SIZE + 1, valid->end, VALIDITY_TIME_SIZE);
    if (rc != EOK) {
        tloge("soft_enine: %s\n", "end mem cpy fail");
        return -1;
    }

    ret = ASN1_TIME_set_string(X509_get_notBefore(x), tmp_start);
    if (ret <= 0) {
        tloge("set cert start time fail, %s", tmp_start);
        return -1;
    }
    ret = ASN1_TIME_set_string(X509_get_notAfter(x), tmp_end);
    if (ret <= 0) {
        tloge("set cert end time fail, %s", tmp_end);
        return -1;
    }
    return 0;
}

static int cert_set_pub_key(X509 *x, const uint8_t *subject_public_key, uint32_t subject_public_key_len)
{
    EVP_PKEY *pub_key = NULL;
    pub_key           = d2i_PUBKEY(&pub_key, (const uint8_t **)&subject_public_key, subject_public_key_len);
    if (pub_key == NULL) {
        tloge("input pub key is error, can convert it");
        return -1;
    }

    int ret = X509_set_pubkey(x, pub_key);
    EVP_PKEY_free(pub_key);
    if (ret <= 0) {
        tloge("cert set public key error");
        return -1;
    }
    return 0;
}

static int cert_set_ext(X509 *x, const uint8_t *attestation_ext, uint32_t attestation_ext_len)
{
    int ret                           = -1;
    X509_EXTENSION *ext               = NULL;
    ASN1_OCTET_STRING *data           = NULL;
    const char attestion_record_oid[] = "1.3.6.1.4.1.11129.2.1.17";
    ASN1_OBJECT *obj                  = OBJ_txt2obj(attestion_record_oid, 1);
    if (obj == NULL) {
        tloge("new obj fail");
        goto error;
    }
    data = ASN1_OCTET_STRING_new();
    if (data == NULL) {
        tloge("new data fail");
        goto error;
    }
    ret = ASN1_OCTET_STRING_set(data, attestation_ext, attestation_ext_len);
    if (ret == 0) {
        ret = -1;
        tloge("set ext data fail");
        goto error;
    }
    ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 0, data);
    if (ext == NULL) {
        ret = -1;
        tloge("attestation_ext is error, can not convert");
        goto error;
    }
    ret = X509_add_ext(x, ext, -1);
    if (ret == 0) {
        tloge("cert set ext fail");
        ret = -1;
        goto error;
    }
    ret = 0;
error:
    ASN1_OBJECT_free(obj);
    ASN1_OCTET_STRING_free(data);
    X509_EXTENSION_free(ext);
    return ret;
}

static int32_t get_ecc_sign_key(void *priv_sign, EC_KEY **ec_key, EVP_PKEY *sign_key)
{
    ecc_priv_key_t *priv = (ecc_priv_key_t *)priv_sign;
    int32_t cur          = ec_nid_tom2boringssl(priv->domain);
    int ret;
    if (cur == -1) {
        tloge("cur get error");
        return -1;
    }

    uint32_t tmp_cur = priv->domain;
    priv->domain     = (uint32_t)cur;
    ret              = (int)ecc_privkey_tee_to_boring(priv, (void **)ec_key);
    priv->domain     = tmp_cur;
    if (ret != (int)TEE_SUCCESS) {
        tloge("Tee Private Key To Boring Key error");
        return -1;
    }
    EC_KEY_set_asn1_flag(*ec_key, OPENSSL_EC_NAMED_CURVE);
    ret = EVP_PKEY_assign_EC_KEY(sign_key, *ec_key);
    if (ret == 0) {
        tloge("assign ec key fail");
        return -1;
    }
    return 1;
}

static int32_t get_rsa_sign_key(void *priv_sign, RSA *rsa_key, EVP_PKEY *sign_key)
{
    int32_t ret;
    rsa_key = build_boringssl_priv_key(priv_sign);
    if (rsa_key == NULL) {
        tloge("rsa build priv key failed");
        return -1;
    }
    ret = EVP_PKEY_assign_RSA(sign_key, rsa_key);
    if (ret == 0) {
        tloge("assign rsa key fail");
        return -1;
    }
    return 1;
}

static EVP_PKEY *cert_get_sign_key(void *priv_sign, uint32_t key_type)
{
    int32_t ret;
    EC_KEY *ec_key     = NULL;
    RSA *rsa_key       = NULL;
    EVP_PKEY *sign_key = EVP_PKEY_new();
    if (sign_key == NULL) {
        tloge("new ecp key fail");
        return NULL;
    }

    if (key_type == ECC_ALG) {
        ret = get_ecc_sign_key(priv_sign, &ec_key, sign_key);
    } else if (key_type == RSA_ALG) {
        ret = get_rsa_sign_key(priv_sign, rsa_key, sign_key);
    } else {
        tloge("error key type");
        goto error;
    }
    if (ret != 1) {
        tloge("get sign key failed");
        goto error;
    }
    return sign_key;
error:
    RSA_free(rsa_key);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(sign_key);
    return NULL;
}

struct hash_to_md {
    uint32_t hash_type;
    const EVP_MD *hash_md;
};

static const EVP_MD *get_hash_md(uint32_t hash)
{
    struct hash_to_md change_hash_to_md[] = {
        { SHA1_HASH,     EVP_sha1() },
        { SHA224_HASH, EVP_sha224() },
        { SHA256_HASH, EVP_sha256() },
        { SHA384_HASH, EVP_sha384() },
        { SHA512_HASH, EVP_sha512() },
    };

    for (size_t i = 0; i < sizeof(change_hash_to_md) / sizeof(change_hash_to_md[0]); i++) {
        if (hash == change_hash_to_md[i].hash_type)
            return change_hash_to_md[i].hash_md;
    }
    return NULL;
}

static int cert_do_sign(X509 *x, uint32_t hash, void *priv_sign, uint32_t key_type)
{
    int ret;
    EVP_PKEY *sign_key = cert_get_sign_key(priv_sign, key_type);
    if (sign_key == NULL) {
        tloge("get sign key fail");
        return -1;
    }

    const EVP_MD *md = get_hash_md(hash);
    if (md == NULL) {
        EVP_PKEY_free(sign_key);
        return -1;
    }

    ret = X509_sign(x, sign_key, md);
    EVP_PKEY_free(sign_key);
    sign_key = NULL;
    if (ret == 0) {
        tloge("x509 sign fail");
        return -1;
    }
    return 0;
}

static int cert_set_usage(X509 *x, uint32_t key_usage_sign_bit, uint32_t key_usage_encrypt_bit)
{
    char *sign_only_usage     = "critical, digitalSignature";
    char *encrypt_only_usage  = "critical, keyEncipherment, dataEncipherment";
    char *sign_encrypto_usage = "critical, digitalSignature, keyEncipherment, dataEncipherment";
    X509_EXTENSION *ext       = NULL;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
    int ret;
    if (key_usage_sign_bit == 1 && key_usage_encrypt_bit == 1)
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, sign_encrypto_usage);
    else if (key_usage_sign_bit == 1)
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, sign_only_usage);
    else if (key_usage_encrypt_bit == 1)
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, encrypt_only_usage);
    else
        return 0;

    if (ext == NULL) {
        tloge("new ext fail");
        return -1;
    }
    ret = X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
    if (ret == 0) {
        tloge("add usage fail");
        return -1;
    }
    return 0;
}

static int cert_set_serial_number(X509 *x)
{
    uint8_t root_ser[] = { 0x01 };
    BIGNUM *serial     = BN_bin2bn(root_ser, sizeof(root_ser), NULL);
    if (serial == NULL) {
        tloge("get serial fail");
        return -1;
    }

    ASN1_INTEGER *ser = BN_to_ASN1_INTEGER(serial, NULL);
    BN_free(serial);
    serial = NULL;
    if (ser == NULL) {
        tloge("serial bn to asn1 integer fail");
        return -1;
    }

    int res = X509_set_serialNumber(x, ser);
    ASN1_STRING_free(ser);
    if (res != 1) {
        tloge("set serial fail");
        return -1;
    }
    return 0;
}

static int cert_set_subject(X509 *x, const uint8_t *cn)
{
    int ret;
    X509_NAME *subject_name = NULL;
    subject_name            = X509_NAME_new();
    ret                     = X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC, cn, -1, -1, 0);
    if (ret != 1) {
        tloge("add CN fail");
        ret = -1;
        goto error;
    }
    ret = X509_set_subject_name(x, subject_name);
    if (ret != 1) {
        tloge("set subject name fail");
        ret = -1;
        goto error;
    }
error:
    X509_NAME_free(subject_name);
    return ret;
}

struct attestation_cert_st {
    const validity_period_t *valid;
    const uint8_t *issuer_tlv;
    uint32_t issuer_tlv_len;
    const uint8_t *subject_public_key;
    uint32_t subject_public_key_len;
    const uint8_t *attestation_ext;
    uint32_t attestation_ext_len;
    uint32_t key_usage_sign_bit;
    uint32_t key_usage_encrypt_bit;
    void *priv_sign;
    uint32_t key_type;
    uint32_t hash;
};

static int32_t set_cert_info(X509 *x, struct attestation_cert_st *cert_info)
{
    const uint8_t *cn = (uint8_t *)"Android Keystore Key";
    int32_t ret = X509_set_version(x, CRYPTO_NUMBER_TWO);
    if (ret == 0) {
        tloge("set version fail ");
        return -1;
    }

    ret = cert_set_serial_number(x);
    if (ret == -1) {
        tloge("set serial number fail ");
        return -1;
    }

    ret = cert_set_subject(x, cn);
    if (ret == -1) {
        tloge("set subject fail ");
        return ret;
    }

    ret = cert_set_time(x, cert_info->valid);
    if (ret == -1) {
        tloge("set time fail ");
        return ret;
    }

    ret = cert_set_issuer_name(x, cert_info->issuer_tlv, cert_info->issuer_tlv_len);
    if (ret == -1) {
        tloge("set issuer name fail ");
        return ret;
    }

    ret = cert_set_pub_key(x, cert_info->subject_public_key, cert_info->subject_public_key_len);
    if (ret == -1) {
        tloge("set public key fail ");
        return ret;
    }

    ret = cert_set_ext(x, cert_info->attestation_ext, cert_info->attestation_ext_len);
    if (ret == -1) {
        tloge("set attestation ext fail ");
        return ret;
    }

    ret = cert_set_usage(x, cert_info->key_usage_sign_bit, cert_info->key_usage_encrypt_bit);
    if (ret == -1) {
        tloge("cert set usage fail ");
        return ret;
    }

    ret = cert_do_sign(x, cert_info->hash, cert_info->priv_sign, cert_info->key_type);
    if (ret == -1) {
        tloge("cert do sign fail ");
        return ret;
    }
    return 1;
}

int32_t create_attestation_cert(uint8_t *cert, uint32_t cert_len, const validity_period_t *valid,
    const uint8_t *issuer_tlv, uint32_t issuer_tlv_len, const uint8_t *subject_public_key,
    uint32_t subject_public_key_len, const uint8_t *attestation_ext, uint32_t attestation_ext_len, void *priv_sign,
    uint32_t key_usage_sign_bit, uint32_t key_usage_encrypt_bit, uint32_t key_type, uint32_t hash)
{
    bool check = (cert == NULL || valid == NULL || issuer_tlv == NULL || subject_public_key == NULL ||
                  attestation_ext == NULL || priv_sign == NULL);
    if (check) {
        tloge("create attestation cert input error");
        return -1;
    }

    X509 *x = X509_new();
    if (x == NULL) {
        tloge("new x509 fail ");
        return -1;
    }

    struct attestation_cert_st cert_info = { 0 };
    cert_info.valid = valid;
    cert_info.issuer_tlv = issuer_tlv;
    cert_info.issuer_tlv_len = issuer_tlv_len;
    cert_info.subject_public_key = subject_public_key;
    cert_info.subject_public_key_len = subject_public_key_len;
    cert_info.attestation_ext = attestation_ext;
    cert_info.attestation_ext_len = attestation_ext_len;
    cert_info.key_usage_sign_bit = key_usage_sign_bit;
    cert_info.key_usage_encrypt_bit = key_usage_encrypt_bit;
    cert_info.priv_sign = priv_sign;
    cert_info.key_type = key_type;
    cert_info.hash = hash;

    int32_t ret = set_cert_info(x, &cert_info);
    if (ret == -1) {
        tloge("cert sign fail ");
        X509_free(x);
        return -1;
    }

    int32_t tmp_len = i2d_X509(x, NULL);
    if (tmp_len <= 0 || tmp_len > (int32_t)cert_len) {
        tloge("conver x509 error");
        X509_free(x);
        return -1;
    }
    uint8_t *orig = cert;
    ret = i2d_X509(x, &orig);
    X509_free(x);
    return ret;
}
