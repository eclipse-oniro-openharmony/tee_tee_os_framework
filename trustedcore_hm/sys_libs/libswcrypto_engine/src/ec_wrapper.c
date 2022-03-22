/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * Description: soft engine of boringssl
 * Create: 2019-05-20
 */
#include <stdbool.h>
#ifdef CRYPTO_SUPPORT_ECC_WRAPPER
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#ifdef BORINGSSL_ENABLE
#include <openssl/nid.h>
#include <openssl/mem.h>
#include <openssl/hkdf.h>
#else
#include <rsa/rsa_local.h>
#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#endif
#endif
#include <securec.h>
#include <tee_log.h>
#include "crypto_inner_interface.h"

#ifdef CRYPTO_SUPPORT_ECC_WRAPPER

/* ECC domain id defined in tomcrypto */
#define EC_KEY_FIX_BUFFER_LEN 66

#define OBJ_LEN_ONE 1
#define OBJ_LEN_TWO 2

const uint8_t g_nist_p256_group_order[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
    0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

unsigned char g_org_unit[] = "Consumer Business Group";
unsigned char g_org[]      = "huawei";
unsigned char g_country[]  = "CN";
unsigned char g_common[]   = "hisi kirin 955";
uint8_t g_root_serial[]    = { 0x10, 0x00 };

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

int32_t ec_nid_tom2boringssl(uint32_t domain)
{
    switch (domain) {
    case NIST_P192:
        return NID_X9_62_prime192v1;
    case NIST_P224:
        return NID_secp224r1;
    case NIST_P256:
        return NID_X9_62_prime256v1;
    case NIST_P384:
        return NID_secp384r1;
    case NIST_P521:
        return NID_secp521r1;
    default:
        tloge("error domain %u", domain);
        return -1;
    }
}
static TEE_Result new_boring_ec_key(const BIGNUM *ecc_priv_boring, const EC_POINT *ecc_pub_boring,
    int32_t ec_nid, EC_KEY **eckey)
{
    EC_KEY *ecc_key = EC_KEY_new_by_curve_name(ec_nid);
    if (ecc_key == NULL) {
        tloge("soft_enine: %s\n", "new ecc key error");
        return TEE_ERROR_GENERIC;
    }
    if (EC_KEY_set_private_key(ecc_key, ecc_priv_boring) != 1) {
        tloge("set private key error");
        EC_KEY_free(ecc_key);
        return TEE_ERROR_GENERIC;
    }
    if (EC_KEY_set_public_key(ecc_key, ecc_pub_boring) != 1) {
        tloge("set pub key error");
        EC_KEY_free(ecc_key);
        return TEE_ERROR_GENERIC;
    }
    *eckey = ecc_key;
    return TEE_SUCCESS;
}

TEE_Result ecc_privkey_tee_to_boring(void *priv, void **eckey)
{
    BIGNUM *ecc_priv_boring  = NULL;
    EC_GROUP *group          = NULL;
    EC_POINT *ecc_pub_boring = NULL;
    ecc_priv_key_t *ecc_priv = NULL;
    int32_t boring_nid;
    TEE_Result ret;
    if (priv == NULL || eckey == NULL) {
        tloge("soft_enine: %s\n", "priv is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ecc_priv        = (ecc_priv_key_t *)priv;
    boring_nid      = (int32_t)ecc_priv->domain;
    ecc_priv_boring = BN_bin2bn(ecc_priv->r, ecc_priv->r_len, NULL);
    if (ecc_priv_boring == NULL) {
        tloge("soft_enine: %s\n", "bin2bn error in tee key to boring private key");
        return TEE_ERROR_GENERIC;
    }

    group = EC_GROUP_new_by_curve_name(boring_nid);
    if (group == NULL) {
        tloge("new ec group error");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    ecc_pub_boring = EC_POINT_new(group);
    if (ecc_pub_boring == NULL) {
        tloge("new boring pub error");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    int32_t res = EC_POINT_mul(group, ecc_pub_boring, ecc_priv_boring, NULL, NULL, NULL);
    if (res != 1) {
        tloge("POINT_mul error");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    ret = new_boring_ec_key(ecc_priv_boring, ecc_pub_boring, boring_nid, (EC_KEY **)eckey);
error:
    BN_free(ecc_priv_boring);
    EC_POINT_free(ecc_pub_boring);
    EC_GROUP_free(group);
    return ret;
}

TEE_Result ecc_pubkey_tee_to_boring(void *public_key, EC_KEY **eckey)
{
    ecc_pub_key_t *pub_key = (ecc_pub_key_t *)public_key;
    if (pub_key == NULL || eckey == NULL) {
        tloge("soft_enine: %s\n", "key is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(pub_key->domain);
    BIGNUM *x      = BN_bin2bn(pub_key->x, pub_key->x_len, NULL);
    BIGNUM *y      = BN_bin2bn(pub_key->y, pub_key->y_len, NULL);
    bool check     = (ec_key == NULL || x == NULL || y == NULL);
    if (check) {
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        tloge("bn new or create ec key error");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    int32_t res = EC_KEY_set_public_key_affine_coordinates(ec_key, x, y);
    if (res == 0) {
        tloge("set pub key error");
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    *eckey = ec_key;
    BN_free(x);
    BN_free(y);
    return TEE_SUCCESS;
}
static int32_t get_public_key(const ecc_priv_key_t *priv_info, struct ecc_derive_public_key_t *public_key)
{
    public_key->priv_bn = BN_bin2bn(priv_info->r, priv_info->r_len, NULL);
    if (public_key->priv_bn == NULL) {
        tloge("priv bin2bn failed");
        return -1;
    }

    public_key->pub_pt = EC_POINT_new(public_key->group);
    if (public_key->pub_pt == NULL) {
        tloge("pub new failed");
        return -1;
    }

    int32_t ret = EC_POINT_mul(public_key->group, public_key->pub_pt, public_key->priv_bn, NULL, NULL, public_key->ctx);
    if (ret != 1) {
        tloge("ec point mul failed");
        return -1;
    }

    ret = EC_POINT_get_affine_coordinates_GFp(public_key->group, public_key->pub_pt, public_key->x_bn, public_key->y_bn,
                                              public_key->ctx);
    if (ret != 1) {
        tloge("get pub point failed");
        return -1;
    }
    return ret;
}

int ecc_derive_public_key(ecc_priv_key_t *priv_info, ecc_pub_key_t *pub_info)
{
    bool check_flag = (priv_info == NULL || pub_info == NULL);
    if (check_flag) {
        tloge("soft_enine: %s\n", "invalid ec info");
        return -1;
    }

    int nid = ec_nid_tom2boringssl(priv_info->domain);
    if (nid < 0) {
        tloge("soft_enine: %s\n", "domain is error, bad private key");
        return -1;
    }

    struct ecc_derive_public_key_t public_key = {0};
    int ret = -1;
    public_key.group = EC_GROUP_new_by_curve_name(nid);
    if (public_key.group == NULL) {
        tloge("soft_enine: %s\n", "alloc group failed");
        return -1;
    }

    public_key.x_bn       = BN_new();
    public_key.y_bn       = BN_new();
    public_key.ctx        = BN_CTX_new();
    check_flag = (public_key.x_bn == NULL || public_key.y_bn == NULL || public_key.ctx == NULL);
    if (check_flag) {
        tloge("alloc points failed");
        goto error;
    }

    ret = get_public_key(priv_info, &public_key);
    if (ret != 1)
        goto error;

    pub_info->x_len  = (uint32_t)BN_bn2bin(public_key.x_bn, pub_info->x);
    pub_info->y_len  = (uint32_t)BN_bn2bin(public_key.y_bn, pub_info->y);
    pub_info->domain = priv_info->domain;
    ret              = 0;

error:
    /* boringssl API will check if pointer is NULL */
    BN_CTX_free(public_key.ctx);
    EC_POINT_free(public_key.pub_pt);
    BN_free(public_key.x_bn);
    BN_free(public_key.y_bn);
    BN_free(public_key.priv_bn);
    EC_GROUP_free(public_key.group);
    return ret;
}

int derive_ecc_private_key_from_huk(ecc_priv_key_t *priv, const uint8_t *secret, uint32_t sec_len)
{
    struct derive_ecc_private_key_from_huk_t priv_key = {0};
    int32_t ret;

    if ((priv == NULL) || (secret == NULL) || (sec_len > SECRET_KEY_MAX_LEN)) {
        tloge("soft_enine: %s\n", "invalid params");
        return -1;
    }
    priv_key.ord = BN_bin2bn(g_nist_p256_group_order, sizeof(g_nist_p256_group_order), NULL);
    if (priv_key.ord == NULL) {
        tloge("soft_enine: %s\n", "bin to bn error");
        return -1;
    }
    priv_key.x = BN_bin2bn(secret, sec_len, NULL);
    if (priv_key.x == NULL) {
        tloge("secret to bn fail");
        ret = -1;
        goto error;
    }
    if (BN_sub_word(priv_key.ord, 1) != 1) {
        tloge("ord get fail");
        ret = -1;
        goto error;
    }
    priv_key.ctx = BN_CTX_new();
    if (priv_key.ctx == NULL) {
        tloge("new ctx fail");
        ret = -1;
        goto error;
    }
    /* Compute x (mod (ord -1)) + 1 */
    ret = BN_mod(priv_key.x, priv_key.x, priv_key.ord, priv_key.ctx);
    BN_CTX_free(priv_key.ctx);
    priv_key.ctx = NULL;
    if ((ret != 1) || (BN_add_word(priv_key.x, 1) == 0)) {
        tloge("bn mod fail");
        ret = -1;
        goto error;
    }
    priv->domain = NIST_P256;
    if (BN_num_bytes(priv_key.x) > ECC_PRIV_LEN) {
        ret = -1;
        goto error;
    }
    priv->r_len = (uint32_t)BN_bn2bin(priv_key.x, priv->r);
    ret         = 0;

error:
    BN_free(priv_key.x);
    BN_free(priv_key.ord);
    return ret;
}

/* file_name if rsa key, we can store offset by file_name */
int derive_private_key_from_secret(void *priv, uint8_t *secret, uint32_t secret_len, uint32_t bits, uint32_t key_type,
                                   uint8_t *file_name)
{
    /* file_name maybe null here */
    if (secret == NULL) {
        tloge("soft_enine: %s\n", "invalid params");
        return -1;
    }
    if (priv == NULL) {
        tloge("soft_enine: %s\n", "invalid params");
        return -1;
    }
    switch (key_type) {
    case RSA_ALG:
        return generate_rsa_from_secret(priv, bits, secret, secret_len, file_name);
    case ECC_ALG: {
        ecc_priv_key_t *priv_key = (ecc_priv_key_t *)priv;
        int ret;

        ret = derive_ecc_private_key_from_huk(priv_key, secret, secret_len);
        if (ret < 0) {
            tloge("soft_enine: %s\n", "derive ecc private fail");
            return -1;
        }
        return ret;
    }
    default:
        return -1;
    }
}
int32_t ecc_export_pub(uint8_t *out, uint32_t out_size, ecc_pub_key_t *pub)
{
    uint32_t old_domain;
    bool check = (out == NULL || pub == NULL);
    if (check) {
        tloge("soft_enine: %s\n", "ecc export pub input error");
        return -1;
    }
    old_domain     = pub->domain;
    int boring_cur = ec_nid_tom2boringssl(pub->domain);
    if (boring_cur < 0) {
        tloge("soft_enine: %s\n", "bad domain in ecc export pub");
        return -1;
    }
    pub->domain    = (uint32_t)boring_cur;
    EC_KEY *eckey  = NULL;
    TEE_Result ret = ecc_pubkey_tee_to_boring(pub, &eckey);
    pub->domain    = old_domain;
    if (ret != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "tee public key to boring key fail");
        return -1;
    }
    /* i2d_EC_PUBKEY while change tmp_out; */
    int32_t buffer_size = i2d_EC_PUBKEY(eckey, NULL);
    if ((uint32_t)buffer_size > out_size) {
        tloge("out buffer not enough");
        EC_KEY_free(eckey);
        return -1;
    }
    buffer_size = i2d_EC_PUBKEY(eckey, &out);
    EC_KEY_free(eckey);
    if (buffer_size == 0) {
        tloge("soft_enine: %s\n", "boring key to asn1 fail");
        return -1;
    }
    return buffer_size;
}
static TEE_Result ecc_get_domain_by_ec_key(const EC_KEY *key, uint32_t *domain)
{
    EC_GROUP *g = (EC_GROUP *)EC_KEY_get0_group(key);
    if (g == NULL) {
        tloge("soft_enine: %s\n", "EC KEY get group fail");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int cur                        = EC_GROUP_get_curve_name(g);
    uint32_t index                 = 0;
    crypto_u2u domain_to_curve_name[] = {
        { NID_X9_62_prime192v1, NIST_P192 }, { NID_secp224r1, NIST_P224 }, { NID_X9_62_prime256v1, NIST_P256 },
        { NID_secp384r1, NIST_P384 },        { NID_secp521r1, NIST_P521 },
    };
    for (; index < sizeof(domain_to_curve_name) / sizeof(crypto_u2u); index++) {
        if ((uint32_t)cur == domain_to_curve_name[index].src) {
            *domain = domain_to_curve_name[index].dest;
            return TEE_SUCCESS;
        }
    }
    tloge("get domain fail, invalid cur 0x%x\n", cur);
    return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result ecc_ecpubkey_boring_to_tee(const EC_KEY *key, ecc_pub_key_t *pub)
{
    if (key == NULL || pub == NULL) {
        tloge("soft_enine: %s\n", "input param is NULL");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret;
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (x == NULL || y == NULL) {
        tloge("new bn error in boring pub to tee pub");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto error;
    }
    const EC_POINT *point = EC_KEY_get0_public_key(key);
    if (point == NULL) {
        tloge("boring ec key get public key error");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    int32_t res = EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key), point, x, y, NULL);
    if (res == 0) {
        tloge("boring ec key get public x y error");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    uint32_t public_key_x_len = (uint32_t)BN_num_bytes(x);
    uint32_t public_key_y_len = (uint32_t)BN_num_bytes(y);
    if (public_key_x_len > EC_KEY_FIX_BUFFER_LEN || public_key_y_len > EC_KEY_FIX_BUFFER_LEN) {
        tloge("buffer not enougth");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto error;
    }
    pub->x_len = (uint32_t)BN_bn2bin(x, pub->x);
    pub->y_len = (uint32_t)BN_bn2bin(y, pub->y);
    ret        = ecc_get_domain_by_ec_key(key, &pub->domain);
    if (ret != TEE_SUCCESS) {
        tloge("get domain fail");
        goto error;
    }
error:
    BN_free(x);
    BN_free(y);
    return ret;
}
int32_t ecc_import_pub(ecc_pub_key_t *pub, const uint8_t *in, uint32_t inlen)
{
    bool check = (pub == NULL || in == NULL);
    if (check) {
        tloge("soft_enine: %s\n", "ecc import pub in error");
        return -1;
    }
    EC_KEY *keyp             = NULL;
    const unsigned char *inp = (const unsigned char *)in;
    keyp                     = d2i_EC_PUBKEY(&keyp, &inp, inlen);
    if (keyp == NULL) {
        tloge("soft_enine: %s\n", "asn1 to ec public key fail");
        return -1;
    }
    TEE_Result ret = ecc_ecpubkey_boring_to_tee(keyp, pub);
    EC_KEY_free(keyp);
    keyp = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "boring ec key to tee fail");
        return -1;
    }
    return 1;
}
static TEE_Result ecc_priv_key_boring_to_tee(ecc_priv_key_t *priv, const EC_KEY *key)
{
    const BIGNUM *priv_bn = EC_KEY_get0_private_key(key);
    if (priv_bn == NULL) {
        tloge("soft_enine: %s\n", "ec key error, get private fail");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t domain = 0;
    TEE_Result ret  = ecc_get_domain_by_ec_key(key, &domain);
    if (ret != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "get domain by ec key fail");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    priv->domain             = domain;
    uint32_t private_key_len = (uint32_t)BN_num_bytes(priv_bn);
    if (private_key_len > EC_FIX_BUFFER_LEN) {
        tloge("soft_enine: %s\n", "private key to buffer error");
        return TEE_ERROR_GENERIC;
    }
    priv->r_len = (uint32_t)BN_bn2bin(priv_bn, priv->r);

    return TEE_SUCCESS;
}
int32_t ecc_import_priv(ecc_priv_key_t *priv, const uint8_t *in, uint32_t inlen)
{
    bool check = (priv == NULL || in == NULL);
    if (check) {
        tloge("soft_enine: %s\n", "ecc import priv in error");
        return -1;
    }
    EC_KEY *key        = NULL;
    const uint8_t *inp = in;
    key                = d2i_ECPrivateKey(&key, &inp, inlen);
    if (key == NULL) {
        tloge("soft_enine: %s\n", "asn1 to ec public key fail");
        return -1;
    }
    TEE_Result ret = ecc_priv_key_boring_to_tee(priv, key);
    EC_KEY_free(key);
    key = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "boring ec private key to tee fail");
        return -1;
    }

    return priv->r_len;
}

/* Read next TLV (Type-Length-Value) from ASN1 buffer buf
  @param type         [out] type of TLV
  @param header_len     [out] length of TLV
  @param buf         [in]  input TLV
  @param buf_len     [in]  Length of buf in bytes
  @Return length if next tlv can be found and otherwice -1.
 * */
int32_t get_next_tlv(uint32_t *type, uint32_t *header_len, const uint8_t *buf, uint32_t buf_len)
{
    uint32_t length = 0;
    if (type == NULL || header_len == NULL || buf == NULL) {
        tloge("soft_enine: %s\n", "get next tlv in error");
        return -1;
    }
    if (buf_len < CRYPTO_NUMBER_THREE) {
        tloge("soft_enine: %s\n", "buf_len too short.\n");
        return -1;
    }
    *type = buf[0];
    buf++;
    buf_len--;
    if (buf[0] < 0x80) { /* Current byte tells the length */
        length = (uint32_t)buf[0];
        buf++;
        buf_len--;
        *header_len = CRYPTO_NUMBER_TWO;
    } else {
        /* bit 8 is set */
        switch (buf[0] & 0x7F) {
        case OBJ_LEN_ONE: /* object length is one */
            buf++;
            length = (uint32_t)buf[0];
            buf++;
            buf_len -= CRYPTO_NUMBER_TWO;
            *header_len = CRYPTO_NUMBER_THREE;
            break;
        case OBJ_LEN_TWO: /* object length is two */
            if (buf_len < CRYPTO_NUMBER_THREE) {
                tloge("soft_enine: %s\n", "buf len is error");
                return -1;
            }
            buf_len -= CRYPTO_NUMBER_THREE;
            buf++;
            length = (((uint32_t)buf[0]) << CRYPTO_NUMBER_EIGHT) + (uint32_t)buf[1];
            *header_len = CRYPTO_NUMBER_FOUR;
            break;
        default: /* Object length does not make sense */
            return -1;
        }
    }
    /* Check that tag length can fit into buffer */
    if (length > buf_len) {
        tloge("soft_enine: %s\n", "get tlv buffer too short");
        return -1;
    }
    return length;
}

static int32_t get_ecsda_signature(ECDSA_SIG *sig_data, uint8_t *signature, uint32_t sig_size)
{
    uint8_t *outp    = NULL;
    int32_t sign_len = i2d_ECDSA_SIG(sig_data, &outp);
    OPENSSL_free(outp);
    if (sign_len < 0 || sign_len > (int32_t)sig_size) {
        tloge("out buffer too small");
        return -1;
    }
    outp = signature;
    return i2d_ECDSA_SIG(sig_data, &outp);
}

int32_t ecc_sign_digest(uint8_t *signature, uint32_t sig_size, uint8_t *in, uint32_t in_len, ecc_priv_key_t *priv)
{
    bool check = (signature == NULL || sig_size == 0 || (in == NULL && in_len != 0) || priv == NULL);
    if (check) {
        tloge("soft_enine: %s\n", "input param is NULL");
        return -1;
    }

    EC_KEY *eckey = NULL;
    int32_t cur = ec_nid_tom2boringssl(priv->domain);
    if (cur == -1) {
        tloge("soft_enine: %s\n", "cur get error");
        return -1;
    }
    uint32_t tmp_cur = priv->domain;
    priv->domain     = (uint32_t)cur;
    TEE_Result ret   = ecc_privkey_tee_to_boring(priv, (void **)&eckey);
    priv->domain     = tmp_cur;
    if (ret != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "Tee Private Key To Boring Key error");
        return -1;
    }
    ECDSA_SIG *sig_data = ECDSA_do_sign(in, in_len, eckey);
    EC_KEY_free(eckey);
    eckey = NULL;
    /* boring to asn */
    if (sig_data == NULL) {
        tloge("soft_enine: %s\n", "boring sign error");
        return -1;
    }
    int32_t sign_len = get_ecsda_signature(sig_data, signature, sig_size);
    ECDSA_SIG_free(sig_data);

    return sign_len;
}
int32_t ecc_verify_digest(const uint8_t *signature, uint32_t sig_len, uint8_t *in, uint32_t in_len, ecc_pub_key_t *pub)
{
    bool check = (signature == NULL || sig_len == 0 || (in == NULL && in_len != 0) || pub == NULL);
    if (check) {
        tloge("soft_enine: %s\n", "input param is NULL");
        return -1;
    }

    ECDSA_SIG *outp    = NULL;
    const uint8_t *tmp = signature;
    EC_KEY *eckey      = NULL;
    int32_t ret;
    int cur = ec_nid_tom2boringssl(pub->domain);
    if (cur < 0) {
        tloge("soft_enine: %s\n", "get cur error");
        return -1;
    }
    outp = d2i_ECDSA_SIG(&outp, &tmp, sig_len);
    if (outp == NULL) {
        tloge("soft_enine: %s\n", "asn to boring fail, sign may be dx");
        return -1;
    }
    uint32_t tmp_cur = pub->domain;
    pub->domain      = (uint32_t)cur;
    ret              = (int32_t)ecc_pubkey_tee_to_boring(pub, &eckey);
    pub->domain      = tmp_cur;
    if (ret != 0) {
        ECDSA_SIG_free(outp);
        tloge("PubKeyToBoringKey key error");
        return -1;
    }
    ret = ECDSA_do_verify(in, in_len, outp, eckey);
    ECDSA_SIG_free(outp);
    outp = NULL;
    EC_KEY_free(eckey);
    eckey = NULL;
    if (ret != 1) {
        tloge("soft_enine: %s\n", "boring verify error");
        return 0;
    }
    return 1;
}
#ifdef CRYPTO_SSL_SUPPORT_X509
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
#ifdef BORINGSSL_ENABLE
static int add_ext(X509 *cert, int nid, char *value)
#else
static int add_ext(X509 *cert, int nid, const char *value)
#endif
{
    X509_EXTENSION *ex = NULL;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (ex == NULL) {
        tloge("soft_enine: %s\n", "conf nid fail");
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
#endif

#ifdef CRYPTO_SSL_SUPPORT_X509
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
    return ret;
}
#endif
#else
int ec_nid_tom2boringssl(uint32_t domain)
{
    (void)domain;
    return -1;
}
TEE_Result ecc_privkey_tee_to_boring(void *priv, void **eckey)
{
    (void)priv;
    (void)eckey;
    return TEE_ERROR_NOT_SUPPORTED;
}

int ecc_derive_public_key(ecc_priv_key_t *priv_info, ecc_pub_key_t *pub_info)
{
    (void)priv_info;
    (void)pub_info;
    return -1;
}

int derive_ecc_private_key_from_huk(ecc_priv_key_t *priv, const uint8_t *secret, uint32_t sec_len)
{
    (void)priv;
    (void)secret;
    (void)sec_len;
    return -1;
}

int derive_private_key_from_secret(void *priv, uint8_t *secret, uint32_t secret_len, uint32_t bits, uint32_t key_type,
                                   uint8_t *file_name)
{
    (void)priv;
    (void)secret;
    (void)secret_len;
    (void)bits;
    (void)key_type;
    (void)file_name;
    return -1;
}

int32_t ecc_export_pub(uint8_t *out, uint32_t out_size, ecc_pub_key_t *pub)
{
    (void)out;
    (void)out_size;
    (void)pub;
    return -1;
}

int32_t ecc_import_pub(ecc_pub_key_t *pub, const uint8_t *in, uint32_t inlen)
{
    (void)pub;
    (void)in;
    (void)inlen;
    return -1;
}

int32_t ecc_import_priv(ecc_priv_key_t *priv, const uint8_t *in, uint32_t inlen)
{
    (void)priv;
    (void)in;
    (void)inlen;
    return -1;
}

int32_t get_next_tlv(uint32_t *type, uint32_t *header_len, const uint8_t *buf, uint32_t buf_len)
{
    (void)type;
    (void)header_len;
    (void)buf;
    (void)buf_len;
    return -1;
}

int32_t ecc_sign_digest(uint8_t *signature, uint32_t sig_size, uint8_t *in, uint32_t in_len, ecc_priv_key_t *priv)
{
    (void)signature;
    (void)sig_size;
    (void)in;
    (void)in_len;
    (void)priv;
    return -1;
}

int32_t ecc_verify_digest(const uint8_t *signature, uint32_t sig_len, uint8_t *in, uint32_t in_len, ecc_pub_key_t *pub)
{
    (void)signature;
    (void)sig_len;
    (void)in;
    (void)in_len;
    (void)pub;
    return -1;
}
#endif

#if (!defined(CRYPTO_SSL_SUPPORT_X509))
int32_t recover_root_cert(uint8_t *cert, uint32_t cert_len, const void *priv, uint32_t keytype)
{
    (void)cert;
    (void)cert_len;
    (void)priv;
    (void)keytype;
    tloge("mix system do not support recover root cert\n");
    return -1;
}

int32_t sign_pkcs10(uint8_t *cert, uint32_t cert_len,
                    const uint8_t *csr, uint32_t csr_len, const validity_period_t *valid,
                    const uint8_t *serial_number, uint32_t serial_length, const void *priv, uint32_t keytype)
{
    (void)cert;
    (void)cert_len;
    (void)csr;
    (void)csr_len;
    (void)valid;
    (void)serial_number;
    (void)serial_length;
    (void)priv;
    (void)keytype;
    return -1;
}
#endif
