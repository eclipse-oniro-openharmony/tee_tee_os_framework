/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: process keymaster crypto info
 * Create: 2018.7.16
 */

#include <openssl/err.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/sms4.h>
#include <openssl/modes.h>
#include <openssl/rand.h>
#include <ec_lcl.h>
#include <bn_lcl.h>
#include <sm2_lcl.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_err.h>
#include <tee_crypto_err.h>
#include <tee_crypto_api.h>
#include <tee_gmssl_api.h>
#include <crypto_driver_adaptor.h>

#define KEY_SIZE             32
#define KEY_SIZE_2           64
#define HEX_LEN              2
#define RAND_SIZE            64
#define SM4_BLOCK            16
#define MOD_LEN              65 /* 256/8*2+1 */
#define ONLY_PUBLIC_LEN      3
#define KEYPAIR_LEN          4
#define GMSSL_OK             1
#define GMSSL_ERR            0
#define STR_END_ZERO         1
#define HASH_SIZE            32
#define COORDINATE_LEN       32
#define COORDINATE_NUM       2
#define SM2_CIPHER_START     0x04
#define SM2_CIPHER_START_LEN 1
#define SIG_COMPONENT_SIZE   32
#define SIG_COMPONENT_NUM    2
#define SM2_CIPHER_INCREASE  97
#define BYTE_TO_BIT          8

int32_t get_gmssl_error(int32_t alg_id, int32_t tee_error)
{
    int32_t engine_error = ERR_GET_REASON(ERR_peek_last_error());

    /* clear opensour lib err state */
    ERR_clear_error();

    if (engine_error == 0)
        return tee_error;
    else
        return TEE_EXT_ERROR_BASE | CRYPTO_MODULE_ERR_ID | (uint32_t)alg_id | (uint32_t)engine_error;
}

struct sm2_public_key {
    uint8_t sm2_x[KEY_SIZE_2 + 1];
    uint8_t sm2_y[KEY_SIZE_2 + 1];
    uint32_t group;
};

struct sm2_public_key_2 {
    uint8_t sm2_x[KEY_SIZE];
    uint8_t sm2_y[KEY_SIZE];
    uint32_t group;
};

typedef struct sm2_key_pair_s {
    char x[KEY_SIZE_2];
    char y[KEY_SIZE_2];
    char d[KEY_SIZE_2];
} sm2_key_pair;

struct ec_key_pair_bignum_t {
    EC_GROUP *group;
    EC_POINT *point;
    BIGNUM *big_p;
    BIGNUM *big_a;
    BIGNUM *big_b;
    BIGNUM *big_d;
    BIGNUM *big_x;
    BIGNUM *big_y;
    BIGNUM *big_n;
    BIGNUM *big_h;
    BN_CTX *ctx;
};

struct sm2_eckey_get_dxy_t {
    char *d;
    char *x;
    char *y;
    int32_t d_len;
    int32_t x_len;
    int32_t y_len;
};

struct sm2_new_ec_group_t {
    const char *p_hex;
    const char *a_hex;
    const char *b_hex;
    const char *x_hex;
    const char *y_hex;
    const char *n_hex;
    const char *h_hex;
};

static void sm2_new_ec_group_free(struct ec_key_pair_bignum_t *ec_key_pair_bignum, bool flag)
{
    BN_CTX_free(ec_key_pair_bignum->ctx);
    ec_key_pair_bignum->ctx = NULL;
    BN_free(ec_key_pair_bignum->big_p);
    ec_key_pair_bignum->big_p = NULL;
    BN_free(ec_key_pair_bignum->big_a);
    ec_key_pair_bignum->big_a = NULL;
    BN_free(ec_key_pair_bignum->big_b);
    ec_key_pair_bignum->big_b = NULL;
    BN_free(ec_key_pair_bignum->big_x);
    ec_key_pair_bignum->big_x = NULL;
    BN_free(ec_key_pair_bignum->big_y);
    ec_key_pair_bignum->big_y = NULL;
    BN_free(ec_key_pair_bignum->big_n);
    ec_key_pair_bignum->big_n = NULL;
    BN_free(ec_key_pair_bignum->big_h);
    ec_key_pair_bignum->big_h = NULL;
    EC_POINT_free(ec_key_pair_bignum->point);
    ec_key_pair_bignum->point = NULL;
    if (flag && (ec_key_pair_bignum->group != NULL)) {
        EC_GROUP_free(ec_key_pair_bignum->group);
        ec_key_pair_bignum->group = NULL;
    }
}

static int32_t sm2_new_group_prime_field(struct ec_key_pair_bignum_t *ec_key_pair_bignum)
{
    ec_key_pair_bignum->group = EC_GROUP_new_curve_GFp(ec_key_pair_bignum->big_p, ec_key_pair_bignum->big_a,
        ec_key_pair_bignum->big_b, ec_key_pair_bignum->ctx);
    if (ec_key_pair_bignum->group == NULL)
        return GMSSL_ERR;

    ec_key_pair_bignum->point = EC_POINT_new(ec_key_pair_bignum->group);
    if (ec_key_pair_bignum->point == NULL)
        return GMSSL_ERR;

    return EC_POINT_set_affine_coordinates_GFp(ec_key_pair_bignum->group, ec_key_pair_bignum->point,
        ec_key_pair_bignum->big_x, ec_key_pair_bignum->big_y, ec_key_pair_bignum->ctx);
}

static int32_t sm2_new_group_other_field(struct ec_key_pair_bignum_t *ec_key_pair_bignum)
{
    ec_key_pair_bignum->group = EC_GROUP_new_curve_GF2m(ec_key_pair_bignum->big_p, ec_key_pair_bignum->big_a,
        ec_key_pair_bignum->big_b, ec_key_pair_bignum->ctx);
    if (ec_key_pair_bignum->group == NULL)
        return GMSSL_ERR;

    ec_key_pair_bignum->point = EC_POINT_new(ec_key_pair_bignum->group);
    if (ec_key_pair_bignum->point == NULL)
        return GMSSL_ERR;

    return EC_POINT_set_affine_coordinates_GF2m(ec_key_pair_bignum->group, ec_key_pair_bignum->point,
        ec_key_pair_bignum->big_x, ec_key_pair_bignum->big_y, ec_key_pair_bignum->ctx);
}

EC_GROUP *sm2_new_ec_group(int is_prime_field, const struct sm2_new_ec_group_t *ec_group_t)
{
    int ret;
    bool check = true;
    struct ec_key_pair_bignum_t ec_key_pair_bignum = {0};

    ec_key_pair_bignum.ctx = BN_CTX_new();
    if (ec_key_pair_bignum.ctx == NULL)
        goto err;

    check = (ec_group_t == NULL || BN_hex2bn(&(ec_key_pair_bignum.big_p), (ec_group_t->p_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_a), (ec_group_t->a_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_b), (ec_group_t->b_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_x), (ec_group_t->x_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_y), (ec_group_t->y_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_n), (ec_group_t->n_hex)) == 0 ||
        BN_hex2bn(&(ec_key_pair_bignum.big_h), (ec_group_t->h_hex)) == 0);
    if (check)
        goto err;

    if (is_prime_field)
        ret = sm2_new_group_prime_field(&ec_key_pair_bignum);
    else
        ret = sm2_new_group_other_field(&ec_key_pair_bignum);
    if (ret == GMSSL_ERR)
        goto err;

    if (EC_GROUP_set_generator(ec_key_pair_bignum.group, ec_key_pair_bignum.point,
        ec_key_pair_bignum.big_n, ec_key_pair_bignum.big_h) == 0)
        goto err;
    EC_GROUP_set_asn1_flag(ec_key_pair_bignum.group, 0);
    EC_GROUP_set_point_conversion_form(ec_key_pair_bignum.group, POINT_CONVERSION_UNCOMPRESSED);

    check = false;
err:
    sm2_new_ec_group_free(&ec_key_pair_bignum, check);
    return ec_key_pair_bignum.group;
}

static int32_t set_sm2_pub_key(EC_KEY *ec_key, BIGNUM **x, BIGNUM **y, const char *x_p, const char *y_p)
{
    bool check = (BN_hex2bn(x, x_p) == GMSSL_ERR || BN_hex2bn(y, y_p) == GMSSL_ERR ||
        EC_KEY_set_public_key_affine_coordinates(ec_key, *x, *y) == GMSSL_ERR);
    if (check) {
        tloge("set sm2 pub key failed\n");
        return GMSSL_ERR;
    }
    return GMSSL_OK;
}

EC_KEY *sm2_new_ec_key(const EC_GROUP *group, const char *sk, const char *x_p, const char *y_p)
{
    int ok    = 0;
    BIGNUM *d = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    if (group == NULL) {
        tloge("parameter is NULL!\n");
        return NULL;
    }
    EC_KEY *ec_key = EC_KEY_new();
    if (ec_key == NULL)
        return NULL;

    int32_t ret = EC_KEY_set_group(ec_key, group);
    if (ret == GMSSL_ERR) {
        tloge("gmssl: %s\n", "EC KEY set group failed\n");
        goto end;
    }

    if (sk != NULL) {
        ret = BN_hex2bn(&d, sk);
        if (ret == GMSSL_ERR) {
            tloge("gmssl: %s\n", "BN hex2bn failed\n");
            goto end;
        }

        ret = EC_KEY_set_private_key(ec_key, d);
        if (ret == GMSSL_ERR) {
            tloge("gmssl: %s\n", "EC KEY set private key failed\n");
            goto end;
        }
    }

    bool check = (x_p != NULL) && (y_p != NULL);
    if (check) {
        ret = set_sm2_pub_key(ec_key, &x, &y, x_p, y_p);
        if (ret == GMSSL_ERR)
            goto end;
    }

    ok = 1;
end:
    BN_free(d);
    d = NULL;
    BN_free(x);
    x = NULL;
    BN_free(y);
    y = NULL;
    if ((ok == 0) && (ec_key != NULL)) {
        EC_KEY_free(ec_key);
        ec_key = NULL;
    }
    return ec_key;
}

TEE_Result sm2_buf2hexstr(const unsigned char *buffer, uint32_t len, char *out, uint32_t out_len)
{
    bool check = (buffer == NULL || out == NULL || len == 0);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    static const char hexdig[] = "0123456789ABCDEF";
    uint8_t *q                 = NULL;
    const unsigned char *p     = NULL;
    uint32_t i;

    if (out_len < (len << 1)) {
        tloge("out len is not large enough!");
        return CRYPTO_BAD_PARAMETERS;
    }

    q = (uint8_t *)out;
    for (i = 0, p = buffer; i < len; i++, p++) {
        *q++ = hexdig[(*p >> 4) & 0xf]; /* Shift right four digits */
        *q++ = hexdig[*p & 0xf];
    }
    return CRYPTO_SUCCESS;
}

static TEE_Result sm2_adapt_ec_key_buf(const char *src_buff, uint32_t src_buff_len,
    char *dest_buff, uint32_t dest_buff_len)
{
    if (dest_buff_len < src_buff_len) {
        tloge("The dest buff is too short\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    errno_t rc = memcpy_s(dest_buff + (dest_buff_len - src_buff_len), src_buff_len, src_buff, src_buff_len);
    if (rc != EOK) {
        tloge("memcpy error in fill zero to buff head\n");
        return TEE_ERROR_SECURITY;
    }
    if (src_buff_len == dest_buff_len)
        return CRYPTO_SUCCESS;
    rc = memset_s(dest_buff, dest_buff_len - src_buff_len, '0', dest_buff_len - src_buff_len);
    if (rc != EOK) {
        tloge("memset error in fill zero to buff head\n");
        return TEE_ERROR_SECURITY;
    }
    return CRYPTO_SUCCESS;
}

static int32_t sm2_get_dxy_bignum_to_buf(const struct ec_key_pair_bignum_t *ec_key_pair_bignum,
    struct memref_t *x, struct memref_t *y, struct memref_t *d)
{
    int32_t ret = 0;
    struct memref_t dd = {0};
    struct memref_t xx = {0};
    struct memref_t yy = {0};

    dd.buffer = (uintptr_t)BN_bn2hex(ec_key_pair_bignum->big_d);
    xx.buffer = (uintptr_t)BN_bn2hex(ec_key_pair_bignum->big_x);
    yy.buffer = (uintptr_t)BN_bn2hex(ec_key_pair_bignum->big_y);
    bool check = (dd.buffer == 0 || xx.buffer == 0 || yy.buffer == 0);
    if (check) {
        tloge("gmssl: %s\n", "BN bn2hex failed!\n");
        ret = 0;
        goto end;
    }

    dd.size = strlen((const char *)(uintptr_t)dd.buffer);
    xx.size = strlen((const char *)(uintptr_t)xx.buffer);
    yy.size = strlen((const char *)(uintptr_t)yy.buffer);

    TEE_Result rc = sm2_adapt_ec_key_buf((const char *)(uintptr_t)xx.buffer, xx.size,
        (char *)(uintptr_t)x->buffer, KEY_SIZE_2);
    if (rc != CRYPTO_SUCCESS) {
        ret = 0;
        tloge("adapt ec key buf failed, buf len=%u\n", xx.size);
        goto end;
    }
    rc = sm2_adapt_ec_key_buf((const char *)(uintptr_t)yy.buffer, yy.size, (char *)(uintptr_t)y->buffer, KEY_SIZE_2);
    if (rc != CRYPTO_SUCCESS) {
        ret = 0;
        tloge("adapt ec key buf failed, buf len=%u\n", yy.size);
        goto end;
    }
    rc = sm2_adapt_ec_key_buf((const char *)(uintptr_t)dd.buffer, dd.size, (char *)(uintptr_t)d->buffer, KEY_SIZE_2);
    if (rc != CRYPTO_SUCCESS) {
        ret = 0;
        tloge("adapt ec key buf failed, buf len=%u\n", dd.size);
        goto end;
    }

    ret = 1;
end:
    OPENSSL_free((void *)(uintptr_t)dd.buffer);
    dd.buffer = 0;
    OPENSSL_free((void *)(uintptr_t)xx.buffer);
    xx.buffer = 0;
    OPENSSL_free((void *)(uintptr_t)yy.buffer);
    yy.buffer = 0;
    return ret;
}

static void free_ec_key_pair_bignum(struct ec_key_pair_bignum_t *ec_key_pair_bignum)
{
    BN_free(ec_key_pair_bignum->big_x);
    ec_key_pair_bignum->big_x = NULL;
    BN_free(ec_key_pair_bignum->big_y);
    ec_key_pair_bignum->big_y = NULL;
    BN_CTX_free(ec_key_pair_bignum->ctx);
    ec_key_pair_bignum->ctx = NULL;
}

int sm2_eckey_get_dxy(const EC_GROUP *group, const EC_KEY *ec_key,
    const struct sm2_eckey_get_dxy_t *sm2_eckey_get_dxy_t)
{
    bool check = (group == NULL || ec_key == NULL || sm2_eckey_get_dxy_t == NULL || sm2_eckey_get_dxy_t->d == NULL ||
        sm2_eckey_get_dxy_t->x == NULL || sm2_eckey_get_dxy_t->y == NULL || sm2_eckey_get_dxy_t->d_len != KEY_SIZE_2 ||
        sm2_eckey_get_dxy_t->x_len != KEY_SIZE_2 || sm2_eckey_get_dxy_t->y_len != KEY_SIZE_2);
    if (check) {
        tloge("group or ec_key is NULL!\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct ec_key_pair_bignum_t ec_key_pair_bignum = {0};
    ec_key_pair_bignum.point = (EC_POINT *)EC_KEY_get0_public_key(ec_key);
    ec_key_pair_bignum.big_d = (BIGNUM *)EC_KEY_get0_private_key(ec_key);
    ec_key_pair_bignum.big_x  = BN_new();
    ec_key_pair_bignum.big_y  = BN_new();
    ec_key_pair_bignum.ctx = BN_CTX_new();

    check = (ec_key_pair_bignum.big_d == NULL || ec_key_pair_bignum.point == NULL || ec_key_pair_bignum.big_x == NULL ||
        ec_key_pair_bignum.big_y == NULL || ec_key_pair_bignum.ctx == NULL);
    if (check) {
        tloge("gmssl: %s\n", "point or bigbum is NULL!\n");
        free_ec_key_pair_bignum(&ec_key_pair_bignum);
        return GMSSL_ERR;
    }

    int32_t sm2_ret = EC_POINT_get_affine_coordinates_GF2m(group, ec_key_pair_bignum.point,
        ec_key_pair_bignum.big_x, ec_key_pair_bignum.big_y, ec_key_pair_bignum.ctx);
    if (sm2_ret == GMSSL_ERR) {
        tloge("gmssl: %s\n", "EC POINT get affine coordinates GF2m failed!\n");
        free_ec_key_pair_bignum(&ec_key_pair_bignum);
        return GMSSL_ERR;
    }

    struct memref_t dd = {0};
    struct memref_t xx = {0};
    struct memref_t yy = {0};

    dd.buffer = (uintptr_t)(sm2_eckey_get_dxy_t->d);
    dd.size = sm2_eckey_get_dxy_t->d_len;
    xx.buffer = (uintptr_t)(sm2_eckey_get_dxy_t->x);
    xx.size = sm2_eckey_get_dxy_t->x_len;
    yy.buffer = (uintptr_t)(sm2_eckey_get_dxy_t->y);
    yy.size = sm2_eckey_get_dxy_t->y_len;

    int32_t ret = sm2_get_dxy_bignum_to_buf(&ec_key_pair_bignum, &xx, &yy, &dd);
    free_ec_key_pair_bignum(&ec_key_pair_bignum);
    return ret;
}

static EC_KEY *new_ec_key(uint32_t group_type, const char *d, const char *x, const char *y)
{
    EC_GROUP *sm2_p256_group = NULL;
    EC_KEY *ec_key           = NULL;
    struct sm2_new_ec_group_t ec_group_t = {0};

    if (group_type == SM2_GROUP_NOSTANDARD) {
        ec_group_t.p_hex = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
        ec_group_t.a_hex = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
        ec_group_t.b_hex = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
        ec_group_t.x_hex = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
        ec_group_t.y_hex = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
        ec_group_t.n_hex = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
        ec_group_t.h_hex = "1";

        sm2_p256_group = sm2_new_ec_group(1, &ec_group_t);
    } else {
        sm2_p256_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    }
    if (sm2_p256_group == NULL) {
        tloge("sm2 new group failed!");
        return NULL;
    }

    ec_key = sm2_new_ec_key(sm2_p256_group, d, x, y);
    if (ec_key == NULL) {
        tloge("sm2_new_ec_key failed!\n");
        EC_GROUP_free(sm2_p256_group);
        return NULL;
    }
    EC_GROUP_free(sm2_p256_group);
    return ec_key;
}

static EC_KEY *get_sm2_pub_key(const void *key)
{
    int32_t ret;
    struct ecc_pub_key_t *pubkey = (struct ecc_pub_key_t *)key;
    uint32_t group_type = pubkey->domain_id;

    if (pubkey->x_len == KEY_SIZE) {
        char x[KEY_SIZE_2 + STR_END_ZERO] = { 0 };
        char y[KEY_SIZE_2 + STR_END_ZERO] = { 0 };
        ret = (int32_t)sm2_buf2hexstr(pubkey->x, KEY_SIZE, x, KEY_SIZE_2 + STR_END_ZERO);
        if (ret != CRYPTO_SUCCESS) {
            tloge("buffer to hexstring failed!");
            return NULL;
        }

        ret = (int32_t)sm2_buf2hexstr(pubkey->y, KEY_SIZE, y, KEY_SIZE_2 + STR_END_ZERO);
        if (ret != CRYPTO_SUCCESS) {
            tloge("buffer to hexstring failed!");
            return NULL;
        }
        return new_ec_key(group_type, NULL, x, y);
    }

    return new_ec_key(group_type, NULL, (char *)pubkey->x, (char *)pubkey->y);
}

static EC_KEY *get_sm2_priv_key(const void *key)
{
    int32_t ret;
    struct ecc_priv_key_t *privkey = (struct ecc_priv_key_t *)key;
    uint32_t group_type = privkey->domain_id;

    if (privkey->r_len == KEY_SIZE) {
        char d[KEY_SIZE_2 + STR_END_ZERO] = { 0 };
        ret = (int32_t)sm2_buf2hexstr(privkey->r, KEY_SIZE, d, KEY_SIZE_2 + STR_END_ZERO);
        if (ret != CRYPTO_SUCCESS) {
            tloge("buffer to hexstring failed!");
            return NULL;
        }
        return new_ec_key(group_type, d, NULL, NULL);
    }

    return new_ec_key(group_type, (const char *)privkey->r, NULL, NULL);
}

EC_KEY *get_sm2_key(const void *key, uint32_t mode)
{
    if (key == NULL) {
        tloge("params is invalid");
        return NULL;
    }

    switch (mode) {
    case ENC_MODE:
    case VERIFY_MODE:
        return get_sm2_pub_key(key);
    case DEC_MODE:
    case SIGN_MODE:
        return get_sm2_priv_key(key);
    default:
        tloge("bad params");
        return NULL;
    }
}

static EC_KEY *get_sm2_pub_key_2(const void *key)
{
    struct ecc_pub_key_t *pubkey = (struct ecc_pub_key_t *)key;
    char x[KEY_SIZE_2 + STR_END_ZERO] = { 0 };
    char y[KEY_SIZE_2 + STR_END_ZERO] = { 0 };

    int32_t ret = (int32_t)sm2_buf2hexstr(pubkey->x, KEY_SIZE, x, KEY_SIZE_2 + STR_END_ZERO);
    if (ret != CRYPTO_SUCCESS) {
        tloge("buffer to hexstring failed!");
        return NULL;
    }

    ret = (int32_t)sm2_buf2hexstr(pubkey->y, KEY_SIZE, y, KEY_SIZE_2 + STR_END_ZERO);
    if (ret != CRYPTO_SUCCESS) {
        tloge("buffer to hexstring failed!");
        return NULL;
    }

    return new_ec_key(pubkey->domain_id, NULL, x, y);
}

static EC_KEY *get_sm2_priv_key_2(const void *key)
{
    char d[KEY_SIZE_2 + STR_END_ZERO] = { 0 };
    struct ecc_priv_key_t *privkey = (struct ecc_priv_key_t *)key;

    int32_t ret = (int32_t)sm2_buf2hexstr(privkey->r, KEY_SIZE, d, KEY_SIZE_2 + STR_END_ZERO);
    if (ret != CRYPTO_SUCCESS) {
        tloge("buffer to hexstring failed!");
        return NULL;
    }

    return new_ec_key(privkey->domain_id, d, NULL, NULL);
}

EC_KEY *get_sm2_key_2(const void *key, uint32_t mode)
{
    if (key == NULL) {
        tloge("params is invalid");
        return NULL;
    }

    switch (mode) {
    case ENC_MODE:
    case VERIFY_MODE:
        return get_sm2_pub_key_2(key);
    case DEC_MODE:
    case SIGN_MODE:
        return get_sm2_priv_key_2(key);
    default:
        tloge("bad params");
        return NULL;
    }
}

static void gmssl_generate_random(void)
{
    char rand_seed[RAND_SIZE] = { 0 };
    uint32_t rand_seed_size   = RAND_SIZE;

    int32_t rand_state = RAND_status();
    if (rand_state != GMSSL_OK) {
        tloge("RAND status is failed!\n");
        TEE_GenerateRandom(rand_seed, rand_seed_size);
        RAND_seed((const void *)rand_seed, (int32_t)rand_seed_size);
    }
}


static int32_t sm2_encrypt(EC_KEY *ec_key, const void *src_data, uint32_t src_len,
    void *dest_data, uint32_t *dest_len)
{
    SM2CiphertextValue *cv    = NULL;

    if (src_len > SM2_MAX_PLAINTEXT_LENGTH) {
        tloge("src len is too big!");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (*dest_len < (src_len + SM2_INCREASE_MAX)) {
        tloge("dest len is not large enough to hold the result!");
        return TEE_ERROR_SHORT_BUFFER;
    }

    gmssl_generate_random();

    /* use publicKey to encrypt */
    cv = SM2_do_encrypt(EVP_sm3(), src_data, src_len, ec_key);
    if (cv == NULL) {
        tloge("SM2 do encrypt failed");
        return get_gmssl_error(SM2_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }

    /* pass cv to destData */
    size_t clen = (size_t)i2d_SM2CiphertextValue(cv, (unsigned char **)&dest_data);
    bool check = (clen <= GMSSL_ERR || clen > UINT32_MAX);
    if (check) {
        tloge("i2d SM2CiphertextValue failed");
        SM2CiphertextValue_free(cv);
        return CRYPTO_BAD_PARAMETERS;
    }

    *dest_len = (uint32_t)clen;
    SM2CiphertextValue_free(cv);
    return CRYPTO_SUCCESS;
}

static TEE_Result cv_to_cip_check(const SM2CiphertextValue *cv, const uint32_t *len)
{
    if ((uint32_t)(cv->hash->length) >
        UINT32_MAX - COORDINATE_LEN * COORDINATE_NUM - SM2_CIPHER_START_LEN - (uint32_t)(cv->ciphertext->length)) {
        tloge("the out buffer is too small\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (*len < (uint32_t)(COORDINATE_LEN * COORDINATE_NUM + cv->hash->length +
        cv->ciphertext->length + SM2_CIPHER_START_LEN)) {
        tloge("the out buffer is too small\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (BN_num_bytes(cv->xCoordinate) > COORDINATE_LEN)
        return CRYPTO_BAD_PARAMETERS;

    return CRYPTO_SUCCESS;
}

static int32_t copy_data_to_cipher(uint8_t *cipher, uint32_t *len, const uint8_t *x_buf, const uint8_t *y_buf,
    const SM2CiphertextValue *cv)
{
    if (memcpy_s(cipher + SM2_CIPHER_START_LEN, *len - SM2_CIPHER_START_LEN, x_buf, COORDINATE_LEN) != EOK)
        return CRYPTO_ERROR_SECURITY;

    if (memcpy_s(cipher + SM2_CIPHER_START_LEN + COORDINATE_LEN, *len - SM2_CIPHER_START_LEN - COORDINATE_LEN,
        y_buf, COORDINATE_LEN) != EOK)
        return CRYPTO_ERROR_SECURITY;

    errno_t rc = memcpy_s(cipher + COORDINATE_LEN * COORDINATE_NUM + SM2_CIPHER_START_LEN,
        *len - COORDINATE_LEN * COORDINATE_NUM - SM2_CIPHER_START_LEN,
        cv->hash->data, cv->hash->length);
    if (rc != EOK) {
        tloge("get hash failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    rc = memcpy_s(cipher + COORDINATE_LEN * COORDINATE_NUM + cv->hash->length + SM2_CIPHER_START_LEN,
        *len - COORDINATE_LEN * COORDINATE_NUM - cv->hash->length - SM2_CIPHER_START_LEN,
        cv->ciphertext->data, cv->ciphertext->length);
    if (rc != EOK) {
        tloge("get cipher text failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    *len = COORDINATE_LEN * COORDINATE_NUM + cv->hash->length + cv->ciphertext->length + SM2_CIPHER_START_LEN;
    return CRYPTO_SUCCESS;
}

static TEE_Result cv_to_cip(SM2CiphertextValue *cv, uint8_t *cipher, uint32_t *len)
{
    cipher[0]                     = SM2_CIPHER_START;
    uint8_t x_buf[COORDINATE_LEN] = { 0 };
    uint8_t y_buf[COORDINATE_LEN] = { 0 };

    TEE_Result ret = cv_to_cip_check(cv, len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("cv to cip check failed\n");
        return ret;
    }

    int32_t x_len = BN_bn2bin(cv->xCoordinate,
                              x_buf + COORDINATE_LEN - BN_num_bytes(cv->xCoordinate));
    if (x_len == 0) {
        tloge("get x coordinate failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t y_len = BN_bn2bin(cv->yCoordinate,
                              y_buf + COORDINATE_LEN - BN_num_bytes(cv->yCoordinate));
    if (y_len == 0) {
        tloge("get y coordinate failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    return (TEE_Result)copy_data_to_cipher(cipher, len, x_buf, y_buf, cv);
}

static int32_t sm2_encrypt_2(EC_KEY *ec_key, const uint8_t *src_data, uint32_t src_len,
    uint8_t *dest_data, uint32_t *dest_len)
{
    SM2CiphertextValue *cv = NULL;

    if (src_len > SM2_MAX_PLAINTEXT_LENGTH) {
        tloge("src len is too big!");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (*dest_len < (src_len + SM2_INCREASE_MAX)) {
        tloge("dest len is not large enough to hold the result!");
        return CRYPTO_SHORT_BUFFER;
    }

    gmssl_generate_random();

    /* use publicKey to encrypt */
    cv = SM2_do_encrypt(EVP_sm3(), src_data, src_len, ec_key);
    if (cv == NULL) {
        tloge("SM2 do encrypt failed");
        return get_gmssl_error(SM2_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }

    /* pass cv to destData */
    TEE_Result ret = cv_to_cip(cv, dest_data, dest_len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("get final data failed\n");
        SM2CiphertextValue_free(cv);
        return (int32_t)ret;
    }

    SM2CiphertextValue_free(cv);
    return CRYPTO_SUCCESS;
}

static TEE_Result cip_to_cv(const uint8_t *cipher, uint32_t len, SM2CiphertextValue *cv)
{
    errno_t rc;

    bool check = (BN_bin2bn(cipher + SM2_CIPHER_START_LEN, COORDINATE_LEN, cv->xCoordinate) == NULL);
    if (check) {
        tloge("get C1 x failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    check = (BN_bin2bn(cipher + COORDINATE_LEN + SM2_CIPHER_START_LEN, COORDINATE_LEN, cv->yCoordinate) == NULL);
    if (check) {
        tloge("get C1 y failed\n");
        return  CRYPTO_BAD_PARAMETERS;
    }
    rc = ASN1_OCTET_STRING_set(cv->hash, cipher + COORDINATE_LEN * COORDINATE_NUM + SM2_CIPHER_START_LEN, HASH_SIZE);
    if (rc != GMSSL_OK) {
        tloge("get hash failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    rc = ASN1_OCTET_STRING_set(cv->ciphertext,
                               cipher + COORDINATE_LEN * COORDINATE_NUM + HASH_SIZE + SM2_CIPHER_START_LEN,
                               len - COORDINATE_LEN * COORDINATE_NUM -  HASH_SIZE - SM2_CIPHER_START_LEN);
    if (rc != GMSSL_OK) {
        tloge("get cipher text failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t sm2_decrypt_2(EC_KEY *ec_key, const void *src_data, uint32_t src_len,
    void *dest_data, uint32_t *dest_len)
{
    TEE_Result ret;

    if (src_len < SM2_CIPHER_INCREASE) {
        tloge("src len is too small\n");
        return CRYPTO_SHORT_BUFFER;
    }

    size_t temp_len = src_len - SM2_CIPHER_INCREASE;
    uint8_t *temp_data = TEE_Malloc(temp_len, 0);
    if (temp_data == NULL) {
        tloge("malloc failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    gmssl_generate_random();

    SM2CiphertextValue *cv = SM2CiphertextValue_new();
    if (cv == NULL) {
        ret = CRYPTO_BAD_PARAMETERS;
        goto exit_free;
    }

    ret = cip_to_cv(src_data, src_len, cv);
    if (ret != CRYPTO_SUCCESS) {
        tloge("change input format failed\n");
        goto release;
    }

    int32_t rc = SM2_do_decrypt(EVP_sm3(), cv, temp_data, &temp_len, ec_key);
    bool check = (rc != GMSSL_OK || *dest_len < temp_len || temp_len > UINT32_MAX);
    if (check) {
        tloge("SM2 decrypt failed\n");
        ret = (TEE_Result)get_gmssl_error(SM2_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
        goto release;
    }

    rc = memcpy_s(dest_data, *dest_len, temp_data, temp_len);
    if (rc != EOK) {
        tloge("memcpy failed\n");
        ret = CRYPTO_ERROR_SECURITY;
        goto release;
    }

    *dest_len = (uint32_t)temp_len;
release:
    SM2CiphertextValue_free(cv);
    cv = NULL;
exit_free:
    (void)memset_s(temp_data, temp_len, 0, temp_len);
    TEE_Free(temp_data);
    return (int32_t)ret;
}

static int32_t sm2_decrypt(EC_KEY *ec_key, const void *src_data, uint32_t src_len,
    void *dest_data, uint32_t *dest_len)
{
    SM2CiphertextValue *cv = NULL;

    if (src_len < SM2_INCREASE_MIN) {
        tloge("src len is too small!");
        return CRYPTO_SHORT_BUFFER;
    }

    if (*dest_len < (src_len - SM2_INCREASE_MIN)) {
        tloge("dest len is not large enough to hold the result!");
        return CRYPTO_SHORT_BUFFER;
    }

    cv = d2i_SM2CiphertextValue(NULL, (const unsigned char **)&src_data, src_len);
    if (cv == NULL) {
        tloge("d2i SM2 Cipher text Value failed");
        return CRYPTO_BAD_PARAMETERS;
    }

    size_t temp_dest_len = *dest_len;
    int32_t sm2_ret = SM2_do_decrypt(EVP_sm3(), cv, dest_data, &temp_dest_len, ec_key);
    bool check = (sm2_ret == GMSSL_ERR || temp_dest_len > UINT32_MAX);
    if (check) {
        tloge("SM2 decrypt failed");
        SM2CiphertextValue_free(cv);
        return get_gmssl_error(SM2_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    *dest_len = (uint32_t)temp_dest_len;

    SM2CiphertextValue_free(cv);
    return CRYPTO_SUCCESS;
}

int32_t libgm_sm2_encrypt_decypt_2(const void *sm2_key, uint32_t mode,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (sm2_key == NULL || data_in == NULL || data_out == NULL);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    EC_KEY *ec_key = get_sm2_key_2(sm2_key, mode);
    if (ec_key == NULL) {
        tloge("input is NULL!");
        return get_gmssl_error(SM2_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    int32_t ret;
    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    if (mode == ENC_MODE) {
        ret = sm2_encrypt_2(ec_key, in_buffer, data_in->size, out_buffer, &(data_out->size));
    } else if (mode == DEC_MODE) {
        ret = sm2_decrypt_2(ec_key, in_buffer, data_in->size, out_buffer, &(data_out->size));
    } else {
        tloge("invalid mode %u\n", mode);
        ret = CRYPTO_BAD_PARAMETERS;
    }
    EC_KEY_free(ec_key);
    return ret;
}

int32_t libgm_sm2_encrypt_decypt(const void *sm2_key, uint32_t mode,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (sm2_key == NULL || data_in == NULL || data_out == NULL);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t ret;
    EC_KEY *ec_key = get_sm2_key(sm2_key, mode);
    if (ec_key == NULL) {
        tloge("input is NULL!\n");
        return get_gmssl_error(SM2_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    if (mode == ENC_MODE) {
        ret = sm2_encrypt(ec_key, in_buffer, data_in->size, out_buffer, &(data_out->size));
    } else if (mode == DEC_MODE) {
        ret = sm2_decrypt(ec_key, in_buffer, data_in->size, out_buffer, &(data_out->size));
    } else {
        tloge("invalid mode %u\n", mode);
        ret = CRYPTO_BAD_PARAMETERS;
    }
    EC_KEY_free(ec_key);
    return ret;
}

static TEE_Result sm4_cipher_init_params_check(uint32_t alg_type, const struct memref_t *iv)
{
    bool check = (alg_type == TEE_ALG_SM4_CTR) || (alg_type == TEE_ALG_SM4_CBC_NOPAD) ||
                 (alg_type == TEE_ALG_SM4_CFB128) || (alg_type == TEE_ALG_SM4_CBC_PKCS7) ||
                 (alg_type == TEE_ALG_SM4_GCM);
    if (check) {
        bool check_iv = (iv == NULL || iv->buffer == 0 || iv->size == 0);
        if (check_iv) {
            tloge("IV is NULL, please set IV first\n");
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    return CRYPTO_SUCCESS;
}

static int32_t sm4_cbc_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx,
    const uint8_t *key_buffer, const uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sms4_cbc(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sms4_cbc(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_ecb_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx,
    const uint8_t *key_buffer, const uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sms4_ecb(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sms4_ecb(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_ctr_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx,
    const uint8_t *key_buffer, const uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sms4_ctr(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sms4_ctr(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_cfb_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx,
    const uint8_t *key_buffer, const uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sms4_cfb128(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sms4_cfb128(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_do_encrypt_init(EVP_CIPHER_CTX *ctx, uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    uint8_t *iv_buffer = NULL;
    bool check = (alg_type == TEE_ALG_SM4_CBC_NOPAD || alg_type == TEE_ALG_SM4_CTR) ||
                 (alg_type == TEE_ALG_SM4_CBC_PKCS7) || (alg_type == TEE_ALG_SM4_CFB128);
    if (check)
        iv_buffer = (uint8_t *)(uintptr_t)(iv->buffer);
    const uint8_t *key_buffer = (const uint8_t *)(uintptr_t)(key->key_buffer);

    switch (alg_type) {
    case TEE_ALG_SM4_CBC_NOPAD:
    case TEE_ALG_SM4_CBC_PKCS7:
        return sm4_cbc_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    case TEE_ALG_SM4_ECB_NOPAD:
        return sm4_ecb_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    case TEE_ALG_SM4_CTR:
        return sm4_ctr_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    case TEE_ALG_SM4_CFB128:
        return sm4_cfb_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    default:
        return GMSSL_ERR;
    }
}

void *libgm_sm4_cipher_init(uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    int32_t ret;
    TEE_Result ret_c;
    bool check = (key == NULL || key->key_buffer == 0 || key->key_size == 0);
    if (check) {
        tloge("keybuf is NULL");
        return NULL;
    }

    ret_c = sm4_cipher_init_params_check(alg_type, iv);
    if (ret_c != CRYPTO_SUCCESS) {
        tloge("check iv failed\n");
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        tloge("New SM4 ctx failed");
        return NULL;
    }
    ret = EVP_CIPHER_CTX_init(ctx);
    if (ret != 1) {
        tloge("init SM4 ctx failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    ret = sm4_do_encrypt_init(ctx, alg_type, direction, key, iv);
    if (ret != 1)
        goto exit;

    if (alg_type == TEE_ALG_SM4_CBC_PKCS7)
        (void)EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    else
        (void)EVP_CIPHER_CTX_set_padding(ctx, 0);
    return ctx;

exit:
    tloge("EVP sm4 cipher init failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

static int32_t sm4_update_params_check(uint32_t alg_type, uint32_t src_len, uint32_t dest_len)
{
    if (alg_type == TEE_ALG_SM4_CBC_PKCS7)
        return CRYPTO_SUCCESS;

    bool check = (alg_type == TEE_ALG_SM4_ECB_NOPAD) || (alg_type == TEE_ALG_SM4_CBC_NOPAD);
    if (check) {
        if ((src_len % SM4_BLOCK) != 0) {
            tloge("src len should be 16 bytes aligned!");
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    if (dest_len < src_len || dest_len == 0) {
        tloge("output buffer is too small\n");
        return CRYPTO_SHORT_BUFFER;
    }

    return CRYPTO_SUCCESS;
}

int32_t libgm_sm4_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    int32_t ret;
    bool check = (ctx == NULL || data_in == NULL || data_out == NULL);
    if (check) {
        tloge("operation handle is NULL");
        return CRYPTO_BAD_PARAMETERS;
    }

    EVP_CIPHER_CTX *sm4_ctx = (EVP_CIPHER_CTX *)(uintptr_t)ctx->ctx_buffer;
    if (sm4_ctx == NULL) {
        tloge("The sm4 cipher ctx is null");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    ret = sm4_update_params_check(ctx->alg_type, data_in->size, data_out->size);
    if (ret != CRYPTO_SUCCESS) {
        tloge("sm4 update paramter check failed\n");
        return ret;
    }

    if (data_out->size > INT32_MAX) {
        tloge("data out size is too long\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t temp_dest_len = (int32_t)data_out->size;
    if (ctx->direction == ENC_MODE)
        ret = EVP_EncryptUpdate(sm4_ctx, out_buffer, &temp_dest_len, in_buffer, data_in->size);
    else
        ret = EVP_DecryptUpdate(sm4_ctx, out_buffer, &temp_dest_len, in_buffer, data_in->size);
    if (ret != GMSSL_OK || temp_dest_len < 0) {
        tloge("sm4 cipher update failed\n");
        return get_gmssl_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    data_out->size = (uint32_t)temp_dest_len;
    return CRYPTO_SUCCESS;
}

int32_t libgm_sm4_do_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    bool check = (ctx == NULL || data_in == NULL || data_out == NULL ||
        ((ctx->alg_type != TEE_ALG_SM4_CBC_PKCS7 || ctx->direction == ENC_MODE) && data_out->size < data_in->size));
    if (check) {
        tloge("bad parameters");
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t ret;
    int32_t update_len = 0;
    uint32_t temp_len = data_out->size;
    if (data_in->buffer != 0 && data_in->size != 0) {
        ret = libgm_sm4_update(ctx, data_in, data_out);
        if (ret != CRYPTO_SUCCESS) {
            tloge("sm4 update last block failed");
            EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer));
            ctx->ctx_buffer = 0;
            return ret;
        }
        update_len = (int32_t)data_out->size;
    }

    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    int32_t final_len = temp_len - update_len;
    if (ctx->direction == ENC_MODE)
        ret = EVP_EncryptFinal_ex((EVP_CIPHER_CTX *)(uintptr_t)ctx->ctx_buffer,
            out_buffer + update_len, &final_len);
    else
        ret = EVP_DecryptFinal_ex((EVP_CIPHER_CTX *)(uintptr_t)ctx->ctx_buffer,
            out_buffer + update_len, &final_len);
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer));
    ctx->ctx_buffer = 0;
    if (ret != 1) {
        tloge("sm4 cipher final failed\n");
        return get_gmssl_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    if (update_len > INT32_MAX - final_len) {
        tloge("final len is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = (uint32_t)(update_len + final_len);
    return CRYPTO_SUCCESS;
}

static TEE_Result hexstr_to_buffer(char *str, uint32_t str_len)
{
    uint32_t buffer_size = str_len / STR_TO_HEX;
    TEE_Result ret;

    uint8_t *buffer = TEE_Malloc(buffer_size, 0);
    if (buffer == NULL) {
        tloge("malloc failed!");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    char *temp_buffer = TEE_Malloc(STR_TO_HEX + 1, 0);
    if (temp_buffer == NULL) {
        tloge("malloc failed!");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto error_temp;
    }

    errno_t rc;
    uint32_t j = 0;
    for (uint32_t i = 0; i < str_len; i += STR_TO_HEX) {
        rc = memcpy_s(temp_buffer, (STR_TO_HEX + 1), str + i, STR_TO_HEX);
        if (rc != EOK) {
            tloge("memcpy failed!");
            ret = TEE_ERROR_SECURITY;
            goto error;
        }
        buffer[j] = (uint8_t)strtol(temp_buffer, NULL, HEX_FLAG);
        j++;
    }

    rc = memcpy_s(str, str_len, buffer, buffer_size);
    if (rc != EOK) {
        tloge("memcpy failed!");
        ret = TEE_ERROR_SECURITY;
        goto error;
    }

    ret = CRYPTO_SUCCESS;
error:
    (void)memset_s(temp_buffer, STR_TO_HEX + 1, 0, STR_TO_HEX + 1);
    TEE_Free(temp_buffer);
    temp_buffer = NULL;
error_temp:
    (void)memset_s(buffer, buffer_size, 0, buffer_size);
    TEE_Free(buffer);
    buffer = NULL;
    return ret;
}

static EC_GROUP *get_ec_group(uint32_t group)
{
    EC_GROUP *sm2_p256_group = NULL;
    struct sm2_new_ec_group_t sm2_group = {0};

    if (group == SM2_GROUP_NOSTANDARD) {
        sm2_group.p_hex = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
        sm2_group.a_hex = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
        sm2_group.b_hex = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
        sm2_group.x_hex = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
        sm2_group.y_hex = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
        sm2_group.n_hex = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
        sm2_group.h_hex = "1";

        sm2_p256_group = sm2_new_ec_group(1, &sm2_group);
    } else {
        sm2_p256_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    }

    return sm2_p256_group;
}

static void eckey_get_dxy(struct sm2_eckey_get_dxy_t *sm2_eckey_struct, const sm2_key_pair *key_pair)
{
    sm2_eckey_struct->d = (char *)(key_pair->d);
    sm2_eckey_struct->d_len = KEY_SIZE_2;
    sm2_eckey_struct->x = (char *)(key_pair->x);
    sm2_eckey_struct->x_len = KEY_SIZE_2;
    sm2_eckey_struct->y = (char *)(key_pair->y);
    sm2_eckey_struct->y_len = KEY_SIZE_2;
}

static int32_t generate_sm2_keypair(uint32_t group, const sm2_key_pair *key_pair)
{
    int32_t ret;
    char rand_seed[RAND_SIZE] = { 0 };
    uint32_t rand_seed_size   = RAND_SIZE;
    struct sm2_eckey_get_dxy_t sm2_eckey_struct = { 0 };

    if (RAND_status() != GMSSL_OK) {
        tlogd("RAND_status is failed!\n");
        TEE_GenerateRandom(rand_seed, rand_seed_size);
        RAND_seed(rand_seed, (int32_t)rand_seed_size);
    }

    /* new ec_key */
    EC_KEY *ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        tloge("EC KEY new failed!");
        return CRYPTO_BAD_PARAMETERS;
    }

    /* Generate new group */
    EC_GROUP *sm2_p256_group = get_ec_group(group);
    if (sm2_p256_group == NULL) {
        tloge("SM2 new ec group failed!");
        ret =  CRYPTO_BAD_PARAMETERS;
        goto end;
    }

    /* set group to ec_key */
    if (EC_KEY_set_group(ec_key, sm2_p256_group) == GMSSL_ERR) {
        tloge("EC KEY set group failed");
        ret = CRYPTO_BAD_PARAMETERS;
        goto end;
    }

    /* Generate new key */
    if (EC_KEY_generate_key(ec_key) == GMSSL_ERR) {
        tloge(" EC KEY generate keyfailed");
        ret = CRYPTO_BAD_PARAMETERS;
        goto end;
    }

    /* get d, x, y from ec_key */
    eckey_get_dxy(&sm2_eckey_struct, key_pair);
    if (sm2_eckey_get_dxy(sm2_p256_group, ec_key, &sm2_eckey_struct) != GMSSL_OK) {
        tloge("SM2 EC KEY GET DXY key failed");
        ret = CRYPTO_BAD_PARAMETERS;
        goto end;
    }
    ret = CRYPTO_SUCCESS;
end:
    EC_KEY_free(ec_key);
    ec_key = NULL;
    EC_GROUP_free(sm2_p256_group);
    sm2_p256_group = NULL;
    return ret;
}

static int32_t copy_key_pair_to_object(struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key,
    const sm2_key_pair *key_pair, uint32_t mod_len, uint32_t key_len)
{
    bool check = (public_key->x_len < mod_len || public_key->y_len < mod_len || private_key->r_len < mod_len);
    if (check) {
        tloge("key size is invlid");
        return CRYPTO_SHORT_BUFFER;
    }
    errno_t rc =  memcpy_s(public_key->x, public_key->x_len, key_pair->x, key_len);
    if (rc != EOK) {
        tloge("memcpy failed");
        return CRYPTO_ERROR_SECURITY;
    }
    public_key->x_len = key_len;

    rc = memcpy_s(public_key->y, public_key->y_len, key_pair->y, key_len);
    if (rc != EOK) {
        tloge("memcpy failed");
        return CRYPTO_ERROR_SECURITY;
    }
    public_key->y_len = key_len;

    rc = memcpy_s(private_key->r, private_key->r_len, key_pair->d, key_len);
    if (rc != EOK) {
        tloge("memcpy failed");
        return CRYPTO_ERROR_SECURITY;
    }
    private_key->r_len = key_len;

    return CRYPTO_SUCCESS;
}

static int32_t gen_sm2_key(sm2_key_pair **key_pair, uint32_t curve)
{
    *key_pair = TEE_Malloc(sizeof(sm2_key_pair), 0);
    if (*key_pair == NULL) {
        tloge("tee malloc failed1");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    int32_t ret = generate_sm2_keypair(curve, *key_pair);
    if (ret != CRYPTO_SUCCESS) {
        tloge("generate sm2 keypair failed!");
        (void)memset_s(*key_pair, sizeof(sm2_key_pair), 0, sizeof(sm2_key_pair));
        TEE_Free(*key_pair);
        *key_pair = NULL;
        return ret;
    }
    return 0;
}

int32_t libgm_sm2_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    int32_t ret;
    errno_t rc;
    (void)key_size;
    if (public_key == NULL || private_key == NULL) {
        tloge("input is null");
        return CRYPTO_BAD_PARAMETERS;
    }

    sm2_key_pair *key_pair = NULL;
    ret = gen_sm2_key(&key_pair, curve);
    if (ret != 0)
        return ret;

    ret = copy_key_pair_to_object(public_key, private_key, key_pair, MOD_LEN, KEY_SIZE_2);
    rc  = memset_s(key_pair, sizeof(*key_pair), 0, sizeof(*key_pair));
    if (rc != EOK)
        tloge("memset keypair failed!");
    TEE_Free(key_pair);
    key_pair = NULL;
    return ret;
}

int32_t libgm_sm2_generate_keypair_2(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    int32_t ret;
    errno_t rc;
    bool check = (public_key == NULL || private_key == NULL || key_size != KEY_SIZE * BYTE_TO_BIT);
    if (check) {
        tloge("bad parameters");
        return CRYPTO_BAD_PARAMETERS;
    }

    sm2_key_pair *key_pair = NULL;
    ret = gen_sm2_key(&key_pair, curve);
    if (ret != 0)
        return ret;

    /* 64 byte hexstring to 32 byte buffer */
    ret = (int32_t)hexstr_to_buffer(key_pair->x, KEY_SIZE_2);
    if (ret != CRYPTO_SUCCESS) {
        tloge("gmssl: %s\n", "hexstr_to_buffer failed");
        ret = CRYPTO_BAD_PARAMETERS;
        goto end;
    }

    ret = (int32_t)hexstr_to_buffer(key_pair->y, KEY_SIZE_2);
    if (ret != CRYPTO_SUCCESS) {
        tloge("gmssl: %s\n", "hexstr_to_buffer failed");
        ret = CRYPTO_BAD_PARAMETERS;
        goto end;
    }

    ret = (int32_t)hexstr_to_buffer(key_pair->d, KEY_SIZE_2);
    if (ret != CRYPTO_SUCCESS) {
        tloge("gmssl: %s\n", "hexstr_to_buffer failed");
        ret = CRYPTO_BAD_PARAMETERS;
        goto end;
    }

    ret = copy_key_pair_to_object(public_key, private_key, key_pair, KEY_SIZE, KEY_SIZE);
end:
    rc = memset_s(key_pair, sizeof(*key_pair), 0, sizeof(*key_pair));
    if (rc != EOK)
        tloge("memset keypair failed!");
    TEE_Free(key_pair);
    key_pair = NULL;
    return ret;
}

int32_t libgm_copy_sm4_operation(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    if (dest == NULL || src == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (dest->ctx_buffer != 0) {
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(dest->ctx_buffer));
        dest->ctx_buffer = 0;
    }
    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    EVP_CIPHER_CTX *new_ctx = EVP_CIPHER_CTX_new();
    if (new_ctx == NULL) {
        tloge("New aes ctx failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int32_t ret = EVP_CIPHER_CTX_copy(new_ctx, (EVP_CIPHER_CTX *)(uintptr_t)(src->ctx_buffer));
    if (ret != GMSSL_OK) {
        tloge("Copy aes ctx failed");
        EVP_CIPHER_CTX_free(new_ctx);
        return get_gmssl_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    dest->ctx_buffer = (uint64_t)(uintptr_t)new_ctx;

    return CRYPTO_SUCCESS;
}

static int32_t sm2_sig_to_buff(const ECDSA_SIG *sig, uint8_t *signature, uint32_t *signature_len)
{
    int32_t ret = CRYPTO_ERROR_SECURITY;

    bool check = (*signature_len < SIG_COMPONENT_SIZE * SIG_COMPONENT_NUM ||
        BN_num_bytes(sig->r) > SIG_COMPONENT_SIZE);
    if (check) {
        tloge("the out buff is too small\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *r = TEE_Malloc(SIG_COMPONENT_SIZE, 0);
    if (r == NULL) {
        tloge("malloc failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    uint8_t *s = TEE_Malloc(SIG_COMPONENT_SIZE, 0);
    if (s == NULL) {
        tloge("malloc failed\n");
        goto exit;
    }

    int32_t len_r = BN_bn2bin(sig->r, r + SIG_COMPONENT_SIZE - BN_num_bytes(sig->r));
    if (len_r == 0) {
        tloge("bn to bin failed r length = %d\n", len_r);
        ret = CRYPTO_BAD_PARAMETERS;
        goto exit;
    }

    int32_t len_s = BN_bn2bin(sig->s, s + SIG_COMPONENT_SIZE - BN_num_bytes(sig->s));
    if (len_s == 0) {
        tloge("bn to bin failed s length = %d\n", len_s);
        ret = CRYPTO_BAD_PARAMETERS;
        goto exit;
    }

    if (memcpy_s(signature, *signature_len, r, SIG_COMPONENT_SIZE) != EOK) {
        tloge("memcpy failed\n");
        goto exit;
    }

    if (memcpy_s(signature + SIG_COMPONENT_SIZE, *signature_len - SIG_COMPONENT_SIZE, s, SIG_COMPONENT_SIZE) != EOK) {
        tloge("memcpy failed\n");
        goto exit;
    }
    *signature_len = SIG_COMPONENT_SIZE * SIG_COMPONENT_NUM;
    ret = CRYPTO_SUCCESS;
exit:
    TEE_Free(s);
    s = NULL;
    TEE_Free(r);
    return ret;
}

int32_t libgm_sm2_sign(const uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len, EC_KEY *ec_key)
{
    ECDSA_SIG *sig = NULL;

    bool check = (digest == NULL || signature == NULL || signature_len == NULL || ec_key == NULL);
    if (check) {
        tloge("invlid paramter\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    gmssl_generate_random();

    sig = SM2_do_sign(digest, digest_len, ec_key);
    if (sig == NULL) {
        tloge("SM2 sign failed\n");
        return get_gmssl_error(SM2_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }

    int32_t ret = sm2_sig_to_buff(sig, signature, signature_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("sm2 sign change format failed\n");

    ECDSA_SIG_free(sig);
    return ret;
}

static int32_t sm2_buff_to_sig(const uint8_t *signature, uint32_t signature_len, ECDSA_SIG **sig)
{
    /* sig will be free in the caller function */
    *sig = ECDSA_SIG_new();
    if (*sig == NULL) {
        tloge("get ECDSA SIG failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    (*sig)->r = BN_new();
    if ((*sig)->r == NULL) {
        tloge("init signature failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    (*sig)->s = BN_new();
    if ((*sig)->s == NULL) {
        tloge("init signature failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (BN_bin2bn(signature, SIG_COMPONENT_SIZE, (*sig)->r) == NULL) {
        tloge("get r failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (BN_bin2bn(signature + SIG_COMPONENT_SIZE, signature_len - SIG_COMPONENT_SIZE, (*sig)->s) == NULL) {
        tloge("get s failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t libgm_sm2_verify(const uint8_t *digest, uint32_t digest_len,
    const uint8_t *signature, uint32_t signature_len, EC_KEY *ec_key)
{
    int32_t rc;
    ECDSA_SIG *sig = NULL;

    if (digest == NULL || signature == NULL || ec_key == NULL) {
        tloge("invlid paramter\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (signature_len != SIG_COMPONENT_SIZE * SIG_COMPONENT_NUM) {
        tloge("the length of signature is invalid\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    gmssl_generate_random();

    rc = sm2_buff_to_sig(signature, signature_len, &sig);
    if (rc != CRYPTO_SUCCESS) {
        tloge("get sm2 sig failed\n");
        goto exit;
    }

    rc = SM2_do_verify(digest, digest_len, sig, ec_key);
    if (rc != GMSSL_OK) {
        tloge("SM2 verify failed\n");
        rc = CRYPTO_SIGNATURE_INVALID;
        goto exit;
    }
    rc = CRYPTO_SUCCESS;
exit:
    ECDSA_SIG_free(sig);
    return rc;
}

void free_cipher_ctx(uint64_t *ctx)
{
    if (ctx == NULL || *ctx == 0)
        return;
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(*ctx));
    *ctx = 0;
}

/* sm4 ae support start */
#define EVP_MODE_ENCRYPT 1
#define EVP_MODE_DECRYPT 0
#define EVP_MODE_UNCHANGE (-1)
void *libgm_ae_init(uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    int32_t ret;
    bool check = (alg_type != TEE_ALG_SM4_GCM) || (iv == NULL) || (iv->buffer == 0) ||
        (iv->size == 0) || (key == NULL) || (key->key_buffer == 0) || (key->key_size == 0);
    if (check) {
        tloge("gm ae error parameters\n");
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        tloge("gm new ae ctx filed\n");
        return NULL;
    }

    int32_t enc_mode = ((direction == ENC_MODE) ? EVP_MODE_ENCRYPT : EVP_MODE_DECRYPT);
    ret = EVP_CipherInit_ex(ctx, EVP_sms4_gcm(), NULL, NULL, NULL, enc_mode);
    if (ret != GMSSL_OK) {
        tloge("gm ae init failed: set cipher\n");
        goto exit;
    }

    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv->size, NULL);
    if (ret != GMSSL_OK) {
        tloge("gm ae set nonce failed\n");
        goto exit;
    }
    const uint8_t *key_buffer = (const uint8_t *)(uintptr_t)(key->key_buffer);
    const uint8_t *iv_buffer = (const uint8_t *)(uintptr_t)(iv->buffer);
    ret = EVP_CipherInit_ex(ctx, NULL, NULL, key_buffer, iv_buffer, EVP_MODE_UNCHANGE);
    if (ret != GMSSL_OK) {
        tloge("gm ae init failed: set key and nonce\n");
        goto exit;
    }

    return ctx;
exit:
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

int32_t libgm_ae_update_aad(const struct ctx_handle_t *ctx, const struct memref_t *aad_data)
{
    bool check = (ctx == NULL) || (aad_data == NULL) || (ctx->ctx_buffer == 0) || (aad_data->size > INT32_MAX);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    EVP_CIPHER_CTX *ae_ctx = (EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer);
    if (ae_ctx == NULL) {
        tloge("gm ae sm4 ctx is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t out_len;
    int32_t ret = EVP_CipherUpdate(ae_ctx, NULL, &out_len, (uint8_t *)(uintptr_t)(aad_data->buffer),
        (int32_t)(aad_data->size));
    if (ret != GMSSL_OK) {
        tloge("gm ae update aad failed\n");
        return get_gmssl_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    return CRYPTO_SUCCESS;
}

int32_t libgm_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (ctx == NULL) || (ctx->ctx_buffer == 0) || (data_in == NULL) || (data_out == NULL) ||
        (data_in->buffer == 0) || (data_out->buffer == 0);
    if (check) {
        tloge("gm ae update bad params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    if (data_out->size > INT32_MAX)
        return CRYPTO_BAD_PARAMETERS;

    int32_t dest_len_temp = (int32_t)(data_out->size);

    int32_t ret = EVP_CipherUpdate((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer), out_buffer, &dest_len_temp,
        in_buffer, (int32_t)data_in->size);
    if (ret != GMSSL_OK || dest_len_temp < 0) {
        tloge("sm4 cipher update failed\n");
        return get_gmssl_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    data_out->size = (uint32_t)dest_len_temp;
    return CRYPTO_SUCCESS;
}

static int32_t ae_final_check_param(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag, const struct memref_t *data_out)
{
    bool check = (ctx == NULL || ctx->ctx_buffer == 0);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    check = (data_in == NULL || data_out == NULL || tag == NULL || tag->buffer == 0);
    if (check) {
        tloge("bad params");
        free_cipher_ctx(&(ctx->ctx_buffer));
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

static int32_t gm_ae_crypto_final(const struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    bool check = (data_in->size > INT32_MAX || data_out->size > INT32_MAX);
    if (check) {
        tloge("data size is too long\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t dest_len_temp = 0;

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    EVP_CIPHER_CTX *ae_ctx = (EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer);
    int32_t rc;
    check = (in_buffer != NULL && data_in->size != 0);
    if (check) {
        dest_len_temp = (int32_t)(data_out->size);
        rc = EVP_CipherUpdate(ae_ctx, out_buffer, &dest_len_temp,
            in_buffer, (int32_t)(data_in->size));
        if (rc != GMSSL_OK) {
            tloge("gm ae cipher update data failed\n");
            return get_gmssl_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
        }
    }
    int32_t final_len = data_out->size - dest_len_temp;
    rc = EVP_CipherFinal_ex(ae_ctx, out_buffer + dest_len_temp, &final_len);
    if (rc != GMSSL_OK) {
        tloge("gm ae cipher final data failed\n");
        return get_gmssl_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    if (dest_len_temp + final_len < 0) {
        tloge("gm ae cipher final data failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = (uint32_t)(dest_len_temp + final_len);
    return CRYPTO_SUCCESS;
}

int32_t libgm_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out)
{
    if (ae_final_check_param(ctx, data_in, tag_out, data_out) != CRYPTO_SUCCESS)
        return CRYPTO_BAD_PARAMETERS;
    uint32_t actual_tag_len = ctx->tag_len;
    if (tag_out->size < actual_tag_len) {
        tloge("The input tag buffer length is too small\n");
        free_cipher_ctx(&(ctx->ctx_buffer));
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t rc = gm_ae_crypto_final(ctx, data_in, data_out);
    if (rc != CRYPTO_SUCCESS) {
        tloge("do ae enc final failed, ret = %d", rc);
        free_cipher_ctx(&(ctx->ctx_buffer));
        return rc;
    }

    rc = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer), EVP_CTRL_GCM_GET_TAG,
        actual_tag_len, (uint8_t *)(uintptr_t)(tag_out->buffer));
    free_cipher_ctx(&(ctx->ctx_buffer));
    if (rc != GMSSL_OK) {
        tloge("Evp ae get tag data failed\n");
        return get_gmssl_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }
    tag_out->size = actual_tag_len;

    return TEE_SUCCESS;
}

int32_t libgm_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out)
{
    if (ae_final_check_param(ctx, data_in, tag_in, data_out) != CRYPTO_SUCCESS)
        return CRYPTO_BAD_PARAMETERS;
    if (tag_in->size != ctx->tag_len) {
        tloge("The input tag length is not equal actual tag length, tag_len = 0x%x, crypto_hal_data->tag_len = 0x%x\n",
            tag_in->size, ctx->tag_len);
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t ret = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer), EVP_CTRL_GCM_SET_TAG,
        tag_in->size, (uint8_t *)(uintptr_t)(tag_in->buffer));
    if (ret != GMSSL_OK) {
        tloge("gm ae set expected tag data failed");
        free_cipher_ctx(&(ctx->ctx_buffer));
        return get_gmssl_error(SM4_LIB_ERR_ID, CRYPTO_BAD_PARAMETERS);
    }

    ret = gm_ae_crypto_final(ctx, data_in, data_out);
    free_cipher_ctx(&(ctx->ctx_buffer));
    if (ret != CRYPTO_SUCCESS)
        tloge("gm ae crypto final data failed\n");
    return ret;
}
/* sm4 ae support end */

