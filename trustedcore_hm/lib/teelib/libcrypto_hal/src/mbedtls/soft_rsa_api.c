/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: implement GP API using mbedtls
 * Create: 2020-11-27
 */
#include "soft_rsa_api.h"
#include <mbedtls/rsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/md.h>
#include <tee_log.h>
#include "soft_common_api.h"
#include "soft_err.h"

#define SOFT_NUMBER_TWO              2
#define UINT8_SHIFT                  8

struct create_rsa_crypt_ctx_t {
    uint32_t alg_type;
    uint32_t mode;
    int32_t padding;
};

static void uint8_to_uint32(const uint8_t *buffer, uint32_t size, uint32_t *result)
{
    bool check = ((buffer == NULL) || (size == 0) || (size > UINT32_SHIFT_MAX));
    if (check)
        return;
    uint32_t shift = 0;
    *result = 0;
    for (int32_t i = (int32_t)(size - 1); i >= 0; i--) {
        *result += buffer[i] << shift;
        shift += UINT8_SHIFT;
    }
    return;
}

static inline int32_t mbd_rand(void *rng_state, unsigned char *output, size_t len)
{
    (void)rng_state;
    TEE_GenerateRandom(output, len);
    return 0;
}

static int32_t mbedtls_rsa_export_raw_and_crt(mbedtls_rsa_context *ctx, struct rsa_priv_key_t *key_pair)
{
    int32_t rc;
    rc = mbedtls_rsa_export_raw(ctx, key_pair->n, key_pair->n_len, key_pair->p, key_pair->p_len,
        key_pair->q, key_pair->q_len, key_pair->d, key_pair->d_len, key_pair->e, key_pair->e_len);
    if (rc != 0) {
        tloge("rsa export raw fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    mbedtls_mpi dp, dq, qp;
    mbedtls_mpi_init(&dp);
    mbedtls_mpi_init(&dq);
    mbedtls_mpi_init(&qp);
    rc =  mbedtls_rsa_export_crt(ctx, &dp, &dq, &qp);
    if (rc != 0) {
        tloge("rsa export crt fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        goto clean;
    }
    rc = mbedtls_mpi_write_binary(&dp, key_pair->dp, key_pair->dp_len);
    if (rc != 0)
        goto clean;
    rc = mbedtls_mpi_write_binary(&dq, key_pair->dq, key_pair->dq_len);
    if (rc != 0)
        goto clean;
    rc = mbedtls_mpi_write_binary(&qp, key_pair->qinv, key_pair->qinv_len);

clean:
    mbedtls_mpi_free(&dp);
    mbedtls_mpi_free(&dq);
    mbedtls_mpi_free(&qp);
    return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
}

#define RSA_F4   0x10001L
#define BYTE2BIT 8
int32_t soft_crypto_rsa_generate_keypair(uint32_t key_size, const struct memref_t *e_value, bool crt_mode,
    struct rsa_priv_key_t *key_pair)
{
    if (e_value == NULL || key_pair == NULL) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }
    uint32_t exponent = 0;
    uint8_to_uint32((uint8_t *)(uintptr_t)(e_value->buffer), e_value->size, &exponent);
    if (exponent > 0xffffff) /* find wrong exponent */
        return CRYPTO_NOT_SUPPORTED;

    if (exponent == 0)
        exponent = RSA_F4;

    mbedtls_rsa_context ctx;
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA1);
    int32_t rc = mbedtls_rsa_gen_key(&ctx, mbd_rand, NULL, key_size * BYTE2BIT, exponent);
    if (rc != 0) {
        tloge("rsa gen key fail, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    if (crt_mode) {
        rc = mbedtls_rsa_export_raw_and_crt(&ctx, key_pair);
    } else {
        rc = mbedtls_rsa_export_raw(&ctx, key_pair->n, key_pair->n_len, NULL, 0,
            NULL, 0, key_pair->d, key_pair->d_len, key_pair->e, key_pair->e_len);
    }
    if (rc != 0) {
        tloge("rsa export fail, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    key_pair->crt_mode = crt_mode;
    return CRYPTO_SUCCESS;
}

static int32_t convert_rsa_padding_to_mbedtls(uint32_t algorithm, int32_t *padding,
    uint32_t *hash_type, uint32_t *hash_len)
{
    switch (algorithm) {
    case CRYPTO_TYPE_RSAES_PKCS1_V1_5:
        *padding = MBEDTLS_RSA_PKCS_V15;
        break;
    case CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA1:
        *hash_type = MBEDTLS_MD_SHA1;
        *padding = MBEDTLS_RSA_PKCS_V21;
        *hash_len = SHA1_LEN;
        break;
    case CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA224:
        *hash_type = MBEDTLS_MD_SHA224;
        *padding = MBEDTLS_RSA_PKCS_V21;
        *hash_len = SHA224_LEN;
        break;
    case CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA256:
        *hash_type = MBEDTLS_MD_SHA256;
        *padding = MBEDTLS_RSA_PKCS_V21;
        *hash_len = SHA256_LEN;
        break;
    case CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA384:
        *hash_type = MBEDTLS_MD_SHA384;
        *padding = MBEDTLS_RSA_PKCS_V21;
        *hash_len = SHA384_LEN;
        break;
    case CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA512:
        *hash_type = MBEDTLS_MD_SHA512;
        *padding = MBEDTLS_RSA_PKCS_V21;
        *hash_len = SHA512_LEN;
        break;
    default:
        tloge("Convert rsa padding: algorithm not supported, algorithm=0x%x\n", algorithm);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_rsa_encrypt(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)rsa_params;
    bool check = (public_key == NULL || data_in == NULL || data_out == NULL || data_in->buffer == 0 ||
        data_out->buffer == 0);
    if (check) {
        tloge("bad params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t padding = MBEDTLS_RSA_PKCS_V15;
    uint32_t hash_type = MBEDTLS_MD_NONE;
    uint32_t hash_len = 0;
    int32_t ret = convert_rsa_padding_to_mbedtls(alg_type, &padding, &hash_type, &hash_len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Convert rsa padding to mbedtls failed ret:%d\n", ret);
        return ret;
    }

    mbedtls_rsa_context ctx;
    mbedtls_rsa_init(&ctx, padding, hash_type);
    ret = mbedtls_mpi_read_binary(&ctx.N, public_key->n, public_key->n_len);
    if (ret != 0)
        goto clean;

    ret = mbedtls_mpi_read_binary(&ctx.E, public_key->e, public_key->e_len);
    if (ret != 0)
        goto clean;

    ctx.len = mbedtls_mpi_size(&ctx.N);
    ret = mbedtls_rsa_pkcs1_encrypt(&ctx, mbd_rand, NULL, MBEDTLS_RSA_PUBLIC, data_in->size,
        (uint8_t *)(uintptr_t)data_in->buffer, (uint8_t *)(uintptr_t)data_out->buffer);
    mbedtls_rsa_free(&ctx);
    if (ret != 0) {
        tloge("rsa pkcs1 encrypt failed err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        goto clean;
    }
clean:
    mbedtls_rsa_free(&ctx);
    return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
}
#define SOFT_RSA_PKCS1_PADDING_LEN 11
static int32_t check_pkcs1_padding(uint32_t dest_len, uint32_t key_size)
{
    if (key_size < SOFT_RSA_PKCS1_PADDING_LEN) {
        tloge("Key size is invalid\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (dest_len < (key_size - SOFT_RSA_PKCS1_PADDING_LEN)) {
        tloge("Dest len is too short, dest_len = 0x%x, max_src_len = 0x%x\n", dest_len,
            (key_size - SOFT_RSA_PKCS1_PADDING_LEN));
        return CRYPTO_SHORT_BUFFER;
    }

    return CRYPTO_SUCCESS;
}
static TEE_Result check_oaep_padding(uint32_t dest_len, uint32_t key_size, uint32_t hash_len)
{
    if (key_size < (SOFT_NUMBER_TWO * hash_len - SOFT_NUMBER_TWO)) {
        tloge("Key size is invalid\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (dest_len < (key_size - SOFT_NUMBER_TWO * hash_len - SOFT_NUMBER_TWO)) {
        tloge("Dest len is too short, dest_len = 0x%x, max_src_len = 0x%x\n", dest_len,
            (key_size - (SOFT_NUMBER_TWO * hash_len - SOFT_NUMBER_TWO)));
        return CRYPTO_SHORT_BUFFER;
    }

    return CRYPTO_SUCCESS;
}

static int32_t check_rsa_decrypt_destlen(uint32_t dest_len, int32_t padding, uint32_t key_size, uint32_t hash_len)
{
    switch (padding) {
    case MBEDTLS_RSA_PKCS_V15:
        return check_pkcs1_padding(dest_len, key_size);
    case MBEDTLS_RSA_PKCS_V21:
        return check_oaep_padding(dest_len, key_size, hash_len);
    default:
        return CRYPTO_BAD_PARAMETERS;
    }
}

static void mpi_init(mbedtls_mpi *x, mbedtls_mpi *y, mbedtls_mpi *g, mbedtls_mpi *r)
{
    mbedtls_mpi_init(x);
    mbedtls_mpi_init(y);
    mbedtls_mpi_init(g);
    mbedtls_mpi_init(r);
}

static void mpi_free(mbedtls_mpi *x, mbedtls_mpi *y, mbedtls_mpi *g, mbedtls_mpi *r)
{
    mbedtls_mpi_free(x);
    mbedtls_mpi_free(y);
    mbedtls_mpi_free(g);
    mbedtls_mpi_free(r);
}

static int32_t mbedtls_mpi_read_rsa_binary(mbedtls_rsa_context *ctx, const struct rsa_priv_key_t *private_key)
{
    int32_t ret = mbedtls_mpi_read_binary(&ctx->E, private_key->e, private_key->e_len);
    if (ret != 0)
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    ret = mbedtls_mpi_read_binary(&ctx->P, private_key->p, private_key->p_len);
    if (ret != 0)
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    ret = mbedtls_mpi_read_binary(&ctx->Q, private_key->q, private_key->q_len);
    if (ret != 0)
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    ret = mbedtls_mpi_read_binary(&ctx->DP, private_key->dp, private_key->dp_len);
    if (ret != 0)
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    ret = mbedtls_mpi_read_binary(&ctx->DQ, private_key->dq, private_key->dq_len);
    if (ret != 0)
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    ret = mbedtls_mpi_read_binary(&ctx->QP, private_key->qinv, private_key->qinv_len);
    if (ret != 0)
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    return CRYPTO_SUCCESS;
}

static int32_t rsa_import_crt(mbedtls_rsa_context *ctx, const struct rsa_priv_key_t *private_key)
{
    int32_t ret = mbedtls_mpi_read_rsa_binary(ctx, private_key);
    if (ret != 0) {
        tloge("read mpi rsa binary fail, err:%d", ret);
        return ret;
    }

    ret = mbedtls_mpi_mul_mpi(&ctx->N, &ctx->P, &ctx->Q);
    if (ret != 0) {
        tloge("read mul fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    }

    mbedtls_mpi x, y, g, r;
    mpi_init(&x, &y, &g, &r);
    ret = mbedtls_mpi_sub_int(&x, &ctx->P, 1);
    if (ret != 0) {
        tloge("mpi sub fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        goto clean;
    }

    ret = mbedtls_mpi_sub_int(&y, &ctx->Q, 1);
    if (ret != 0) {
        tloge("mpi sub fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        goto clean;
    }

    mbedtls_mpi_gcd(&g, &x, &y);
    ret = mbedtls_mpi_div_mpi(&x, &r, &x, &g);
    if (ret != 0) {
        tloge("mpi div fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        goto clean;
    }

    ret = mbedtls_mpi_mul_mpi(&r, &y, &x);
    if (ret != 0) {
        tloge("mpi mul fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        goto clean;
    }
    ret = mbedtls_mpi_inv_mod(&ctx->D, &ctx->E, &y);
    if (ret != 0) {
        tloge("mpi inv mod fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        goto clean;
    }
    ctx->len = mbedtls_mpi_size(&ctx->N);

    ret = mbedtls_rsa_complete(ctx);
    if (ret != 0)
        tloge("mbedtls_rsa_complete failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, ret));

clean:
    mpi_free(&x, &y, &g, &r);
    return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
}

static int32_t rsa_import_non_crt(mbedtls_rsa_context *ctx, const struct rsa_priv_key_t *private_key)
{
    int32_t ret = mbedtls_mpi_read_binary(&ctx->N, private_key->n, private_key->n_len);
    if (ret != 0) {
        tloge("read binary n failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    }

    ret = mbedtls_mpi_read_binary(&ctx->E, private_key->e, private_key->e_len);
    if (ret != 0) {
        tloge("read binary e failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    }

    ret = mbedtls_mpi_read_binary(&ctx->D, private_key->d, private_key->d_len);
    if (ret != 0) {
        tloge("read binary d failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    }
    ctx->len = mbedtls_mpi_size(&ctx->N);

    ret = mbedtls_rsa_complete(ctx);
    if (ret != 0) {
        tloge("rsa complete failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    }

    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_rsa_decrypt(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)rsa_params;
    bool check = (private_key == NULL || data_in == NULL || data_out == NULL || data_in->buffer == 0 ||
        data_out->buffer == 0);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    int32_t padding = MBEDTLS_RSA_PKCS_V15;
    uint32_t hash_type = MBEDTLS_MD_NONE;
    uint32_t hash_len = 0;
    int32_t ret  = convert_rsa_padding_to_mbedtls(alg_type, &padding, &hash_type, &hash_len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Convert rsa padding to mbedtls failed\n");
        return ret;
    }

    ret = check_rsa_decrypt_destlen(data_out->size, padding, private_key->n_len, hash_len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("dest_len is invalid");
        return CRYPTO_SHORT_BUFFER;
    }

    mbedtls_rsa_context ctx;
    mbedtls_rsa_init(&ctx, padding, hash_type);

    if (private_key->crt_mode) {
        ret = rsa_import_crt(&ctx, private_key);
    } else {
        ret = rsa_import_non_crt(&ctx, private_key);
    }
    if (ret != 0) {
        tloge("rsa import failed, ret:%d crt_mode:0x%x\n", ret, private_key->crt_mode);
        mbedtls_rsa_free(&ctx);
        return ret;
    }

    size_t olen = (size_t)data_out->size;
    ret = mbedtls_rsa_pkcs1_decrypt(&ctx, mbd_rand, NULL, MBEDTLS_RSA_PRIVATE, &olen,
        (uint8_t *)(uintptr_t)data_in->buffer, (uint8_t *)(uintptr_t)data_out->buffer, data_out->size);
    mbedtls_rsa_free(&ctx);
    if (ret != 0) {
        tloge("rsa pkcs1 decrypt failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    }

    data_out->size = (uint32_t)olen;
    return CRYPTO_SUCCESS;
}

static bool check_is_rsa_pss_sign_algorithm(uint32_t algorithm)
{
    uint32_t i = 0;
    uint32_t algorithm_set[] = {
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_MD5,
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA1,
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA224,
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA256,
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA384,
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA512
    };
    uint32_t total_set_num = sizeof(algorithm_set) / sizeof(uint32_t);
    for (; i < total_set_num; i++) {
        if (algorithm_set[i] == algorithm)
            return true;
    }

    return false;
}

static int32_t get_hash_type_from_algorithm(uint32_t algorithm, uint32_t *hash_type)
{
    uint32_t i = 0;
    crypto_uint2uint algorithm_to_hash_type[] = {
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_MD5, MBEDTLS_MD_MD5 },
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA1, MBEDTLS_MD_SHA1 },
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA224, MBEDTLS_MD_SHA224 },
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA256, MBEDTLS_MD_SHA256 },
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA384, MBEDTLS_MD_SHA384 },
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA512, MBEDTLS_MD_SHA512 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_MD5, MBEDTLS_MD_MD5 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA1, MBEDTLS_MD_SHA1 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA224, MBEDTLS_MD_SHA224 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA256, MBEDTLS_MD_SHA256 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA384, MBEDTLS_MD_SHA384 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA512, MBEDTLS_MD_SHA512 },
        { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA1,  MBEDTLS_MD_SHA1 },
        { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA224, MBEDTLS_MD_SHA224 },
        { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA256, MBEDTLS_MD_SHA256 },
        { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA384, MBEDTLS_MD_SHA384 },
        { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA512, MBEDTLS_MD_SHA512 },
    };
    uint32_t total_map_num = sizeof(algorithm_to_hash_type) / sizeof(crypto_uint2uint);
    for (; i < total_map_num; i++) {
        if (algorithm_to_hash_type[i].src == algorithm) {
            *hash_type = (int32_t)algorithm_to_hash_type[i].dest;
            return CRYPTO_SUCCESS;
        }
    }

    return CRYPTO_BAD_PARAMETERS;
}

static int32_t do_rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct memref_t *digest, const struct memref_t *signature)
{
    int32_t ret;
    mbedtls_rsa_context ctx;
    uint32_t hash_type;
    uint32_t padding;

    bool is_pss_sign_algorithm = check_is_rsa_pss_sign_algorithm(alg_type);
    if (is_pss_sign_algorithm)
        padding = MBEDTLS_RSA_PKCS_V21;
    else
        padding = MBEDTLS_RSA_PKCS_V15;

    ret = get_hash_type_from_algorithm(alg_type, &hash_type);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Get hash type from operation algorithm failed\n");
        return ret;
    }

    mbedtls_rsa_init(&ctx, padding, hash_type);
    if (private_key->crt_mode) {
        ret = rsa_import_crt(&ctx, private_key);
    } else {
        ret = rsa_import_non_crt(&ctx, private_key);
    }
    if (ret != 0) {
        tloge("rsa import failed, ret:%d crt_mode:0x%x\n", ret, private_key->crt_mode);
        mbedtls_rsa_free(&ctx);
        return ret;
    }

    ret = mbedtls_rsa_pkcs1_sign(&ctx, mbd_rand, NULL, MBEDTLS_RSA_PRIVATE, hash_type,
        digest->size, (uint8_t *)(uintptr_t)digest->buffer, (uint8_t *)(uintptr_t)signature->buffer);
    mbedtls_rsa_free(&ctx);
    if (ret != 0)
        tloge("rsa sign fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, ret));

    return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
}

int32_t soft_crypto_rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *digest,
    struct memref_t *signature)
{
    (void)rsa_params;
    if (private_key == NULL || digest == NULL || signature == NULL || digest->buffer == 0 ||
        signature->buffer == 0) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    return do_rsa_sign_digest(alg_type, private_key, digest, signature);
}

static int32_t do_rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct memref_t *digest, const struct memref_t *signature)
{
    int32_t ret;
    mbedtls_rsa_context ctx;
    uint32_t hash_type;
    uint32_t padding;

    bool is_pss_sign_algorithm = check_is_rsa_pss_sign_algorithm(alg_type);
    if (is_pss_sign_algorithm)
        padding = MBEDTLS_RSA_PKCS_V21;
    else
        padding = MBEDTLS_RSA_PKCS_V15;

    ret = get_hash_type_from_algorithm(alg_type, &hash_type);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Get hash type from operation algorithm failed\n");
        return ret;
    }

    mbedtls_rsa_init(&ctx, padding, hash_type);
    ret = mbedtls_mpi_read_binary(&ctx.N, public_key->n, public_key->n_len);
    if (ret != 0) {
        tloge("mpi read binary failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        mbedtls_rsa_free(&ctx);
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    }
    ret = mbedtls_mpi_read_binary(&ctx.E, public_key->e, public_key->e_len);
    if (ret != 0) {
        tloge("mpi read binary failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, ret));
        mbedtls_rsa_free(&ctx);
        return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
    }
    ctx.len = mbedtls_mpi_size(&ctx.N);

    ret = mbedtls_rsa_pkcs1_verify(&ctx, mbd_rand, NULL, MBEDTLS_RSA_PUBLIC, hash_type,
        digest->size, (uint8_t *)(uintptr_t)digest->buffer, (uint8_t *)(uintptr_t)signature->buffer);
    mbedtls_rsa_free(&ctx);
    if (ret != 0)
        tloge("rsa verify fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, ret));

    return get_soft_crypto_error(CRYPTO_SUCCESS, ret);
}

int32_t soft_crypto_rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *digest,
    const struct memref_t *signature)
{
    (void)rsa_params;
    if (public_key == NULL || digest == NULL || signature == NULL || digest->buffer == 0 ||
        signature->buffer == 0) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    return do_rsa_verify_digest(alg_type, public_key, digest, signature);
}
