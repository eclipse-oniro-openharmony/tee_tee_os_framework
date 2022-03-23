/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Crypto API at driver adaptor.
 * Create: 2020-03-24
 */
#include "crypto_hal.h"
#include <securec.h>
#include <tee_log.h>
#include <tee_crypto_hal.h>
#include "crypto_manager.h"
#include "soft_common_api.h"
#include "crypto_mgr_syscall.h"
#include "ccmgr_hm.h"
#include "sys/usrsyscall_ext.h"
#include <api/errno.h>
#include "tee_drv_client.h"

#define MAX_CRYPTO_RANDOM_LEN (500 * 1024)
#define MAX_CRYPTO_CTX_SIZE   (1024 * 1024)

#ifdef CRYPTO_MGR_SERVER_ENABLE
static int64_t get_ctx_fd_handle(uint32_t alg_type)
{
    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint32_t args = (uint32_t)(&alg_type);
    return tee_drv_open(drv_name, &args, sizeof(args));
}
#endif

static struct ctx_handle_t *driver_alloc_ctx_handle(uint32_t alg_type, uint32_t engine, struct ctx_handle_t *ctx)
{
    int32_t ctx_size;
    uint8_t *ctx_ctx_buffer = NULL;
#ifdef CRYPTO_MGR_SERVER_ENABLE
    int64_t fd = get_ctx_fd_handle(alg_type);
    if (fd <= 0) {
        tloge("open fd failed\n");
        goto error;
    }
    ctx_size = crypto_driver_get_ctx_size(alg_type, fd);
#else
    ctx_size = crypto_driver_get_ctx_size(alg_type, engine);
#endif
    bool check = ((ctx_size <= 0) || (ctx_size > MAX_CRYPTO_CTX_SIZE));
    if (check) {
        tloge("Get ctx size failed, ctx size=%d, algorithm type=0x%x, engine=0x%x\n", ctx_size, alg_type, engine);
        goto error;
    }

    ctx_ctx_buffer = (uint8_t *)malloc_coherent((size_t)ctx_size);
    if (ctx_ctx_buffer == NULL) {
        tloge("Malloc ctx buffer failed, ctx size=%d\n", ctx_size);
        goto error;
    }
    if (memset_s(ctx_ctx_buffer, (size_t)ctx_size, 0, (size_t)ctx_size) != EOK) {
        tloge("memset ctx buffer failed\n");
        goto error;
    }
#ifdef CRYPTO_MGR_SERVER_ENABLE
    ctx->driver_ability = crypto_driver_get_driver_ability(fd);
    ctx->fd = fd;
#else
    ctx->driver_ability = (uint32_t)crypto_driver_get_driver_ability(engine);
#endif
    ctx->ctx_buffer = (uint64_t)(uintptr_t)ctx_ctx_buffer;
    ctx->ctx_size = (uint32_t)ctx_size;
    return ctx;

error:
    if (ctx_ctx_buffer != NULL) {
        TEE_Free(ctx_ctx_buffer);
        ctx_ctx_buffer = NULL;
    }
#ifdef CRYPTO_MGR_SERVER_ENABLE
    if (fd < 0)
        tee_drv_close(fd);
#endif
    TEE_Free(ctx);
    return NULL;
}

struct ctx_handle_t *alloc_ctx_handle(uint32_t alg_type, uint32_t engine)
{
    struct ctx_handle_t *ctx = TEE_Malloc(sizeof(*ctx), 0);
    if (ctx == NULL) {
        tloge("Malloc ctx handle failed\n");
        return NULL;
    }
    ctx->alg_type = alg_type;
    ctx->engine = engine;
    if (engine == SOFT_CRYPTO)
        return ctx;

    return driver_alloc_ctx_handle(alg_type, engine, ctx);
}

static void free_crypto_cache(struct crypto_cache_t *crypto_cache)
{
    if (crypto_cache != NULL) {
        if (crypto_cache->buffer != NULL) {
            (void)memset_s(crypto_cache->buffer, crypto_cache->total_len, 0, crypto_cache->total_len);
            TEE_Free(crypto_cache->buffer);
            crypto_cache->buffer = NULL;
        }
        TEE_Free(crypto_cache);
        crypto_cache = NULL;
    }
}

static int32_t tee_crypto_ctx_cache_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx)
{
    struct crypto_cache_t *src_cache = (struct crypto_cache_t *)(uintptr_t)(src_ctx->cache_buffer);
    struct crypto_cache_t *dest_cache = (struct crypto_cache_t *)(uintptr_t)(dest_ctx->cache_buffer);

    free_crypto_cache(dest_cache);
    dest_ctx->cache_buffer = 0;

    if (src_ctx->cache_buffer == 0)
        return CRYPTO_SUCCESS;

    bool check = ((src_cache->total_len == 0) || (src_cache->total_len > MAX_CRYPTO_DATA_LEN));
    if (check) {
        tloge("The src cache len is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    dest_cache = TEE_Malloc(sizeof(*dest_cache), 0);
    if (dest_cache == NULL) {
        tloge("Malloc cache buffer failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    dest_cache->buffer = TEE_Malloc(src_cache->total_len, 0);
    if (dest_cache->buffer == NULL) {
        tloge("Malloc cache buffer failed\n");
        TEE_Free(dest_cache);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    (void)memcpy_s(dest_cache->buffer, src_cache->total_len, src_cache->buffer, src_cache->total_len);

    dest_cache->total_len = src_cache->total_len;
    dest_cache->effective_len = src_cache->effective_len;

    dest_ctx->cache_buffer = (uint64_t)(uintptr_t)dest_cache;

    return CRYPTO_SUCCESS;
}

static void free_ctx_buff(struct ctx_handle_t *ctx)
{
    if (ctx->ctx_buffer != 0) {
        if (ctx->free_context != NULL) {
            ctx->free_context(&(ctx->ctx_buffer));
        } else {
            uint8_t *ctx_ctx_buffer = (uint8_t *)(uintptr_t)(ctx->ctx_buffer);
            (void)memset_s(ctx_ctx_buffer, ctx->ctx_size, 0x0, ctx->ctx_size);
            TEE_Free(ctx_ctx_buffer);
            ctx_ctx_buffer = NULL;
        }
        ctx->ctx_buffer = 0;
    }
}

void tee_crypto_ctx_free(struct ctx_handle_t *ctx)
{
    if (ctx == NULL)
        return;
    free_ctx_buff(ctx);
    struct crypto_cache_t *cache = (struct crypto_cache_t *)(uintptr_t)(ctx->cache_buffer);
    free_crypto_cache(cache);
    cache = NULL;
    TEE_Free(ctx);
    if (ctx->fd != 0) {
        int32_t ret = tee_drv_close(ctx->fd);
        if (ret != 0)
            tloge("close fd fail fd = 0x%x, ret = 0x%x\n", ctx->fd, ret);
    }
}

int32_t tee_crypto_ctx_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx)
{
    bool check = ((src_ctx == NULL) || (dest_ctx == NULL) || src_ctx->ctx_size > MAX_CRYPTO_CTX_SIZE);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    if (src_ctx == dest_ctx)
        return CRYPTO_SUCCESS;

    dest_ctx->alg_type = src_ctx->alg_type;
    dest_ctx->ctx_size = src_ctx->ctx_size;
    dest_ctx->direction = src_ctx->direction;
    dest_ctx->engine = src_ctx->engine;
    dest_ctx->is_support_ae_update = src_ctx->is_support_ae_update;
    dest_ctx->tag_len = src_ctx->tag_len;

    (void)memcpy_s(dest_ctx->cbc_mac_buffer, sizeof(dest_ctx->cbc_mac_buffer),
        src_ctx->cbc_mac_buffer, sizeof(src_ctx->cbc_mac_buffer));
    (void)memcpy_s(dest_ctx->cipher_cache_data, sizeof(dest_ctx->cipher_cache_data),
        src_ctx->cipher_cache_data, sizeof(src_ctx->cipher_cache_data));

    dest_ctx->cipher_cache_len = src_ctx->cipher_cache_len;
    dest_ctx->free_context = src_ctx->free_context;

    int32_t ret;
    if (src_ctx->engine == SOFT_CRYPTO) {
        ret = soft_crypto_ctx_copy(src_ctx, dest_ctx);
    } else {
        TEE_Free((void *)(uintptr_t)(dest_ctx->ctx_buffer));
        dest_ctx->ctx_buffer = (uintptr_t)TEE_Malloc(src_ctx->ctx_size, 0);
        if (dest_ctx->ctx_buffer == 0) {
            tloge("malloc crypto ctx failed");
            return CRYPTO_ERROR_OUT_OF_MEMORY;
        }
        ret = crypto_driver_ctx_copy(src_ctx, dest_ctx);
    }
    if (ret != CRYPTO_SUCCESS)
        goto free_ctx;

    if (src_ctx->cache_buffer == 0)
        return CRYPTO_SUCCESS;

    ret = tee_crypto_ctx_cache_copy(src_ctx, dest_ctx);
    if (ret != CRYPTO_SUCCESS)
        goto free_ctx;
    return CRYPTO_SUCCESS;

free_ctx:
    tloge("copy stx failed, ret = %d", ret);
    if (src_ctx->engine != SOFT_CRYPTO) {
        TEE_Free((void *)(uintptr_t)(dest_ctx->ctx_buffer));
        dest_ctx->ctx_buffer = 0;
    } else {
        free_ctx_buff(dest_ctx);
    }
    return ret;
}

#define LCG96_RAND_NUM 63
#define U32_VAL_MAX    0xffffffffull
#define U32_BITS       32
#define WORD_SIZE      4

static uint32_t g_seed = 0xa897213f;

enum {
    LCG96_U32_LOW = 0,
    LCG96_U32_MID = 1,
    LCG96_U32_HIG = 2,
    LCG96_U32_NUM = 3
};

/*
 * LCG(Linear Congruential Generator) is an algorithm that yields a sequence
 * of pseudo-randomized numbers calculated with a discontinuous piecewise
 * linear equation.
 * The generator is defined by recurrence relation:
 * X(i+1) = (a * X(i) + c) (mod m), i >= 0 && i < n
 * The "X(0...n-1)" is just the "g_lcg96_rand[]" array
 */
static unsigned long long g_lcg96_rand[LCG96_RAND_NUM];

#define MULTIPLIER_NUM1 0x5aa1cae5
#define MULTIPLIER_NUM2 0xd0cf37be
#define MULTIPLIER_NUM3 0x92efd1b8

/* The "a" in the above formula is the g_multiplier, and its value is 5^41 */
static const unsigned int g_multiplier[LCG96_U32_NUM] = {
    MULTIPLIER_NUM1,
    MULTIPLIER_NUM2,
    MULTIPLIER_NUM3
};

/* Calculate: x1 = (g_multiplier[] * x0 + 1) (mod 2^96) */
static void lcg96_calc(const unsigned int *x0, unsigned int *x1)
{
    int i, j, k, h;
    unsigned int t[LCG96_U32_NUM];
    unsigned long long tmp, carry;

    for (i = 0; i < LCG96_U32_NUM; i++) {
        x1[i] = 0;
        t[i] = 0;
    }
    x1[0] = 1;

    for (i = 0; i < LCG96_U32_NUM; i++) {
        for (j = 0; j < LCG96_U32_NUM && (i + j) < LCG96_U32_NUM; j++) {
            tmp = (unsigned long long)g_multiplier[i] *
                  (unsigned long long)x0[j];
            t[1] = (unsigned int)(tmp >> U32_BITS);
            t[0] = (unsigned int)tmp;
            carry = 0ull;
            for (k = i + j; k < LCG96_U32_NUM; k++) {
                h = k - (i + j);
                tmp = (unsigned long long)x1[k] + t[h] + carry;
                carry = (tmp > U32_VAL_MAX) ? 1ull : 0ull;
                x1[k] = (unsigned int)tmp;
            }
        }
    }
}

static void random_seed(unsigned int seed)
{
#define LCG96_XI_NUM    2
    int i, j;
    unsigned int x_i[LCG96_XI_NUM][LCG96_U32_NUM];

    for (i = 0; i < LCG96_XI_NUM; i++) {
        for (j = LCG96_U32_LOW; j < LCG96_U32_NUM; j++)
            x_i[i][j] = 0;
    }
    x_i[0][LCG96_U32_LOW] = seed;
    j = 0;
    for (i = 0; i < LCG96_RAND_NUM; i++) {
        lcg96_calc(x_i[j], x_i[1 - j]);
        j = 1 - j;
        /* Take bits 95...32 of "Xi[]" as g_lcg96_rand numbers */
        g_lcg96_rand[i] =
            (unsigned long long)x_i[j][LCG96_U32_HIG] |
            ((unsigned long long)x_i[j][LCG96_U32_MID] << U32_BITS);
    }
    /* make sure g_lcg96_rand contains at least one odd number */
    g_lcg96_rand[0] |= 1ull;
#undef LCG96_XI_NUM
}

#define NEXT_SEED_NUM1 0x57e32a47
#define NEXT_SEED_NUM2 0x207c87a3

static void next_seed(void)
{
    g_seed = (uint32_t)(g_seed * NEXT_SEED_NUM1 + NEXT_SEED_NUM2);
}

static uint32_t random_arch_get(void)
{
    next_seed();
#define LCG96_OFFSET    5
    static int rand_idx = 1;
    int i = rand_idx;
    int j = (i + LCG96_OFFSET) % LCG96_RAND_NUM;

    random_seed(g_seed);

    g_lcg96_rand[j] += g_lcg96_rand[i];
    rand_idx = (rand_idx + 1) % LCG96_RAND_NUM;

    return (uint32_t)g_lcg96_rand[j];
#undef LCG96_OFFSET
}

int32_t soft_random_get(uint8_t *trng_addr, uint32_t length)
{
    uint32_t i;
    uint32_t value;
    uint32_t *tmp_addr = NULL;
    uint32_t left;

    if (trng_addr == NULL) {
        printf("bad param!\n");
        return -1;
    }

    left = length % WORD_SIZE;
    tmp_addr = (uint32_t *)trng_addr;

    for (i = 0; i < length / WORD_SIZE; i++) {
        tmp_addr[i] = random_arch_get();
        if (tmp_addr[i] == 0) {
            printf("get rng value error!\n");
            return -1;
        }
    }

    if (left == 0)
        return 0;

    value = random_arch_get();
    if (memcpy_s(trng_addr + i * WORD_SIZE, length - i * WORD_SIZE, (char *)(&value), left) != EOK) {
        printf("copy random error!\n");
        return -1;
    }

    return 0;
}

int32_t get_seed_from_sysmgr(void)
{
    struct acquire_rnd_msg msg = { {{ 0 }} };
    struct acquire_rnd_reply rmsg;
    int32_t ret;
    cref_t sysmgrch = hmapi_get_sysmgrch();

    msg.header.send.msg_class = HM_MSG_HEADER_CLASS_ACQUIRE_RND;
    msg.header.send.msg_flags = 0;
    msg.header.send.msg_id    = 0x0;
    msg.header.send.msg_size  = sizeof(msg);

    ret = hm_msg_call(sysmgrch, &msg, sizeof(msg), &rmsg, sizeof(rmsg), 0, HM_NO_TIMEOUT);
    if (ret != HM_OK) {
        tloge("crypto manage: hm_msg_call 0x%x failed: %d\n", sysmgrch, ret);
        return HM_ERROR;
    }
    g_seed = (uint32_t)rmsg.rnd;
    return (int32_t)rmsg.header.reply.ret_val;
}

int32_t tee_crypto_generate_random(void *buffer, uint32_t size)
{
    if ((buffer == NULL) || (size == 0)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (size > MAX_RANDOM_SIZE) {
        tloge("this random size is too large!");
        return CRYPTO_BAD_PARAMETERS;
    }

    size_t offset_len = 0;
    int32_t ret;

    while (size > MAX_CRYPTO_RANDOM_LEN) {
#if !defined(TEE_SUPPORT_PLATDRV_64BIT) && !defined(TEE_SUPPORT_PLATDRV_32BIT) && !defined(CRYPTO_MGR_SERVER_ENABLE)
        ret = soft_random_get(buffer + offset_len, MAX_CRYPTO_RANDOM_LEN);
#else
        ret = crypto_driver_generate_random(buffer + offset_len, MAX_CRYPTO_RANDOM_LEN);
#endif
        if (ret != CRYPTO_SUCCESS) {
            tloge("driver generate random failed, ret = 0x%x\n", ret);
            return ret;
        }
        size -= MAX_CRYPTO_RANDOM_LEN;
        offset_len += MAX_CRYPTO_RANDOM_LEN;
    }
#if !defined(TEE_SUPPORT_PLATDRV_64BIT) && !defined(TEE_SUPPORT_PLATDRV_32BIT) && !defined(CRYPTO_MGR_SERVER_ENABLE)
    ret = soft_random_get(buffer + offset_len, size);
#else
    ret = crypto_driver_generate_random(buffer + offset_len, size);
#endif
    return ret;
}
