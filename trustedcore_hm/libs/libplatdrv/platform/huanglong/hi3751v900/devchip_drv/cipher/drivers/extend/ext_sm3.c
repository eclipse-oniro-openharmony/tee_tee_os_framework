/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: extend sm3
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "drv_osal_lib.h"
#include "cryp_hash.h"

#ifdef SOFT_SM3_SUPPORT

/*************************** Internal Structure Definition ****************************/
/* \addtogroup      sm3 */
/* @{ */  /* <!-- [sm3] */

#define ROTATE_DIVIDER 32

hi_u32 rotateleft(hi_u32 x, hi_u32 n)
{
    n %= ROTATE_DIVIDER;

    if (n == 0) {
        return x;
    }

    return (x << n) | (x >> (ROTATE_DIVIDER - n));
}

#define p0(x) ((x) ^  rotateleft((x), 9)  ^ rotateleft((x), 17))
#define p1(x) ((x) ^  rotateleft((x), 15) ^ rotateleft((x), 23))

#define ff0(x, y, z) ((x) ^ (y) ^ (z))
#define ff1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define gg0(x, y, z) ((x) ^ (y) ^ (z))
#define gg1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

#define SM3_BLOCK_SIZE            64
#define SM3_W_SIZE                (SM3_BLOCK_SIZE + WORD_WIDTH)
#define SM3_RESULT_SIZE_IN_WORD   (SM3_RESULT_SIZE / WORD_WIDTH)
#define SM3_PAD_MIN_SIZE          9
#define SM3_PAD_LEN_SIZE          8
#define SM3_BYTE_MSB              0x80

/* SM3, the initial hash value, H(0) */
#define SM3_H0    0x7380166F
#define SM3_H1    0x4914B2B9
#define SM3_H2    0x172442D7
#define SM3_H3    0xDA8A0600
#define SM3_H4    0xA96F30BC
#define SM3_H5    0x163138AA
#define SM3_H6    0xE38DEE4D
#define SM3_H7    0xB0FB0E4E

#define HASH_MAX_BUFFER_SIZE    0x10000 /* 64K */

/**
 * \brief          aes ccm context structure
 */
typedef struct {
    hi_u32 state[SM3_RESULT_SIZE_IN_WORD];
    hi_u8  tail[SM3_BLOCK_SIZE];
    hi_u32 tail_len;
    hi_u32 total;
}
ext_sm3_context;

/** @} */  /** <!-- ==== Structure Definition end ==== */

/******************************* API Code *****************************/
/** \addtogroup      sm3 */
/** @{ */  /** <!-- [sm3] */

hi_s32 sm3_compress(hi_u32 digest[SM3_RESULT_SIZE_IN_WORD], const hi_u8 block[SM3_BLOCK_SIZE])
{
    hi_s32 j;
    hi_s32 k = 0;
    hi_u32 *w = HI_NULL;
    hi_u32 *w1 = HI_NULL;
    hi_u32 *t = HI_NULL;
    const hi_u32 *pblock = (const hi_u32 *)block;
    hi_u32 a = digest[k++];
    hi_u32 b = digest[k++];
    hi_u32 c = digest[k++];
    hi_u32 d = digest[k++];
    hi_u32 e = digest[k++];
    hi_u32 f = digest[k++];
    hi_u32 g = digest[k++];
    hi_u32 h = digest[k++];
    hi_u32 ss1, ss2, tt1, tt2;
    hi_u32 *buffer = HI_NULL;
    hi_u32 buffer_size;
    hi_s32 ret;

    buffer_size = sizeof(hi_u32) * (SM3_W_SIZE + SM3_BLOCK_SIZE + SM3_BLOCK_SIZE);
    buffer = (hi_u32 *)CRYPTO_MALLOC(buffer_size);
    if (buffer == HI_NULL) {
        hi_log_error("sm3 compress crypto malloc buff failed!\n");
        return HI_ERR_CIPHER_FAILED_MEM;
    }
    ret = memset_s(buffer, buffer_size, 0, buffer_size);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, ret);
        CRYPTO_FREE(buffer);
        buffer = HI_NULL;
        return ret;
    }
    w = buffer;
    w1 = buffer + SM3_W_SIZE;
    t = buffer + SM3_W_SIZE + SM3_BLOCK_SIZE;

    for (j = 0; j < 16; j++) { /* 16 */
        w[j] = cipher_cpu_to_be32(pblock[j]);
    }
    for (j = 16; j < SM3_W_SIZE; j++) { /* 16 */
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotateleft(w[j - 3], 15)) /* 16 9 3 15 */
            ^ rotateleft(w[j - 13], 7) ^ w[j - 6]; /* 13 7 6 */
    }
    for (j = 0; j < SM3_BLOCK_SIZE; j++) {
        w1[j] = w[j] ^ w[j + 4]; /* 4 */
    }

    for (j = 0; j < 16; j++) { /* 16 */
        t[j] = 0x79CC4519;
        ss1 = rotateleft((rotateleft(a, 12) + e + rotateleft(t[j], j)), 7); /* 12 7 */
        ss2 = ss1 ^ rotateleft(a, 12); /* 12 */
        tt1 = ff0(a, b, c) + d + ss2 + w1[j];
        tt2 = gg0(e, f, g) + h + ss1 + w[j];
        d = c;
        c = rotateleft(b, 9); /* 9 */
        b = a;
        a = tt1;
        h = g;
        g = rotateleft(f, 19); /* 19 */
        f = e;
        e = p0(tt2);
    }

    for (j = 16; j < SM3_BLOCK_SIZE; j++) { /* 16 */
        t[j] = 0x7A879D8A;
        ss1 = rotateleft((rotateleft(a, 12) + e + rotateleft(t[j], j)), 7); /* 12 7 */
        ss2 = ss1 ^ rotateleft(a, 12); /* 12 */
        tt1 = ff1(a, b, c) + d + ss2 + w1[j];
        tt2 = gg1(e, f, g) + h + ss1 + w[j];
        d = c;
        c = rotateleft(b, 9); /* 9 */
        b = a;
        a = tt1;
        h = g;
        g = rotateleft(f, 19); /* 19 */
        f = e;
        e = p0(tt2);
    }

    k = 0;
    digest[k++] ^= a;
    digest[k++] ^= b;
    digest[k++] ^= c;
    digest[k++] ^= d;
    digest[k++] ^= e;
    digest[k++] ^= f;
    digest[k++] ^= g;
    digest[k++] ^= h;

    if (buffer != HI_NULL) {
        CRYPTO_FREE(buffer);
        buffer = HI_NULL;
    }

    return HI_SUCCESS;
}

static void sm3_init(ext_sm3_context *ctx)
{
    int i = 0;
    hi_log_func_enter();

    ctx->state[i++] = SM3_H0;
    ctx->state[i++] = SM3_H1;
    ctx->state[i++] = SM3_H2;
    ctx->state[i++] = SM3_H3;
    ctx->state[i++] = SM3_H4;
    ctx->state[i++] = SM3_H5;
    ctx->state[i++] = SM3_H6;
    ctx->state[i++] = SM3_H7;

    hi_log_func_exit();

    return;
}

static hi_s32 sm3_update(ext_sm3_context *ctx, const hi_u8 *data, hi_u32 data_len)
{
    hi_u32 left = 0;
    hi_s32 ret = HI_FAILURE;

    hi_log_func_enter();

    ctx->total += data_len;

    if (ctx->tail_len) {
        left = SM3_BLOCK_SIZE - ctx->tail_len;
        if (data_len < left) {
            ret = memcpy_s(ctx->tail + ctx->tail_len, left, data, data_len);
            if (ret != HI_SUCCESS) {
                hi_log_print_func_err(memcpy_s, ret);
                return ret;
            }
            ctx->tail_len += data_len;
            return HI_SUCCESS;
        } else {
            ret = memcpy_s(ctx->tail + ctx->tail_len, left, data, left);
            if (ret != HI_SUCCESS) {
                hi_log_print_func_err(memcpy_s, ret);
                return ret;
            }
            ret = sm3_compress(ctx->state, ctx->tail);
            if (ret != HI_SUCCESS) {
                hi_log_print_func_err(sm3_compress, ret);
                return ret;
            }

            data += left;
            data_len -= left;
        }
    }

    while (data_len >= SM3_BLOCK_SIZE) {
        ret = sm3_compress(ctx->state, data);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(sm3_compress, ret);
            return ret;
        }

        data += SM3_BLOCK_SIZE;
        data_len -= SM3_BLOCK_SIZE;
    }

    ctx->tail_len = data_len;
    if (data_len) {
        ret = memcpy_s(ctx->tail, SM3_BLOCK_SIZE, data, data_len);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(memcpy_s, ret);
            return ret;
        }
    }

    hi_log_func_exit();

    return HI_SUCCESS;
}

static hi_s32 sm3_final(ext_sm3_context *ctx, hi_u8 *digest, hi_u32 digest_buf_len)
{
    hi_s32 i = 0;
    hi_s32 ret = HI_FAILURE;
    hi_u32 hash[SM3_RESULT_SIZE_IN_WORD] = {0};

    hi_log_func_enter();

    ctx->tail[ctx->tail_len] = SM3_BYTE_MSB;

    /* a block is enough */
    if (ctx->tail_len + SM3_PAD_MIN_SIZE <= SM3_BLOCK_SIZE) {
        ret = memset_s(ctx->tail + ctx->tail_len + 1, SM3_BLOCK_SIZE - ctx->tail_len - 1, 0,
            SM3_BLOCK_SIZE - ctx->tail_len - 1);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(memset_s, ret);
            return ret;
        }
    } else {
        /* 2 block is request */
        ret = memset_s(ctx->tail + ctx->tail_len + 1, SM3_BLOCK_SIZE - ctx->tail_len - 1,
            0, SM3_BLOCK_SIZE - ctx->tail_len - 1);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(memset_s, ret);
            return ret;
        }

        ret = sm3_compress(ctx->state, ctx->tail);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(sm3_compress, ret);
            return ret;
        }

        ret = memset_s(ctx->tail, SM3_BLOCK_SIZE, 0, SM3_BLOCK_SIZE);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(memset_s, ret);
            return ret;
        }
    }

    /* write 8 bytes fix data length * 8 */
    ctx->tail[SM3_BLOCK_SIZE - 5] = (hi_u8)((ctx->total >> 29) & 0x07); /* 5 29 0x07 */
    ctx->tail[SM3_BLOCK_SIZE - 4] = (hi_u8)((ctx->total >> 21) & 0xff); /* 4 21 0xff */
    ctx->tail[SM3_BLOCK_SIZE - 3] = (hi_u8)((ctx->total >> 13) & 0xff); /* 3 13 0xff */
    ctx->tail[SM3_BLOCK_SIZE - 2] = (hi_u8)((ctx->total >> 5)  & 0xff); /* 2  5 0xff */
    ctx->tail[SM3_BLOCK_SIZE - 1] = (hi_u8)((ctx->total << 3)  & 0xff); /* 1  3 0xff */

    ret = sm3_compress(ctx->state, ctx->tail);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(sm3_compress, ret);
        return ret;
    }

    for (i = 0; i < SM3_RESULT_SIZE_IN_WORD; i++) {
        hash[i] = cipher_cpu_to_be32(ctx->state[i]);
    }

    ret = memcpy_s(digest, digest_buf_len, hash, SM3_RESULT_SIZE);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(memcpy_s, ret);
        return ret;
    }

    hi_log_func_exit();

    return HI_SUCCESS;
}

void *ext_sm3_create(hash_mode mode)
{
    ext_sm3_context *ctx = HI_NULL;
    hi_s32 ret;

    hi_log_func_enter();

    ctx = CRYPTO_MALLOC(sizeof(ext_sm3_context));
    if (ctx == HI_NULL) {
        hi_log_error("malloc hash context buffer failed!");
        return HI_NULL;
    }

    ret = memset_s(ctx, sizeof(ext_sm3_context), 0, sizeof(ext_sm3_context));
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(memset_s, ret);
        CRYPTO_FREE(ctx);
        ctx = HI_NULL;
        return HI_NULL;
    }

    sm3_init(ctx);

    hi_log_func_exit();

    return ctx;
}

hi_s32 ext_sm3_update(void *ctx, hi_u8 *chunk, hi_u32 chunk_len, hash_chunk_src src)
{
    hi_u8 *ptr = HI_NULL;
    hi_s32 ret = HI_FAILURE;
    hi_u32 offset = 0;
    hi_u32 length = 0;

    hi_log_func_enter();

    hi_log_check_param(ctx == HI_NULL);

    if (chunk_len == 0x00) {
        return HI_SUCCESS;
    }

    if (src == HASH_CHUNCK_SRC_USER) {
        ptr = CRYPTO_MALLOC(HASH_MAX_BUFFER_SIZE);
        if (ptr == HI_NULL) {
            hi_log_error("malloc hash chunk buffer failed, chunkLen 0x%x\n!", chunk_len);
            hi_log_print_err_code(HI_ERR_CIPHER_FAILED_MEM);
            return HI_ERR_CIPHER_FAILED_MEM;
        }

        while (offset < chunk_len) {
            length = chunk_len - offset;
            if (length > HASH_MAX_BUFFER_SIZE) {
                length = HASH_MAX_BUFFER_SIZE;
            }
            ret = crypto_copy_from_user(ptr, HASH_MAX_BUFFER_SIZE, chunk + offset, length);
            if (ret != HI_SUCCESS) {
                hi_log_error("copy hash chunk from user failed!");
                hi_log_print_err_code(HI_ERR_CIPHER_FAILED_MEM);
                goto EXIT;
            }
            ret = sm3_update(ctx, ptr, length);
            if (ret != HI_SUCCESS) {
                hi_log_print_func_err(sm3_update, ret);
                goto EXIT;
            }

            CRYPTO_MSLEEP(1);
            offset   += length;
        }
    } else {
        if (chunk == HI_NULL) {
            hi_log_error("Invalid point,chunk is null!");
            ret = HI_ERR_CIPHER_INVALID_POINT;
            goto EXIT;
        }
        ret = sm3_update(ctx, chunk, chunk_len);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(sm3_update, ret);
            goto EXIT;
        }

        ret = HI_SUCCESS;
    }

EXIT:
    if (ptr != HI_NULL) {
        CRYPTO_FREE(ptr);
        ptr = HI_NULL;
    }

    hi_log_func_exit();

    return ret;
}

hi_s32 ext_sm3_finish(void *ctx, void *hash, hi_u32 hash_buf_len, hi_u32 *hashlen)
{
    hi_s32 ret;
    hi_log_func_enter();

    hi_log_check_param(ctx == HI_NULL);

    ret = sm3_final(ctx, hash, hash_buf_len);
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(sm3_final, ret);
        return ret;
    }
    *hashlen = SM3_RESULT_SIZE;

    hi_log_func_exit();
    return HI_SUCCESS;
}

hi_s32 ext_sm3_destory(const void *ctx)
{
    hi_log_func_enter();

    hi_log_check_param(ctx == HI_NULL);

    CRYPTO_FREE(ctx);
    ctx  = HI_NULL;

    hi_log_func_exit();
    return HI_SUCCESS;
}

#endif
/** @} */  /** <!-- ==== API Code end ==== */
