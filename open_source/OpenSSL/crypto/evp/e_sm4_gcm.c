 /*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/modes.h>

#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include "crypto/evp.h"
#include "modes_local.h"
#include <openssl/rand.h>
#include "evp_local.h"

#ifndef OPENSSL_NO_SM4

#include <crypto/sm4.h>

typedef struct {
    union {
        double align;
        SM4_KEY ks;
    } ks;                       /* SM4 key schedule to use */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    GCM128_CONTEXT gcm;
    unsigned char *iv;          /* Temporary IV store */
    int ivlen;                  /* IV length */
    int taglen;
    int iv_gen;                 /* It is OK to generate IVs */
    int tls_aad_len;            /* TLS AAD length */
    ctr128_f ctr;
} EVP_SM4_GCM_CTX;


static int sm4_gcm_cleanup(EVP_CIPHER_CTX *c)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX, c);
    if(gctx == NULL)
        return 0;
    OPENSSL_cleanse(&gctx->gcm, sizeof(gctx->gcm));
    if (gctx->iv != EVP_CIPHER_CTX_iv_noconst(c))
        OPENSSL_free(gctx->iv);
    return 1;
}

/* increment counter (64-bit int) by 1 */
static void ctr64_inc(unsigned char *counter)
{
    int n = 8;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

static int sm4_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,c);
    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_CTX_iv_length(c);
        gctx->iv = c->iv;
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        gctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = gctx->ivlen;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;
        /* Allocate memory for IV if needed */
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != c->iv)
                OPENSSL_free(gctx->iv);
           if ((gctx->iv = OPENSSL_malloc(arg)) == NULL)
                return 0;
        }
        gctx->ivlen = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || c->encrypt)
            return 0;
        memcpy(c->buf, ptr, arg);
        gctx->taglen = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !c->encrypt
            || gctx->taglen < 0)
            return 0;
        memcpy(ptr, c->buf, arg);
        return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
        /* Special case: -1 length restores whole IV */
        if (arg == -1) {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
        }
        /*
         * Fixed field must be at least 4 bytes and invocation field at least
         * 8.
         */
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (c->encrypt
            && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;

    case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        /*
         * Invocation field will be at least 8 bytes in size and so no need
         * to check wrap around or increment more than last 8 bytes.
         */
        ctr64_inc(gctx->iv + gctx->ivlen - 8);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0 || c->encrypt)
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(c->buf, ptr, arg);
        gctx->tls_aad_len = arg;
        {
            unsigned int len =c->buf[arg - 2] << 8 | c->buf[arg - 1];
            /* Correct length for explicit IV */
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!c->encrypt)
                len -= EVP_GCM_TLS_TAG_LEN;
            c->buf[arg - 2] = len >> 8;
            c->buf[arg - 1] = len & 0xff;
        }
        /* Extra padding: tag appended to record */
        return EVP_GCM_TLS_TAG_LEN;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_SM4_GCM_CTX *gctx_out = EVP_C_DATA(EVP_SM4_GCM_CTX,out);
            if (gctx->gcm.key) {
                if (gctx->gcm.key != &gctx->ks)
                    return 0;
                gctx_out->gcm.key = &gctx_out->ks;
            }
            if (gctx->iv == c->iv)
                gctx_out->iv = out->iv;
            else {
                gctx_out->iv = OPENSSL_malloc(gctx->ivlen);
                if (gctx_out->iv == NULL)
                    return 0;
                memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
            }
            return 1;
        }

    default:
        return -1;

    }
}

static int sm4_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);
    if (!iv && !key)
        return 1;
    if (key) {
        do {
            (void)0;        /* terminate potentially open 'else' */

            SM4_gcm_set_key(&(gctx->ks.ks), key);
            CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks,
                               (block128_f)SM4_encrypt);
            gctx->ctr = NULL;
        } while (0);

        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (gctx->key_set)
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
}

/*
 * Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */

static int sm4_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t len)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);
    int rv = -1;
    /* Encrypt/decrypt must be performed in place */
    if (out != in
        || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        return -1;
    /*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, ctx->encrypt ?
                            EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
        goto err;
    /* Use saved AAD */
    if (CRYPTO_gcm128_aad(&gctx->gcm, ctx->buf, gctx->tls_aad_len))
        goto err;
    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    if (ctx->encrypt) {
        /* Encrypt payload */
        if (gctx->ctr) {
            size_t bulk = 0;
            if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
            if (CRYPTO_gcm128_encrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        out += len;
        /* Finally write tag */
        CRYPTO_gcm128_tag(&gctx->gcm, out, EVP_GCM_TLS_TAG_LEN);
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    } else {
        /* Decrypt */
        if (gctx->ctr) {
            size_t bulk = 0;
            if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
            if (CRYPTO_gcm128_decrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        /* Retrieve tag */
        CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, EVP_GCM_TLS_TAG_LEN);
        /* If tag mismatch wipe buffer */
        if (CRYPTO_memcmp(ctx->buf, in + len, EVP_GCM_TLS_TAG_LEN)) {
            OPENSSL_cleanse(out, len);
            goto err;
        }
        rv = len;
    }

 err:
    gctx->iv_set = 0;
    gctx->tls_aad_len = -1;
    return rv;
}

static int sm4_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);
    /* If not set up, return error */
    if (!gctx->key_set)
        return -1;

    if (gctx->tls_aad_len >= 0)
        return sm4_gcm_tls_cipher(ctx, out, in, len);

    if (!gctx->iv_set)
        return -1;
    if (in) {
        if (out == NULL) {
            if (CRYPTO_gcm128_aad(&gctx->gcm, in, len))
                return -1;
        } else if (ctx->encrypt) {
            if (gctx->ctr) {
                size_t bulk = 0;
                if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
                                                in + bulk,
                                                out + bulk,
                                                len - bulk, gctx->ctr))
                    return -1;
            } else {
                size_t bulk = 0;
                if (CRYPTO_gcm128_encrypt(&gctx->gcm,
                                          in + bulk, out + bulk, len - bulk))
                    return -1;
            }
        } else {
            if (gctx->ctr) {
                size_t bulk = 0;
                if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
                                                in + bulk,
                                                out + bulk,
                                                len - bulk, gctx->ctr))
                    return -1;
            } else {
                size_t bulk = 0;
                if (CRYPTO_gcm128_decrypt(&gctx->gcm,
                                          in + bulk, out + bulk, len - bulk))
                    return -1;
            }
        }
        return len;
    } else {
        if (!ctx->encrypt) {
            if (gctx->taglen < 0)
                return -1;
            if (CRYPTO_gcm128_finish(&gctx->gcm, ctx->buf, gctx->taglen) != 0)
                return -1;
            gctx->iv_set = 0;
            return 0;
        }
        CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, 16);
        gctx->taglen = 16;
        /* Don't reuse the IV */
        gctx->iv_set = 0;
        return 0;
    }

}

#define SM4_GCM_BLOCK_SIZE	1
#define SM4_GCM_IV_LENGTH	12

#define SM4_GCM_FLAGS (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY \
		| EVP_CIPH_FLAG_AEAD_CIPHER)

static const EVP_CIPHER sm4_gcm = {
	NID_sm4_gcm,
	SM4_GCM_BLOCK_SIZE,
	SM4_KEY_LENGTH,
	SM4_GCM_IV_LENGTH,
	SM4_GCM_FLAGS,
	sm4_gcm_init_key,
	sm4_gcm_cipher,
	sm4_gcm_cleanup,
	sizeof(EVP_SM4_GCM_CTX),
	NULL, NULL, sm4_gcm_ctrl, NULL
};

const EVP_CIPHER *EVP_sm4_gcm(void) {
	return &sm4_gcm;
}

#endif /* OPENSSL_NO_SM4 */
