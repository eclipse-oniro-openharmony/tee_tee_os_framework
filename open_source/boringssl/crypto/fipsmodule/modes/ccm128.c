/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: implament boringssl aes ccm
 * Author: gaobo j00499231
 * Create: 2019-07-25
 */

#include <string.h>

#include <openssl/crypto.h>

#include "internal.h"

#if defined(__aarch64__)
# define U64(C) C##UL
#else
# define U64(C) C##ULL
#endif

#define CCM_BASE_NUM_TWO   2
#define CCM_BASE_NUM_THREE 3
#define CCM_LOW_THREE_MASK 7
#define CCM_MAX_BLOCK_INDEX (AES_BLOCK_SIZE - 1)

/*
 * First you setup M and L parameters and pass the key schedule. This is
 * called once per session setup...
 */
#define CCM_INVALID_INIT_PARAM(ctx, m, l, block) \
	(((ctx) == NULL) || ((block) == NULL) || ((m) < CCM_BASE_NUM_TWO) || ((l) < 1))

void crypto_ccm128_init2(ccm128_cipher_ctx *ctx, unsigned int m, unsigned int l, block128_f block)
{
	if (CCM_INVALID_INIT_PARAM(ctx, m, l, block))
		return;

	OPENSSL_memset(ctx->nonce.c, 0, sizeof(ctx->nonce.c));
	ctx->nonce.c[0] = (((uint8_t)(l - 1) & CCM_LOW_THREE_MASK) |
		((uint8_t)(((m - CCM_BASE_NUM_TWO) >> 1) & CCM_LOW_THREE_MASK) << CCM_BASE_NUM_THREE));
	ctx->block = block;
	ctx->blocks = 0;
}

#define SHIFT_SEVEN_BYTES 56
#define SHIFT_SIX_BYTES   48
#define SHIFT_FIVE_BYTES  40
#define SHIFT_FOUR_BYTES  32
#define SHIFT_THREE_BYTES 24
#define SHIFT_TWO_BYTES   16
#define SHIFT_ONE_BYTES   8
#define SET_CCM_LONG_IV(ctx, msg_len) do { \
	(ctx)->nonce.c[8] = (uint8_t)((msg_len) >> SHIFT_SEVEN_BYTES); \
	(ctx)->nonce.c[9] = (uint8_t)((msg_len) >> SHIFT_SIX_BYTES); \
	(ctx)->nonce.c[10] = (uint8_t)((msg_len) >> SHIFT_FIVE_BYTES); \
	(ctx)->nonce.c[11] = (uint8_t)((msg_len) >> SHIFT_FOUR_BYTES); \
	(ctx)->nonce.c[12] = (uint8_t)((msg_len) >> SHIFT_THREE_BYTES); \
	(ctx)->nonce.c[13] = (uint8_t)((msg_len) >> SHIFT_TWO_BYTES); \
	(ctx)->nonce.c[14] = (uint8_t)((msg_len) >> SHIFT_ONE_BYTES); \
	(ctx)->nonce.c[15] = (uint8_t)(msg_len); \
} while (0)

#define SET_CCM_SHORT_IV(ctx, msg_len) do { \
	(ctx)->nonce.u[1] = 0; \
	(ctx)->nonce.c[12] = (uint8_t)((msg_len) >> SHIFT_THREE_BYTES); \
	(ctx)->nonce.c[13] = (uint8_t)((msg_len) >> SHIFT_TWO_BYTES); \
	(ctx)->nonce.c[14] = (uint8_t)((msg_len) >> SHIFT_ONE_BYTES); \
	(ctx)->nonce.c[15] = (uint8_t)(msg_len); \
} while (0)

/* Then you setup per-message nonce and pass the length of the message */
#define CCM_AAD_FLAG (0x40)
#define CCM_64_BITS_FLAG 8
#define CCM_NONCE_UP_BIT_VALUE 14
int crypto_ccm128_set_iv(ccm128_cipher_ctx *ctx, const unsigned char *nonce, size_t nonce_len, size_t msg_len)
{
	if ((ctx == NULL) || (nonce == NULL))
		return -1;
	unsigned int l = ctx->nonce.c[0] & CCM_LOW_THREE_MASK; /* the L parameter */
	if (nonce_len < (CCM_NONCE_UP_BIT_VALUE - l))
		return -1;

	if ((sizeof(msg_len) == CCM_64_BITS_FLAG) && (l >= CCM_BASE_NUM_THREE))
		SET_CCM_LONG_IV(ctx, msg_len);
	else
		SET_CCM_SHORT_IV(ctx, msg_len);

	ctx->nonce.c[0] &= ~CCM_AAD_FLAG;
	OPENSSL_memcpy(&ctx->nonce.c[1], nonce, CCM_NONCE_UP_BIT_VALUE - l);
	return 0;
}

#define SET_CCM_SMALL_AAD(ctx, aad_len) do { \
	(ctx)->cmac.c[0] ^= (uint8_t)((aad_len) >> SHIFT_ONE_BYTES); \
	(ctx)->cmac.c[1] ^= (uint8_t)(aad_len); \
} while (0)

#define BIG_AAD_HEAD_NUM (0xFF)
#define SET_CCM_BIG_AAD(ctx, aad_len) do { \
	(ctx)->cmac.c[0] ^= BIG_AAD_HEAD_NUM; \
	(ctx)->cmac.c[1] ^= BIG_AAD_HEAD_NUM; \
	(ctx)->cmac.c[2] ^= (uint8_t)((aad_len) >> SHIFT_SEVEN_BYTES); \
	(ctx)->cmac.c[3] ^= (uint8_t)((aad_len) >> SHIFT_SIX_BYTES); \
	(ctx)->cmac.c[4] ^= (uint8_t)((aad_len) >> SHIFT_FIVE_BYTES); \
	(ctx)->cmac.c[5] ^= (uint8_t)((aad_len) >> SHIFT_FOUR_BYTES); \
	(ctx)->cmac.c[6] ^= (uint8_t)((aad_len) >> SHIFT_THREE_BYTES); \
	(ctx)->cmac.c[7] ^= (uint8_t)((aad_len) >> SHIFT_TWO_BYTES); \
	(ctx)->cmac.c[8] ^= (uint8_t)((aad_len) >> SHIFT_ONE_BYTES); \
	(ctx)->cmac.c[9] ^= (uint8_t)(aad_len); \
} while (0)

#define MIDDLE_AAD_HEAD_NUM1 (0xFF)
#define MIDDLE_AAD_HEAD_NUM2 (0xFE)
#define SET_CCM_MIDDLE_AAD(ctx, aad_len) do { \
	(ctx)->cmac.c[0] ^= MIDDLE_AAD_HEAD_NUM1; \
	(ctx)->cmac.c[1] ^= MIDDLE_AAD_HEAD_NUM2; \
	(ctx)->cmac.c[2] ^= (uint8_t)((aad_len) >> SHIFT_THREE_BYTES); \
	(ctx)->cmac.c[3] ^= (uint8_t)((aad_len) >> SHIFT_TWO_BYTES); \
	(ctx)->cmac.c[4] ^= (uint8_t)((aad_len) >> SHIFT_ONE_BYTES); \
	(ctx)->cmac.c[5] ^= (uint8_t)(aad_len); \
} while (0)

static void do_crypto_ccm_aad(ccm128_cipher_ctx *ctx,
	const unsigned char *aad, size_t aad_len, unsigned int aad_bytes)
{
	block128_f block = ctx->block;
	do {
		for (;((aad_bytes < AES_BLOCK_SIZE) && (aad_len != 0));) {
			ctx->cmac.c[aad_bytes] ^= *aad;
			aad++;
			aad_len--;
			aad_bytes++;
		}
		(*block)(ctx->cmac.c, ctx->cmac.c, &(ctx->key));
		ctx->blocks++;
		aad_bytes = 0;
	} while (aad_len != 0);
}

/* Then you pass additional authentication data, this is optional */
#define SMALL_AAD_MAX_VALUE (0x10000 - 0x100)
#define SMALL_AAD_BYTES_NUM  2
#define BIG_AAD_BYTES_NUM    10
#define MIDDLE_AAD_BYTES_NUM 6
#define CCM_INVALID_AAD_PARAM(ctx, aad, aad_len) \
	(((ctx) == NULL) || ((ctx)->block == NULL) || ((aad) == NULL) || ((aad_len) == 0))

void crypto_ccm128_aad(ccm128_cipher_ctx *ctx, const unsigned char *aad, size_t aad_len)
{
	if (CCM_INVALID_AAD_PARAM(ctx, aad, aad_len))
		return;

	unsigned int aad_bytes = 0;
	block128_f block = ctx->block;

	ctx->nonce.c[0] |= CCM_AAD_FLAG;
	(*block)(ctx->nonce.c, ctx->cmac.c, &(ctx->key));
	ctx->blocks++;

	if (aad_len < SMALL_AAD_MAX_VALUE) {
		SET_CCM_SMALL_AAD(ctx, aad_len);
		aad_bytes = SMALL_AAD_BYTES_NUM;
	} else if ((sizeof(aad_len) == CCM_64_BITS_FLAG) && (aad_len >= ((size_t)1 << SHIFT_FOUR_BYTES))) {
		SET_CCM_BIG_AAD(ctx, aad_len);
		aad_bytes = BIG_AAD_BYTES_NUM;
	} else {
		SET_CCM_MIDDLE_AAD(ctx, aad_len);
		aad_bytes = MIDDLE_AAD_BYTES_NUM;
	}

	do_crypto_ccm_aad(ctx, aad, aad_len, aad_bytes);
}

/*
 * counter part of nonce may not be larger than L*8 bits, L is not larger
 * than 8, therefore 64-bit counter...
 */
#define LOOP_VALUE 8
static void ctr64_inc(unsigned char *counter, unsigned int len)
{
	unsigned int loop = LOOP_VALUE;
	if (len < AES_BLOCK_SIZE)
		return;
	counter += SHIFT_ONE_BYTES;

	while (loop != 0) {
		uint8_t tmp = counter[--loop];
		counter[loop] = ++tmp;
		if (tmp != 0)
			break;
	}
}

static uint64_t get_ccm_payload(ccm128_cipher_ctx *ctx)
{
	uint64_t payload = 0;
	unsigned char flags0 = ctx->nonce.c[0];
	ctx->nonce.c[0] = (flags0 & CCM_LOW_THREE_MASK);
	unsigned int index = (CCM_MAX_BLOCK_INDEX - (flags0 & CCM_LOW_THREE_MASK));

	for (; index < CCM_MAX_BLOCK_INDEX; ++index) {
		payload |= ctx->nonce.c[index];
		ctx->nonce.c[index] = 0;
		payload <<= SHIFT_ONE_BYTES;
	}

	payload |= ctx->nonce.c[CCM_MAX_BLOCK_INDEX];
	return payload;
}

static void do_ccm_not_block_encrypt(ccm128_cipher_ctx *ctx,
	const unsigned char *input, unsigned char *output, uint64_t input_len)
{
	uint64_t index;
	block128_f block = ctx->block;
	ccm128_block flexible_buffer = {0};

	for (index = 0; index < input_len; ++index)
		ctx->cmac.c[index] ^= input[index];
	(*block)(ctx->cmac.c, ctx->cmac.c, &(ctx->key));
	(*block)(ctx->nonce.c, flexible_buffer.c, &(ctx->key));
	for (index = 0; index < input_len; ++index)
		output[index] = flexible_buffer.c[index] ^ input[index];

	return;
}

static uint64_t do_ccm_block_encrypt(ccm128_cipher_ctx *ctx,
	const unsigned char *input, unsigned char *output, uint64_t input_len)
{
	uint64_t offset = 0;
	block128_f block = ctx->block;
	ccm128_block flexible_buffer = {0};

	while (input_len >= AES_BLOCK_SIZE) {
#if defined(STRICT_ALIGNMENT)
		ccm128_block temp = {0};
		OPENSSL_memcpy(temp.c, input, AES_BLOCK_SIZE);
		ctx->cmac.u[0] ^= temp.u[0];
		ctx->cmac.u[1] ^= temp.u[1];
#else
		ctx->cmac.u[0] ^= ((uint64_t *)(input))[0];
		ctx->cmac.u[1] ^= ((uint64_t *)(input))[1];
#endif
		(*block)(ctx->cmac.c, ctx->cmac.c, &(ctx->key));
		(*block)(ctx->nonce.c, flexible_buffer.c, &(ctx->key));
		ctr64_inc(ctx->nonce.c, AES_BLOCK_SIZE);
#if defined(STRICT_ALIGNMENT)
		temp.u[0] ^= flexible_buffer.u[0];
		temp.u[1] ^= flexible_buffer.u[1];
		OPENSSL_memcpy(output, temp.c, AES_BLOCK_SIZE);
#else
		((uint64_t *)(output))[0] = flexible_buffer.u[0] ^ ((uint64_t *)(input))[0];
		((uint64_t *)(output))[1] = flexible_buffer.u[1] ^ ((uint64_t *)(input))[1];
#endif
		input_len -= AES_BLOCK_SIZE;
		output += AES_BLOCK_SIZE;
		input += AES_BLOCK_SIZE;
		offset += AES_BLOCK_SIZE;
	}

	return offset;
}

static void reset_ccm_ctx(ccm128_cipher_ctx *ctx, unsigned char flags0)
{
	block128_f block = ctx->block;
	ccm128_block flexible_buffer = {0};

	unsigned int index = CCM_MAX_BLOCK_INDEX - (flags0 & CCM_LOW_THREE_MASK);
	for (; index < AES_BLOCK_SIZE; ++index)
		ctx->nonce.c[index] = 0;

	(*block)(ctx->nonce.c, flexible_buffer.c, &(ctx->key));
	ctx->cmac.u[0] ^= flexible_buffer.u[0];
	ctx->cmac.u[1] ^= flexible_buffer.u[1];

	ctx->nonce.c[0] = flags0;
}

#define CCM_MAX_VALUE (U64(1) << 61)
#define CCM_INVALID_ENCRYPT_PARAM(ctx, inp, out, len) \
	(((ctx) == NULL) || ((ctx)->block == NULL) || \
		((inp) == NULL) || ((out) == NULL) || ((len) > (CCM_MAX_VALUE - CCM_MAX_BLOCK_INDEX)))

int crypto_ccm128_encrypt2(ccm128_cipher_ctx *ctx,
    const unsigned char *inp, unsigned char *out, size_t len)
{
	if (CCM_INVALID_ENCRYPT_PARAM(ctx, inp, out, len))
		return -1;

	unsigned char flags0 = ctx->nonce.c[0];
	block128_f block = ctx->block;
	uint64_t input_len = len;

	if ((flags0 & CCM_AAD_FLAG) == 0) {
		(*block)(ctx->nonce.c, ctx->cmac.c, &(ctx->key));
		ctx->blocks++;
	}

	uint64_t payload = get_ccm_payload(ctx);
	if (payload != input_len)
		return -1;
	ctx->nonce.c[CCM_MAX_BLOCK_INDEX] = 1;

	uint64_t tmp = ((input_len + CCM_MAX_BLOCK_INDEX) >> CCM_BASE_NUM_THREE) | 1;
	if (ctx->blocks > (CCM_MAX_VALUE - tmp))
		return -1;
	ctx->blocks += tmp;

	uint64_t offset = do_ccm_block_encrypt(ctx, inp, out, input_len);

	if ((input_len - offset) != 0)
		do_ccm_not_block_encrypt(ctx, inp + offset, out + offset, input_len - offset);

	reset_ccm_ctx(ctx, flags0);
	return 0;
}

static uint64_t do_ccm_block_decrypt(ccm128_cipher_ctx *ctx,
	const unsigned char *input, unsigned char *output, uint64_t input_len)
{
	uint64_t offset = 0;
	block128_f block = ctx->block;
	ccm128_block flexible_buffer = {0};

	while (input_len >= AES_BLOCK_SIZE) {
#if defined(STRICT_ALIGNMENT)
		ccm128_block temp = {0};
#endif
		(*block)(ctx->nonce.c, flexible_buffer.c, &(ctx->key));
		ctr64_inc(ctx->nonce.c, AES_BLOCK_SIZE);
#if defined(STRICT_ALIGNMENT)
		OPENSSL_memcpy(temp.c, input, AES_BLOCK_SIZE);
		flexible_buffer.u[0] ^= temp.u[0];
		flexible_buffer.u[1] ^= temp.u[1];
		OPENSSL_memcpy(output, flexible_buffer.c, AES_BLOCK_SIZE);
		ctx->cmac.u[0] ^= flexible_buffer.u[0];
		ctx->cmac.u[1] ^= flexible_buffer.u[1];
#else
		((uint64_t *)(output))[0] = flexible_buffer.u[0] ^ ((uint64_t *)(input))[0];
		((uint64_t *)(output))[1] = flexible_buffer.u[1] ^ ((uint64_t *)(input))[1];
		ctx->cmac.u[0] ^= ((uint64_t *)(output))[0];
		ctx->cmac.u[1] ^= ((uint64_t *)(output))[1];
#endif
		(*block)(ctx->cmac.c, ctx->cmac.c, &(ctx->key));

		input += AES_BLOCK_SIZE;
		output += AES_BLOCK_SIZE;
		input_len -= AES_BLOCK_SIZE;
		offset += AES_BLOCK_SIZE;
	}
	return offset;
}

static void do_ccm_not_block_decrypt(ccm128_cipher_ctx *ctx,
	const unsigned char *input, unsigned char *output, uint64_t input_len)
{
	unsigned int index = 0;
	block128_f block = ctx->block;
	ccm128_block flexible_buffer = {0};

	(*block)(ctx->nonce.c, flexible_buffer.c, &(ctx->key));
	for (; index < input_len; ++index) {
		output[index] = flexible_buffer.c[index] ^ input[index];
		ctx->cmac.c[index] ^= output[index];
	}
	(*block)(ctx->cmac.c, ctx->cmac.c, &(ctx->key));
}

#define CCM_INVALID_DECRYPT_PARAM(ctx, inp, out) \
	(((ctx) == NULL) || ((ctx)->block == NULL) || ((inp) == NULL) || ((out) == NULL))

int crypto_ccm128_decrypt2(ccm128_cipher_ctx *ctx, const unsigned char *inp, unsigned char *out, size_t len)
{
	if (CCM_INVALID_DECRYPT_PARAM(ctx, inp, out))
		return -1;

	unsigned char flags0 = ctx->nonce.c[0];
	block128_f block = ctx->block;
	uint64_t input_len = len;

	if ((flags0 & CCM_AAD_FLAG) == 0)
		(*block)(ctx->nonce.c, ctx->cmac.c, &(ctx->key));

	uint64_t payload = get_ccm_payload(ctx);
	if (payload != input_len)
		return -1;
	ctx->nonce.c[CCM_MAX_BLOCK_INDEX] = 1;

	uint64_t offset = do_ccm_block_decrypt(ctx, inp, out, input_len);

	if ((input_len - offset) != 0)
		do_ccm_not_block_decrypt(ctx, inp + offset, out + offset, input_len - offset);

	reset_ccm_ctx(ctx, flags0);
	return 0;
}

#define ONE_BYTE_MASK (0xff)
static void ctr64_add(unsigned char *counter, unsigned int len, size_t inc)
{
	if (len != AES_BLOCK_SIZE)
		return;
	size_t loop = LOOP_VALUE;
	size_t tmp = 0;
	counter += SHIFT_ONE_BYTES;

	do {
		tmp += counter[--loop] + (inc & ONE_BYTE_MASK);
		counter[loop] = (unsigned char)tmp;
		tmp >>= SHIFT_ONE_BYTES;
		inc >>= SHIFT_ONE_BYTES;
	} while ((loop != 0) && ((inc != 0) || (tmp != 0)));
}

#define DO_CCM64_BLOCK_CRYPTO(ctx, inp, out, blocks, key, len, stream) do { \
	(*(stream))((inp), (out), (blocks), (key), (ctx)->nonce.c, (ctx)->cmac.c); \
	(blocks) *= AES_BLOCK_SIZE; \
	(inp) += (blocks); \
	(out) += (blocks); \
	(len) -= (blocks); \
	if (len != 0) \
		ctr64_add((ctx)->nonce.c, AES_BLOCK_SIZE, (blocks) / AES_BLOCK_SIZE); \
} while (0)

int crypto_ccm128_encrypt_ccm64(ccm128_cipher_ctx *ctx,
	const unsigned char *inp, unsigned char *out,
	size_t len, ccm128_f stream)
{
	if (CCM_INVALID_ENCRYPT_PARAM(ctx, inp, out, len))
		return -1;

	unsigned char flags0 = ctx->nonce.c[0];
	block128_f block = ctx->block;

	if ((flags0 & CCM_AAD_FLAG) == 0) {
		(*block)(ctx->nonce.c, ctx->cmac.c, &(ctx->key));
		ctx->blocks++;
	}

	uint64_t payload = get_ccm_payload(ctx);
	if (payload != len)
		return -1;
	ctx->nonce.c[CCM_MAX_BLOCK_INDEX] = 1;

	uint64_t tmp = ((len + CCM_MAX_BLOCK_INDEX) >> CCM_BASE_NUM_THREE) | 1;
	if (ctx->blocks > (CCM_MAX_VALUE - tmp))
		return -1;
	ctx->blocks += tmp;

	uint64_t blocks = len / AES_BLOCK_SIZE;
	if (blocks != 0) {
		if (stream == NULL)
			return -1;
		DO_CCM64_BLOCK_CRYPTO(ctx, inp, out, blocks, &(ctx->key), len, stream);
	}

	if (len != 0)
		do_ccm_not_block_encrypt(ctx, inp, out, len);

	reset_ccm_ctx(ctx, flags0);

	return 0;
}

int crypto_ccm128_decrypt_ccm64(ccm128_cipher_ctx *ctx,
	const unsigned char *inp, unsigned char *out,
	size_t len, ccm128_f stream)
{
	if (CCM_INVALID_DECRYPT_PARAM(ctx, inp, out))
		return -1;

	unsigned char flags0 = ctx->nonce.c[0];
	block128_f block = ctx->block;

	if ((flags0 & CCM_AAD_FLAG) == 0)
		(*block)(ctx->nonce.c, ctx->cmac.c, &(ctx->key));

	uint64_t payload = get_ccm_payload(ctx);
	if (payload != len)
		return -1;
	ctx->nonce.c[CCM_MAX_BLOCK_INDEX] = 1;

	uint64_t blocks = len / AES_BLOCK_SIZE;
	if (blocks != 0) {
		if (stream == NULL)
			return -1;
		DO_CCM64_BLOCK_CRYPTO(ctx, inp, out, blocks, &(ctx->key), len, stream);
	}

	if (len != 0)
		do_ccm_not_block_decrypt(ctx, inp, out, len);

	reset_ccm_ctx(ctx, flags0);

	return 0;
}

size_t crypto_ccm128_tag(const ccm128_cipher_ctx *ctx, unsigned char *tag, size_t len)
{
	if ((ctx == NULL) || (tag == NULL))
		return 0;

	size_t tag_len = ((ctx->nonce.c[0] >> CCM_BASE_NUM_THREE) & CCM_LOW_THREE_MASK);

	tag_len *= CCM_BASE_NUM_TWO;
	tag_len += CCM_BASE_NUM_TWO;
	if (len < tag_len)
		return 0;

	OPENSSL_memcpy(tag, ctx->cmac.c, tag_len);
	return tag_len;
}
