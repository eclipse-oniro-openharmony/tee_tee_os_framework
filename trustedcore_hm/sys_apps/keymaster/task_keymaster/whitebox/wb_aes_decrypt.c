/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
 * Description: aes decrypt whitebox
 * Create: 2013-01-17
 */
#include"wb_aes_decrypt.h"
#include"wb_const.h"
#include"table2.h"
#include"securec.h"
#include "tee_log.h"

#define TB2 g_table2

static void transform(const uint8_t *input, uint16_t *array, int size, uint8_t s)
{
    int i;
    uint16_t t16;
    for (i = 0; i < size; i++) {
        t16 = input[i];
        array[i] = rotl(t16, IN_ROT1 * i, s) ^ rotl(t16, IN_ROT2 * i, s)
            ^ rotl(t16, IN_ROT3 * i, s) ^ ((uint16_t)(i * IN_CONST));
    }
}

#define DECRYPT_ZERO   0
#define DECRYPT_ONE    1
#define DECRYPT_TWO    2
#define DECRYPT_THREE  3
#define DECRYPT_FOUR   4
#define DECRYPT_FIVE   5
#define DECRYPT_SIX    6
#define DECRYPT_SEVEN  7
#define DECRYPT_EIGHT  8
#define DECRYPT_NINE   9
#define DECRYPT_TEN    10
#define DECRYPT_ELEVEN 11
#define DECRYPT_TWELVE 12
#define DECRYPT_THIRT  13

static void wb_aes_decrypt_by_tab2(uint16_t temp[AES_BLOCK_SIZE], uint8_t s)
{
#if WB_EXP_SIZE2 == 8
    uint32_t x0, x1, x2, x3, y0, y1, y2, y3;
    get_uint32_le(x0, temp, DECRYPT_ZERO);
    get_uint32_le(x1, temp, DECRYPT_FOUR);
    get_uint32_le(x2, temp, DECRYPT_EIGHT);
    get_uint32_le(x3, temp, DECRYPT_TWELVE);
#else
    uint64_t x0, x1, x2, x3, y0, y1, y2, y3;
    get_uint64_le(x0, temp, DECRYPT_ZERO);
    get_uint64_le(x1, temp, DECRYPT_FOUR);
    get_uint64_le(x2, temp, DECRYPT_EIGHT);
    get_uint64_le(x3, temp, DECRYPT_TWELVE);
#endif

    /* decryption */
    wb_aes_bround(TB2, y, x, DECRYPT_ZERO);
    wb_aes_bround(TB2, x, y, DECRYPT_ONE);
    wb_aes_bround(TB2, y, x, DECRYPT_TWO);
    wb_aes_bround(TB2, x, y, DECRYPT_THREE);
    wb_aes_bround(TB2, y, x, DECRYPT_FOUR);
    wb_aes_bround(TB2, x, y, DECRYPT_FIVE);
    wb_aes_bround(TB2, y, x, DECRYPT_SIX);
    wb_aes_bround(TB2, x, y, DECRYPT_SEVEN);
    wb_aes_bround(TB2, y, x, DECRYPT_EIGHT);
    wb_aes_bround(TB2, x, y, DECRYPT_NINE);
#if WB_NR2 > 10
    wb_aes_bround(TB2, y, x, DECRYPT_TEN);
    wb_aes_bround(TB2, x, y, DECRYPT_ELEVEN);
#endif
#if WB_NR2 > 12
    wb_aes_bround(TB2, y, x, DECRYPT_TWELVE);
    wb_aes_bround(TB2, x, y, DECRYPT_THIRT);
#endif
    /* output transformation */
#if WB_EXP_SIZE2 == 8
    put_uint32_le(x0, temp, DECRYPT_ZERO);
    put_uint32_le(x1, temp, DECRYPT_FOUR);
    put_uint32_le(x2, temp, DECRYPT_EIGHT);
    put_uint32_le(x3, temp, DECRYPT_TWELVE);
#else
    put_uint64_le(x0, temp, DECRYPT_ZERO);
    put_uint64_le(x1, temp, DECRYPT_EIGHT);
    put_uint64_le(x2, temp, DECRYPT_EIGHT);
    put_uint64_le(x3, temp, DECRYPT_TWELVE);
#endif
}

void wb_aes_decrypt(const uint8_t *input, uint8_t *output)
{
    bool condition_check = (input == NULL || output == NULL);
    if (condition_check) {
        tloge("input or output is null!\n");
        return;
    }
    int i;
    const uint8_t s = WB_EXP_SIZE2;
    uint16_t mask = (1 << s) - 1;
    uint16_t t16;

    /* input transformation */
    uint16_t temp[AES_BLOCK_SIZE] = { 0 };
    transform(input, temp, AES_BLOCK_SIZE, s);

    /* put transformed ciphertext into Xs */
    wb_aes_decrypt_by_tab2(temp, s);

    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        t16 = temp[i] & mask;
        output[i] = rotl(t16, OUT_ROT1 * i, s) ^ rotl(t16, OUT_ROT2 * i, s) ^
            rotl(t16, OUT_ROT3 * i, s) ^ ((uint16_t)(i * OUT_CONST));
    }
}

static int32_t check_last_block(const uint8_t *temp, uint32_t temp_buf_len, uint32_t in_len, uint8_t *output,
    uint32_t *out_len)
{
    if (temp == NULL || output == NULL || out_len == NULL) {
        tloge("null pointer\n");
        return -1;
    }
    if (temp_buf_len != AES_BLOCK_SIZE) {
        tloge("invalid block size\n");
        return -1;
    }
    /* check pkcs7 padding */
    uint8_t pad = temp[AES_BLOCK_SIZE - 1];
    if (pad > AES_BLOCK_SIZE) {
        tloge("padding invalid\n");
        return -1;
    }
    uint32_t j;
    for (j = 1; j < pad; ++j) {
        if (temp[(AES_BLOCK_SIZE - 1) - j] != pad) {
            tloge("padding error\n");
            return -1;
        }
    }
    if (in_len < pad) {
        tloge("invalid in_len\n");
        return -1;
    }
    *out_len = in_len - pad;
    if (AES_BLOCK_SIZE - pad != 0 && memcpy_s(output, AES_BLOCK_SIZE - pad, temp, AES_BLOCK_SIZE - pad) != EOK)
        return -1;

    return 0;
}

int wb_aes_decrypt_cbc(const uint8_t *iv, const uint8_t *input, uint32_t in_len, uint8_t *output, uint32_t *out_len)
{
    bool condition_check = ((iv == NULL) || (input == NULL) || (output == NULL) || (out_len == NULL) || (in_len == 0) ||
        ((in_len % AES_BLOCK_SIZE) != 0));
    if (condition_check == true) {
        tloge("data or input or output or out_len is null or in_len is null or error\n");
        return -1;
    }
    uint32_t i;
    uint8_t buf[AES_BLOCK_SIZE] = {0};
    uint8_t temp[AES_BLOCK_SIZE] = {0};
    /* cbc-decryption */
    if (memcpy_s(buf, sizeof(buf), iv, AES_BLOCK_SIZE) != EOK)
        return -1;

    for (i = 0; i < in_len / AES_BLOCK_SIZE; ++i) {
        if (i == (in_len / AES_BLOCK_SIZE - 1)) {
            wb_aes_decrypt(input, temp);
            xor_block(temp, buf, AES_BLOCK_SIZE);
            /* check pkcs7 padding */
            if (check_last_block(temp, AES_BLOCK_SIZE, in_len, output, out_len) != 0) {
                tloge("check last block failed\n");
                return -1;
            }
        } else {
            wb_aes_decrypt(input, output);
            xor_block(output, buf, AES_BLOCK_SIZE);
        }
        if (memcpy_s(buf, sizeof(buf), input, AES_BLOCK_SIZE) != EOK)
            return -1;

        input += AES_BLOCK_SIZE;
        output += AES_BLOCK_SIZE;
    }
    return 0;
}
