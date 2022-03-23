/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: cipher common
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "drv_osal_lib.h"
#include "crys_cipher_common.h"
#include "crys_rsa_error.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "hi_tee_drv_klad.h"

#define CRYS_BUFF_SIZE_16 16
#define BYTE_BIT_WIDTH 8
#define SHIFT_3 3
#define SHIFT_4 4
#define SHIFT_8 8
#define SHIFT_16 16
#define SHIFT_24 24
#define OFFSET_0 0
#define OFFSET_1 1
#define OFFSET_2 2
#define OFFSET_3 3
#define OFFSET_4 4

hi_u32 crys_get_bit_num(hi_u8 *bits, hi_u32 num_len)
{
    static const hi_s8 bit_map[16] = {0, 1, 2, 2, 3, 3, 3, 3, /* 16 0 1 2 3 3 3 3 3 */
                                      4, 4, 4, 4, 4, 4, 4, 4 }; /* 4 4 4 4 4 4 4 4 */
    hi_u32 i;
    hi_u32 num;

    for (i = 0; i < num_len; i++) {
        num = bit_map[(bits[i] & 0xF0) >> SHIFT_4];
        if (num > 0) {
            return (num_len - i - 1) * BYTE_BIT_WIDTH + num + OFFSET_4;
        }
        num = bit_map[bits[i] & 0xF];
        if (num > 0) {
            return (num_len - i - 1) * BYTE_BIT_WIDTH + num;
        }
    }
    return 0;
}

#define CIL ((int)sizeof(int)) /* chars in limb */

hi_s32 crys_bn2bin(const hi_u32 *bn, hi_u8 *bin, hi_s32 len)
{
    hi_s32 i, n;
    hi_u32 j;
    hi_s32 ret;

    n = len;

    ret = memset_s(bin, len, 0, len);
    if (ret != 0) {
        return ret;
    }

    for (i = len - 1, j = 0; n > 0; i--, j++, n--) {
        bin[i] = (unsigned char)(bn[j / CIL] >> ((j % CIL) << 3)); /* left shift 3 */
    }

    return (0);
}

hi_s32 crys_bin2bn(hi_u32 *bn, const hi_u8 *bin, hi_s32 len)
{
    hi_s32 i, n;
    hi_u32 j;
    hi_s32 ret;

    ret = memset_s(bn, len, 0, len);
    if (ret != 0) {
        return ret;
    }

    for (n = 0; n < len; n++)
        if (bin[n] != 0) {
            break;
        }

    for (i = len - 1, j = 0; i >= n; i--, j++) {
        bn[j / CIL] |= ((unsigned int)bin[i]) << ((j % CIL) << 3); /* left shift 3 */
    }

    return (0);
}

hi_s32 crys_get_random_number(hi_u8 *random, hi_u32 size)
{
    hi_s32 ret;
    hi_u32 i = 0;
    hi_u32 rand = 0;

    if (random == DX_NULL) {
        return HI_FAILURE;
    }

    ret = memset_s(random, size, 0, size);
    if (ret != 0) {
        return ret;
    }

    for (i = 0; i < size; i += 4) { /* step is 4 */
        ret = kapi_trng_get_random(&rand, -1);
        if (ret != HI_SUCCESS) {
            hi_log_error("Get random number failed, ret = %x\n", ret);
            return HI_FAILURE;
        }
        random[i + OFFSET_3] = (hi_u8)(rand >> SHIFT_24) & 0xFF;
        random[i + OFFSET_2] = (hi_u8)(rand >> SHIFT_16) & 0xFF;
        random[i + OFFSET_1] = (hi_u8)(rand >> SHIFT_8) & 0xFF;
        random[i + OFFSET_0] = (hi_u8)(rand) & 0xFF;
    }

    return ret;
}

hi_s32 crys_ras_call_mul(hi_u8 *x_in, hi_u8 *a_in, hi_u8 *b_in, hi_u32 x_size, hi_u32 a_size, hi_u32 b_size)
{
    mbedtls_mpi x, a, b;
    hi_s32 ret;

    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);

    ret = mbedtls_mpi_read_binary(&a, a_in, a_size);
    if (ret != HI_SUCCESS) {
        hi_log_error("mpi read P error, ret = 0x%x\n", ret);
        hi_log_print_func_err(mbedtls_mpi_read_binary, ret);
        return ret;
    }
    ret = mbedtls_mpi_read_binary(&b, b_in, b_size);
    if (ret != HI_SUCCESS) {
        hi_log_error("mpi read P error, ret = 0x%x\n", ret);
        hi_log_print_func_err(mbedtls_mpi_read_binary, ret);
        mbedtls_mpi_free(&a);
        return ret;
    }

    ret = mbedtls_mpi_mul_mpi(&x, &a, &b);
    if (ret != HI_SUCCESS) {
        hi_log_error("mpi mul error!, ret = 0x%x\n", ret);
        hi_log_print_func_err(mbedtls_mpi_mul_mpi, ret);
        mbedtls_mpi_free(&a);
        mbedtls_mpi_free(&b);
        return ret;
    }

    ret = mbedtls_mpi_write_binary(&x, x_in, x_size);
    if (ret != HI_SUCCESS) {
        hi_log_error("mpi write, ret = 0x%x\n", ret);
        hi_log_print_func_err(mbedtls_mpi_write_binary, ret);
        mbedtls_mpi_free(&x);
        mbedtls_mpi_free(&a);
        mbedtls_mpi_free(&b);
        return ret;
    }

    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&b);

    return ret;
}

/* http://www.secg.org/sec2-v2.pdf */
#define SECP192K1_P  "\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xEE\x37"
#define SECP192K1_A  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define SECP192K1_B  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"
#define SECP192K1_GX "\x00\x00\x00\x00\x00\x00\x00\x00\xDB\x4F\xF1\x0E\xC0\x57\xE9\xAE" \
                     "\x26\xB0\x7D\x02\x80\xB7\xF4\x34\x1D\xA5\xD1\xB1\xEA\xE0\x6C\x7D"
#define SECP192K1_GY "\x00\x00\x00\x00\x00\x00\x00\x00\x9B\x2F\x2F\x6D\x9C\x56\x28\xA7" \
                     "\x84\x41\x63\xD0\x15\xBE\x86\x34\x40\x82\xAA\x88\xD9\x5E\x2F\x9D"
#define SECP192K1_N  "\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFE\x26\xF2\xFC\x17\x0F\x69\x46\x6A\x74\xDE\xFD\x8D"
#define SECP192K1_SIZE                                                               32
#define SECP192K1_PAD_SIZE                                                           8

#define SECP192R1_P  "\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
#define SECP192R1_A  "\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC"
#define SECP192R1_B  "\x00\x00\x00\x00\x00\x00\x00\x00\x64\x21\x05\x19\xE5\x9C\x80\xE7" \
                     "\x0F\xA7\xE9\xAB\x72\x24\x30\x49\xFE\xB8\xDE\xEC\xC1\x46\xB9\xB1"
#define SECP192R1_GX "\x00\x00\x00\x00\x00\x00\x00\x00\x18\x8D\xA8\x0E\xB0\x30\x90\xF6" \
                     "\x7C\xBF\x20\xEB\x43\xA1\x88\x00\xF4\xFF\x0A\xFD\x82\xFF\x10\x12"
#define SECP192R1_GY "\x00\x00\x00\x00\x00\x00\x00\x00\x07\x19\x2B\x95\xFF\xC8\xDA\x78" \
                     "\x63\x10\x11\xED\x6B\x24\xCD\xD5\x73\xF9\x77\xA1\x1E\x79\x48\x11"
#define SECP192R1_N  "\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\x99\xDE\xF8\x36\x14\x6B\xC9\xB1\xB4\xD2\x28\x31"
#define SECP192R1_SIZE                                                               32
#define SECP192R1_PAD_SIZE                                                           8

#define SECP224K1_P  "\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xE5\x6D"
#define SECP224K1_A  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define SECP224K1_B  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05"
#define SECP224K1_GX "\x00\x00\x00\x00\xA1\x45\x5B\x33\x4D\xF0\x99\xDF\x30\xFC\x28\xA1" \
                     "\x69\xA4\x67\xE9\xE4\x70\x75\xA9\x0F\x7E\x65\x0E\xB6\xB7\xA4\x5C"
#define SECP224K1_GY "\x00\x00\x00\x00\x7E\x08\x9F\xED\x7F\xBA\x34\x42\x82\xCA\xFB\xD6" \
                     "\xF7\xE3\x19\xF7\xC0\xB0\xBD\x59\xE2\xCA\x4B\xDB\x55\x6D\x61\xA5"
#define SECP224K1_N  "\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x01\xDC\xE8\xD2\xEC\x61\x84\xCA\xF0\xA9\x71\x76\x9F\xB1\xF7"
#define SECP224K1_SIZE                                                               32
#define SECP224K1_PAD_SIZE                                                           4

#define SECP224R1_P  "\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
#define SECP224R1_A  "\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE"
#define SECP224R1_B  "\x00\x00\x00\x00\xB4\x05\x0A\x85\x0C\x04\xB3\xAB\xF5\x41\x32\x56" \
                     "\x50\x44\xB0\xB7\xD7\xBF\xD8\xBA\x27\x0B\x39\x43\x23\x55\xFF\xB4"
#define SECP224R1_GX "\x00\x00\x00\x00\xB7\x0E\x0C\xBD\x6B\xB4\xBF\x7F\x32\x13\x90\xB9" \
                     "\x4A\x03\xC1\xD3\x56\xC2\x11\x22\x34\x32\x80\xD6\x11\x5C\x1D\x21"
#define SECP224R1_GY "\x00\x00\x00\x00\xBD\x37\x63\x88\xB5\xF7\x23\xFB\x4C\x22\xDF\xE6" \
                     "\xCD\x43\x75\xA0\x5A\x07\x47\x64\x44\xD5\x81\x99\x85\x00\x7E\x34"
#define SECP224R1_N  "\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\x16\xA2\xE0\xB8\xF0\x3E\x13\xDD\x29\x45\x5C\x5C\x2A\x3D"
#define SECP224R1_SIZE                                                              32
#define SECP224R1_PAD_SIZE                                                          4

#define SECP256K1_P  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFC\x2F"
#define SECP256K1_A  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define SECP256K1_B  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07"
#define SECP256K1_GX "\x79\xBE\x66\x7E\xF9\xDC\xBB\xAC\x55\xA0\x62\x95\xCE\x87\x0B\x07" \
                     "\x02\x9B\xFC\xDB\x2D\xCE\x28\xD9\x59\xF2\x81\x5B\x16\xF8\x17\x98"
#define SECP256K1_GY "\x48\x3A\xDA\x77\x26\xA3\xC4\x65\x5D\xA4\xFB\xFC\x0E\x11\x08\xA8" \
                     "\xFD\x17\xB4\x48\xA6\x85\x54\x19\x9C\x47\xD0\x8F\xFB\x10\xD4\xB8"
#define SECP256K1_N  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE" \
                     "\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41"
#define SECP256K1_SIZE                                                             32
#define SECP256K1_PAD_SIZE                                                         0

#define SECP256R1_P  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFC\x2F"
#define SECP256R1_A  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define SECP256R1_B  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07"
#define SECP256R1_GX "\x79\xBE\x66\x7E\xF9\xDC\xBB\xAC\x55\xA0\x62\x95\xCE\x87\x0B\x07" \
                     "\x02\x9B\xFC\xDB\x2D\xCE\x28\xD9\x59\xF2\x81\x5B\x16\xF8\x17\x98"
#define SECP256R1_GY "\x48\x3A\xDA\x77\x26\xA3\xC4\x65\x5D\xA4\xFB\xFC\x0E\x11\x08\xA8" \
                     "\xFD\x17\xB4\x48\xA6\x85\x54\x19\x9C\x47\xD0\x8F\xFB\x10\xD4\xB8"
#define SECP256R1_N  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE" \
                     "\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41"
#define SECP256R1_SIZE                                                             32
#define SECP256R1_PAD_SIZE                                                         0

#define SECP384R1_P  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE" \
                     "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF"
#define SECP384R1_A  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE" \
                     "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFC"
#define SECP384R1_B  "\xB3\x31\x2F\xA7\xE2\x3E\xE7\xE4\x98\x8E\x05\x6B\xE3\xF8\x2D\x19" \
                     "\x18\x1D\x9C\x6E\xFE\x81\x41\x12\x03\x14\x08\x8F\x50\x13\x87\x5A" \
                     "\xC6\x56\x39\x8D\x8A\x2E\xD1\x9D\x2A\x85\xC8\xED\xD3\xEC\x2A\xEF"
#define SECP384R1_GX "\xAA\x87\xCA\x22\xBE\x8B\x05\x37\x8E\xB1\xC7\x1E\xF3\x20\xAD\x74" \
                     "\x6E\x1D\x3B\x62\x8B\xA7\x9B\x98\x59\xF7\x41\xE0\x82\x54\x2A\x38" \
                     "\x55\x02\xF2\x5D\xBF\x55\x29\x6C\x3A\x54\x5E\x38\x72\x76\x0A\xB7"
#define SECP384R1_GY "\x36\x17\xDE\x4A\x96\x26\x2C\x6F\x5D\x9E\x98\xBF\x92\x92\xDC\x29" \
                     "\xF8\xF4\x1D\xBD\x28\x9A\x14\x7C\xE9\xDA\x31\x13\xB5\xF0\xB8\xC0" \
                     "\x0A\x60\xB1\xCE\x1D\x7E\x81\x9D\x7A\x43\x1D\x7C\x90\xEA\x0E\x5F"
#define SECP384R1_N  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC7\x63\x4D\x81\xF4\x37\x2D\xDF" \
                     "\x58\x1A\x0D\xB2\x48\xB0\xA7\x7A\xEC\xEC\x19\x6A\xCC\xC5\x29\x73"
#define SECP384R1_SIZE                                                            48
#define SECP384R1_PAD_SIZE                                                        0

#define SECP521R1_P  "\x00\x00\x00\x00\x00\x00\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
#define SECP521R1_A  "\x00\x00\x00\x00\x00\x00\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC"
#define SECP521R1_B  "\x00\x00\x00\x00\x00\x00\x00\x51\x95\x3E\xB9\x61\x8E\x1C\x9A\x1F"  \
                     "\x92\x9A\x21\xA0\xB6\x85\x40\xEE\xA2\xDA\x72\x5B\x99\xB3\x15\xF3"  \
                     "\xB8\xB4\x89\x91\x8E\xF1\x09\xE1\x56\x19\x39\x51\xEC\x7E\x93\x7B"  \
                     "\x16\x52\xC0\xBD\x3B\xB1\xBF\x07\x35\x73\xDF\x88\x3D\x2C\x34\xF1"  \
                     "\xEF\x45\x1F\xD4\x6B\x50\x3F\x00"
#define SECP521R1_GX "\x00\x00\x00\x00\x00\x00\x00\xC6\x85\x8E\x06\xB7\x04\x04\xE9\xCD"  \
                     "\x9E\x3E\xCB\x66\x23\x95\xB4\x42\x9C\x64\x81\x39\x05\x3F\xB5\x21" \
                     "\xF8\x28\xAF\x60\x6B\x4D\x3D\xBA\xA1\x4B\x5E\x77\xEF\xE7\x59\x28" \
                     "\xFE\x1D\xC1\x27\xA2\xFF\xA8\xDE\x33\x48\xB3\xC1\x85\x6A\x42\x9B" \
                     "\xF9\x7E\x7E\x31\xC2\xE5\xBD\x66"
#define SECP521R1_GY "\x00\x00\x00\x00\x00\x00\x01\x18\x39\x29\x6A\x78\x9A\x3B\xC0\x04"  \
                     "\x5C\x8A\x5F\xB4\x2C\x7D\x1B\xD9\x98\xF5\x44\x49\x57\x9B\x44\x68"  \
                     "\x17\xAF\xBD\x17\x27\x3E\x66\x2C\x97\xEE\x72\x99\x5E\xF4\x26\x40"  \
                     "\xC5\x50\xB9\x01\x3F\xAD\x07\x61\x35\x3C\x70\x86\xA2\x72\xC2\x40"  \
                     "\x88\xBE\x94\x76\x9F\xD1\x66\x50"
#define SECP521R1_N  "\x00\x00\x00\x00\x00\x00\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  \
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFA\x51\x86\x87\x83\xBF\x2F\x96\x6B"  \
                     "\x7F\xCC\x01\x48\xF7\x09\xA5\xD0\x3B\xB5\xC9\xB8\x89\x9C\x47\xAE"  \
                     "\xBB\x6F\xB7\x1E\x91\x38\x64\x09"
#define SECP521R1_SIZE                                                               72
#define SECP521R1_PAD_SIZE                                                           6

hi_s32 crys_ecp_load_group(CRYS_ECPKI_DomainID_t domain_id, ecc_param_t *ecc_param, hi_u32 *pad_len)
{
    hi_u32 id;

    hi_u32 ecdh_sizes[] =   {SECP192K1_SIZE, SECP192R1_SIZE, SECP224K1_SIZE, SECP224R1_SIZE,
                             SECP256K1_SIZE, SECP256R1_SIZE, SECP384R1_SIZE, SECP521R1_SIZE};
    hi_u32 pad_sizes[]  =   {SECP192K1_PAD_SIZE, SECP192R1_PAD_SIZE, SECP224K1_PAD_SIZE, SECP224R1_PAD_SIZE,
                             SECP256K1_PAD_SIZE, SECP256R1_PAD_SIZE, SECP384R1_PAD_SIZE, SECP521R1_PAD_SIZE};

    const char *ecdh_p[] =  {SECP192K1_P,  SECP192R1_P,  SECP224K1_P,  SECP224R1_P,
                             SECP256K1_P,  SECP256R1_P,  SECP384R1_P,  SECP521R1_P};

    const char *ecdh_a[] =  {SECP192K1_A,  SECP192R1_A,  SECP224K1_A,  SECP224R1_A,
                             SECP256K1_A,  SECP256K1_A,  SECP384R1_A,  SECP521R1_A};

    const char *ecdh_b[] =  {SECP192K1_B,  SECP192R1_B,  SECP224K1_B,  SECP224R1_B,
                             SECP256K1_B,  SECP256R1_B,  SECP384R1_B,  SECP521R1_B};

    const char *ecdh_gx[] = {SECP192K1_GX, SECP192R1_GX, SECP224K1_GX, SECP224R1_GX,
                             SECP256K1_GX, SECP256R1_GX, SECP384R1_GX, SECP521R1_GX};

    const char *ecdh_gy[] = {SECP192K1_GY, SECP192R1_GY, SECP224K1_GY, SECP224R1_GY,
                             SECP256K1_GX, SECP256R1_GY, SECP384R1_GY, SECP521R1_GY};

    const char *ecdh_n[] =  {SECP192K1_N,  SECP192R1_N,  SECP224K1_N,  SECP224R1_N,
                             SECP256K1_GY, SECP256R1_N,  SECP384R1_N,  SECP521R1_N};

    switch (domain_id) {
        case CRYS_ECPKI_DomainID_secp192k1:
        case CRYS_ECPKI_DomainID_secp192r1:
        case CRYS_ECPKI_DomainID_secp224k1:
        case CRYS_ECPKI_DomainID_secp224r1:
        case CRYS_ECPKI_DomainID_secp256k1:
        case CRYS_ECPKI_DomainID_secp256r1:
        case CRYS_ECPKI_DomainID_secp384r1:
        case CRYS_ECPKI_DomainID_secp521r1:
            id = domain_id - CRYS_ECPKI_DomainID_secp192k1;
            ecc_param->p = (hi_u8*)ecdh_p[id];
            ecc_param->a = (hi_u8*)ecdh_a[id];
            ecc_param->b = (hi_u8*)ecdh_b[id];
            ecc_param->gx = (hi_u8*)ecdh_gx[id];
            ecc_param->gy = (hi_u8*)ecdh_gy[id];
            ecc_param->n = (hi_u8*)ecdh_n[id];
            ecc_param->h = 1;
            ecc_param->ksize = ecdh_sizes[id];
            *pad_len = pad_sizes[id];
            break;
        default:
            return CRYS_ECPKI_BUILD_KEY_ILLEGAL_DOMAIN_ID_ERROR;
    }

    return HI_SUCCESS;
}

hi_s32 crys_aes_set_clear_key(hi_handle cipher, const hi_u8 *key, hi_u32 keylen)
{
    hi_s32 ret;
    hi_handle handle_ks = 0;
    klad_clear_cw_param clear_cw = { 0 };

    ret = kapi_symc_get_keyslot(cipher, &handle_ks);
    if (ret != HI_SUCCESS) {
        tloge("hi_tee_cipher_get_key_slot_handle failed\n");
        return ret;
    }

    clear_cw.ks_handle = handle_ks;
    clear_cw.attr.klad_cfg.owner_id = 0;
    clear_cw.attr.klad_cfg.klad_type = HI_KLAD_TYPE_CLEARCW;
    clear_cw.attr.key_cfg.decrypt_support = 1;
    clear_cw.attr.key_cfg.encrypt_support = 1;
    clear_cw.attr.key_cfg.engine = HI_CRYPTO_ENGINE_ALG_RAW_AES;
    clear_cw.attr.key_sec_cfg.key_sec = HI_KLAD_SEC_ENABLE;
    clear_cw.attr.key_sec_cfg.dest_buf_non_sec_support = 1;
    clear_cw.attr.key_sec_cfg.dest_buf_sec_support = 1;
    clear_cw.attr.key_sec_cfg.src_buf_non_sec_support = 1;
    clear_cw.attr.key_sec_cfg.src_buf_sec_support = 1;
    clear_cw.clr_key.key_size = keylen;
    if (memcpy_s(clear_cw.clr_key.key, sizeof(clear_cw.clr_key.key), key, keylen) != EOK) {
        return HI_FAILURE;
    }

    ret = hi_drv_klad_clear_cw(&clear_cw);
    if (ret != HI_SUCCESS) {
        tloge("hi_tee_klad_set_clear_key failed\n");
    }

    return ret;
}



