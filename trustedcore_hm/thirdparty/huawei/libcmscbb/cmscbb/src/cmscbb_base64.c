/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../cmscbb_common/cmscbb_base64.h"
#include "../cmscbb_common/cmscbb_common.h"

#if CMSCBB_SUPPORT_PEM
#define BASE64_MAP_SIZE 128
/* map of radix64 and byte */
static const CVB_BYTE g_cvbBase64DecMap[BASE64_MAP_SIZE] = {
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F,  62, 0x7F, 0x7F, 0x7F,  63,  52,  53,
    54,   55,  56,  57,  58,  59,  60,  61, 0x7F, 0x7F,
    0x7F,  64, 0x7F, 0x7F, 0x7F,   0,   1,   2,   3,   4,
    5,     6,   7,   8,   9,  10,  11,  12,  13,  14,
    15,   16,  17,  18,  19,  20,  21,  22,  23,  24,
    25,  0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,  26,  27,  28,
    29,   30,  31,  32,  33,  34,  35,  36,  37,  38,
    39,   40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,   50,  51, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F
};

#define MAX_ASCII_VALUE 127
#define MAX_RADIX64_VALUE 64   /* max value of base64 */
#define PAIR_LENGTH_OF_ASCII 4
#define PAIR_LENGTH_OF_BYTE 3
#define CRCL_SIZE 2 /* /r&/n */
#define CL_SIZE 1 /* /n Only */
#define MAX_EQUAL_SIGN_COUNT 2
#define MASK_CODE_LOW_R64 0x3F
#define ASCII_BITS_COUNT 6

/*
 * Prototype    : InternalIsEndOfLine
 * Description  : check if read point reach the end of line.
 * Params
 *   [IN] encoded: encode CHAR list
 *   [IN] nEncoded: the length of encode
 *   [IN] i: position
 * Return Value : CVB_BOOL
 *   Date              Author     Modification
 *   2015/11/10 19:31  t00307193  Create
 */
CVB_STATIC CVB_BOOL InternalIsEndOfLine(const CVB_CHAR* encoded, CVB_UINT32 nEncoded, CVB_INT i)
{
    if (((CVB_INT)nEncoded - i) >= CRCL_SIZE && encoded[i] == '\r' && encoded[i + 1] == '\n') {
        return CVB_TRUE;
    }

    if (((CVB_INT)nEncoded - i) >= CL_SIZE && encoded[i] == '\n') {
        return CVB_TRUE;
    }

    return CVB_FALSE;
}

/*
 * Prototype    : InternalB64GetDecLen
 * Description  : calculate the length after base64 decoded.
 * Params
 *   [IN] encoded: base64 encode char list
 *   [IN] nEncoded: length of encode
 *   [IN] nValid: valid length
 *   [IN] nLen: output length
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 19:33  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalB64GetDecLen(const CVB_CHAR* encoded, CVB_UINT32 nEncoded, CVB_INT* nValid, CVB_INT *nLen)
{
    CVB_INT i = 0;
    CVB_INT n = 0;
    CVB_UINT32 j = 0;   /* count of "=" */
    CVB_UINT32 x = 0;   /* count of " " */

    /* check for validity and get output length */
    while (i < (CVB_INT)nEncoded) {
        x = 0;  /* Skip spaces before checking for EOL */
        while (i < (CVB_INT)nEncoded && encoded[i] == ' ') {
            ++i;
            ++x;
        }

        /* Spaces at end of buffer are OK */
        if ((CVB_INT)nEncoded == i) {
            break;
        }

        /* Spaces at end of line are OK */
        if (InternalIsEndOfLine(encoded, nEncoded, i) == CVB_TRUE) {
            ++i;
            continue;
        }

        /* Space inside a line is an error */
        if (x != 0) {
            return CMSCBB_ERR_SYS_UTIL_B64_DEC;
        }

        if (encoded[i] == '=' && ++j > MAX_EQUAL_SIGN_COUNT) {
            return CMSCBB_ERR_SYS_UTIL_B64_DEC;
        }

        if ((CVB_BYTE)encoded[i] > MAX_ASCII_VALUE) {
            return CMSCBB_ERR_SYS_UTIL_B64_DEC;
        }

        if (g_cvbBase64DecMap[(CVB_INT)encoded[i]] < MAX_RADIX64_VALUE && j != 0) {
            return CMSCBB_ERR_SYS_UTIL_B64_DEC;
        }
        ++i;
        ++n;
    }

    if (0 == n) {
        return CMSCBB_ERR_SYS_UTIL_B64_DEC;
    }

    n = (CVB_INT)(((CVB_UINT)((n * ASCII_BITS_COUNT) + (ASCII_BITS_COUNT + 1))) >> PAIR_LENGTH_OF_BYTE);
    n -= (CVB_INT)j;

    *nLen = n;
    *nValid = i;
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalB64DoDec
 * Description  : decode base64
 * Params
 *   [IN] encoded:encode by base64
 *   [IN] nValid: valid length
 *   [IN] decoded: decode from base64
 * Return Value : CVB_UINT32
 *   Date              Author     Modification
 *   2015/11/10 19:46  t00307193  Create
 */
#define BIT_COUNT_OF_2_BYTES 16
#define BYTE_UNIT_IDX1 1
#define BYTE_UNIT_IDX2 2
CVB_STATIC CVB_UINT32 InternalB64DoDec(const CVB_CHAR* encoded, CVB_INT nValid, CVB_BYTE* decoded)
{
    CVB_INT n;
    CVB_UINT32 j;
    CVB_UINT32 x;
    CVB_BYTE* d = decoded;
    const CVB_CHAR* s = encoded;

    for (j = PAIR_LENGTH_OF_BYTE, n = 0, x = 0; nValid > 0; --nValid, ++s) {
        if (*s == '\r' || *s == '\n' || *s == ' ') {
            continue;
        }

        j -= (CVB_UINT32)(MAX_RADIX64_VALUE == g_cvbBase64DecMap[(CVB_INT)(*s)]);
        x = (x << ASCII_BITS_COUNT) | (g_cvbBase64DecMap[(CVB_INT)(*s)] & MASK_CODE_LOW_R64);

        if (++n == PAIR_LENGTH_OF_ASCII) {
            n = 0;
            if (j > 0) {
                *d++ = (CVB_BYTE)(x >> BIT_COUNT_OF_2_BYTES);
            }
            if (j > BYTE_UNIT_IDX1) {
                *d++ = (CVB_BYTE)(x >> BIT_COUNT_OF_BYTE);
            }
            if (j > BYTE_UNIT_IDX2) {
                *d++ = (CVB_BYTE)(x);
            }
        }
    }
    return (CVB_UINT32)(d - decoded);
}

CMSCBB_ERROR_CODE CmscbbBase64Decode(const CVB_CHAR* encoded, CVB_UINT32 nEncoded, CVB_BYTE* decoded, CVB_UINT32* nDecoded)
{
    CMSCBB_ERROR_CODE ret;
    CVB_INT nDec = 0;
    CVB_INT nValid = 0;

    if (encoded == CVB_NULL || nEncoded == 0 || nDecoded == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    ret = InternalB64GetDecLen(encoded, nEncoded, &nValid, &nDec);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    if (decoded == CVB_NULL || (CVB_INT)*nDecoded < nDec) {
        /* only require output length */
        *nDecoded = (CVB_UINT32)nDec;
        return CVB_SUCCESS;
    }

    *nDecoded = InternalB64DoDec(encoded, nValid, decoded);
    return CVB_SUCCESS;
}
#endif
