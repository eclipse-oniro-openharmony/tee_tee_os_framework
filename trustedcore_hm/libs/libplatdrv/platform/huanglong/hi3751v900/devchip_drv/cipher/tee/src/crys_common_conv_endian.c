/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: conv endian
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "crys.h"
#include "crys_common.h"
#include "crys_common_math.h"
#include "crys_common_error.h"
#include "dx_pal_mem.h"

#ifndef DX_OEM_FW

/***********************************************************************/
/**
 * @brief This function converts in place words byffer to bytes buffer with
 *        reversed endianity of output array.
 *
 *        The function can convert:
 *           - big endian bytes array to words array with little endian order
 *             of words and backward.
 *
 *      Note:
 *      1. Endianness of each word in words buffer should be set allways
 *      according to processor used.
 *      2. Implementation is given for both big and little endianness of
 *      processor.
 *
 * @param[in]  buf_ptr - The 32-bits pointer to input/output buffer.
 * @param[in]  sizeWords - The size in words (sizeWords > 0).
 *
 * @return - no return value.
 */
void CRYS_COMMON_InPlaceConvertBytesWordsAndArrayEndianness(
        uint32_t *buf_ptr,
        uint32_t  sizeWords)
{
    uint32_t i, tmp;

    /* Reverse words order and bytes in each word */
    for (i = 0; i < sizeWords / 2; i++) { /* 2 is divider */
#ifndef BIG__ENDIAN
        tmp = CRYS_COMMON_REVERSE32(buf_ptr[i]);
        buf_ptr[i] = CRYS_COMMON_REVERSE32(buf_ptr[sizeWords - i - 1]);
#else
        tmp = buf_ptr[i];
        buf_ptr[i] = buf_ptr[sizeWords - i - 1];
#endif
        buf_ptr[sizeWords - i - 1] = tmp;
    }

    /* If sizeWords is odd revert middle word */
#ifndef BIG__ENDIAN
    if (sizeWords & 1UL) {
        buf_ptr[sizeWords / 2] = CRYS_COMMON_REVERSE32(buf_ptr[sizeWords / 2]); /* 2 is divider */
    }
#endif

    return;
} /* End of CRYS_COMMON_InPlaceConvertBytesWordsAndArrayEndianness */


/***********************************************************************/
/**
 * @brief This function converts big endianness bytes array to aligned words
 *        array with words order according to little endian.
 *
 *            1. Assumed, that input bytes order is set according
 *     	  to big endianness: MS Byte is most left, i.e. order is from
 *     	  Msb to Lsb.
 *            2. Output words array should set according to
 *     	  little endianness words order: LSWord is most left, i.e. order
 *     	  is from Lsw to Msw. Order bytes in each word - according to
 *     	  processor endianness.
 *            3. Owerlapping of buffers is not allowed, besides in
 *     	  place operation and size aligned to full words.
 *            4. Implementation is given for both big and little
 *     	  endianness of processor.
 *
 * @param[out] out32_ptr - The 32-bits pointer to output buffer.
 * @param[in] sizeOutBuffBytes - The size in bytes of output buffer, must be
 *            aligned to 4 bytes and not less than sizeInBytes.
 * @param[in] in8_ptr - The pointer to input buffer.
 * @param[in] sizeInBytes - The size in bytes of input data(sizeBytes >= 1).
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(
        uint32_t *out32_ptr,
        uint32_t  sizeOutBuffBytes,
        uint8_t  *in8_ptr,
        uint32_t  sizeInBytes)
{
    uint32_t size_in_words;
    CRYSError_t error = CRYS_FATAL_ERROR;

    /* Check pointers and size */
    if ((in8_ptr == NULL) || (out32_ptr == NULL))
        return CRYS_COMMON_DATA_IN_POINTER_INVALID_ERROR;

    /*  Check the size and in place operation:       *
     *   the size must be > 0 and aligned to words    */
    if ((sizeInBytes == 0) ||
            (((DxVirtAddr_t)out32_ptr == (DxVirtAddr_t)in8_ptr) && (sizeInBytes & 3))) /* 3 is mode */
        return CRYS_COMMON_DATA_SIZE_ILLEGAL;

    /* Size in words rounded up */
    size_in_words = (sizeInBytes + 3) / 4; /* 3 4 */

    if (sizeOutBuffBytes < (size_in_words * 4)) /* a word is 4 bytes */
        return CRYS_COMMON_OUTPUT_BUFF_SIZE_ILLEGAL;

    /*  If not in place operation zeroe output leading
        words and copy the input into aligned output
     *   buffer starting from non zero MSB */
    if ((DxVirtAddr_t)out32_ptr != (DxVirtAddr_t)in8_ptr) {
        /* Check overlapping */
        if ((((DxVirtAddr_t)out32_ptr > (DxVirtAddr_t)in8_ptr)
                    && ((DxVirtAddr_t)out32_ptr < (DxVirtAddr_t)(in8_ptr + sizeInBytes)))
                || (((DxVirtAddr_t)out32_ptr < (DxVirtAddr_t)in8_ptr)
                    && (((DxVirtAddr_t)out32_ptr + sizeInBytes) >= (DxVirtAddr_t)in8_ptr)))
            return CRYS_COMMON_DATA_OUT_DATA_IN_OVERLAP_ERROR;

        /* zeroe empty bytes */
        out32_ptr[0] = 0;
        /* zeroe empty bytes */
        out32_ptr[0] = 0;
        error = memset_s((DxUint8_t*)out32_ptr + (sizeInBytes & 3UL), sizeOutBuffBytes - (sizeInBytes & 3UL),
                         0, sizeOutBuffBytes - (sizeInBytes & 3UL));
        if (error != 0) {
            return error;
        }

        /* copy */
        error = memcpy_s((DxUint8_t*)out32_ptr + ((4 - (sizeInBytes & 3UL)) & 3UL), /* 4 bytes */
                         sizeInBytes, in8_ptr, sizeInBytes);
        if (error != CRYS_OK) {
            return error;
        }
    }

    /* Reverse words order and set endianness of each word */
    CRYS_COMMON_InPlaceConvertBytesWordsAndArrayEndianness(out32_ptr, size_in_words);

    return CRYS_OK;
}


/***********************************************************************/
/**
 * @brief This function converts big endianness bytes array to aligned words
 *        array with words order according to little endian.
 *
 *            1. Assumed, that input bytes order is set according
 *     	  to big endianness: MS Byte is most left, i.e. order is from
 *     	  Msb to Lsb.
 *            2. Output words array should be set according to
 *     	  little endianness words order: LSWord is most left, i.e. order
 *     	  is from Lsw to Msw. Bytes order in each word - according to
 *     	  processor endianness.
 *            3. Owerlapping of buffers is not allowed, besides in
 *     	  place operation and size aligned to full words.
 *            4. Implementation is given for both big and little
 *     	  endianness of processor.
 *
 * @param[in] out32_ptr - The 32-bits pointer to output buffer.
 * @param[in] sizeOutBuffBytes - The size in bytes of output buffer, must be
 *       not less than sizeInBytes.
 * @param[out] in8_ptr - The pointer to input buffer.
 * @param[in] sizeInBytes - The size in bytes. The size must be not 0 and
 *       aligned to 4 bytes word.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t CRYS_COMMON_ConvertLswMswWordsToMsbLsbBytes(
        uint8_t  *out8_ptr,
        uint32_t  sizeOutBuffBytes,
        uint32_t *in32_ptr,
        uint32_t  sizeInBytes)
{
    uint32_t size_in_words;
    CRYSError_t error = CRYS_FATAL_ERROR;

    /* Check pointers and size */
    if ((in32_ptr == NULL) || (out8_ptr == NULL))
        return CRYS_COMMON_DATA_IN_POINTER_INVALID_ERROR;

    /* Size in words rounded up */
    size_in_words = (sizeInBytes + 3) / 4; /* 3 4 */

    if ((sizeInBytes == 0) || (sizeOutBuffBytes < sizeInBytes))
        return CRYS_COMMON_DATA_SIZE_ILLEGAL;

    /* Check in place operation: the size must be aligned to word */
    if (((DxVirtAddr_t)in32_ptr == (DxVirtAddr_t)out8_ptr) && (sizeInBytes & 3UL))
        return CRYS_COMMON_DATA_SIZE_ILLEGAL;

    /* Reverse words order and bytes according to endianness of CPU */
    CRYS_COMMON_InPlaceConvertBytesWordsAndArrayEndianness(in32_ptr, size_in_words);

    /* Copy output buffer */
    if ((DxVirtAddr_t)out8_ptr != (DxVirtAddr_t)in32_ptr) {
        /* Check overlapping */
        if (((DxVirtAddr_t)out8_ptr > (DxVirtAddr_t)in32_ptr
                    && (DxVirtAddr_t)out8_ptr < ((DxVirtAddr_t)in32_ptr + sizeInBytes))
                || ((DxVirtAddr_t)out8_ptr < (DxVirtAddr_t)in32_ptr
                    && ((DxVirtAddr_t)out8_ptr + sizeInBytes) >= (DxVirtAddr_t)in32_ptr))
            return CRYS_COMMON_DATA_OUT_DATA_IN_OVERLAP_ERROR;

        error = memcpy_s(out8_ptr, sizeInBytes, (uint8_t *)in32_ptr
                + ((4 - (sizeInBytes & 3UL)) & 3UL), sizeInBytes); /* 4 */
        if (error != CRYS_OK) {
            return error;
        }

        /* Revert the input buffer to previous state */
        CRYS_COMMON_InPlaceConvertBytesWordsAndArrayEndianness(in32_ptr, size_in_words);
    }

    return CRYS_OK;
}

#endif
