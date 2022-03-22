/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

#include "sasi_common.h"
#include "sasi_common_math.h"
#include "sasi_common_error.h"
#include "ssi_pal_mem.h"

/* *********************** Defines **************************** */

/* *********************** Enums ****************************** */

/* *********************** Typedefs *************************** */

/* *********************** Global Data ************************ */

/* ************ Private function prototype ******************** */

/* *********************** Public Functions ******************* */

/* **********************************************************************
 **
 * @brief This function executes a reverse bytes copying from one buffer to another buffer.
 *
 *        Overlapping of buffers is not allowed, excluding the case, when destination and source
 *        buffers are the same.
 *        Example of a 5 byte buffer:
 *
 *        dst_ptr[4] = src_ptr[0]
 *        dst_ptr[3] = src_ptr[1]
 *        dst_ptr[2] = src_ptr[2]
 *        dst_ptr[1] = src_ptr[3]
 *        dst_ptr[0] = src_ptr[4]
 *
 * @param[in] dst_ptr - The pointer to destination buffer.
 * @param[in] src_ptr - The pointer to source buffer.
 * @param[in] size    - The size in bytes.
 *
 */
SaSiError_t SaSi_COMMON_ReverseMemcpy(uint8_t *dst_ptr, uint8_t *src_ptr, uint32_t size)
{
    /* FUNCTION DECLARATIONS */

    /* loop variable */
    uint32_t i;

    /* FUNCTION LOGIC */

    /* check overlapping */
    if ((dst_ptr > src_ptr && dst_ptr < (src_ptr + size)) || (dst_ptr < src_ptr && (dst_ptr + size) >= src_ptr)) {
        return SaSi_COMMON_DATA_OUT_DATA_IN_OVERLAP_ERROR;
    }

    /* execute the reverse copy in case of different buffers */
    if (dst_ptr != src_ptr) {
        for (i = 0; i < size; i++)
            dst_ptr[i] = src_ptr[size - 1 - i];
    }

    /* execute the reverse copy in the same place */
    else {
        uint8_t temp;

        for (i = 0; i < size / 2; i++) {
            temp                  = src_ptr[i];
            src_ptr[i]            = src_ptr[size - 1 - i];
            src_ptr[size - 1 - i] = temp;
        }
    }

    return SaSi_OK;

} /* END OF SaSi_COMMON_ReverseMemcpy */

#ifndef DX_OEM_FW

/* ******************************************************************** */
/*
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
void SaSi_COMMON_InPlaceConvertBytesWordsAndArrayEndianness(uint32_t *buf_ptr, uint32_t sizeWords)
{
    /* FUNCTION DECLARATIONS */

    uint32_t i, tmp;

    /* FUNCTION logic */

    if (sizeWords == 0)
        return;
    if (sizeWords == 1) {
        buf_ptr[0] = SaSi_COMMON_REVERSE32(buf_ptr[0]);
        return;
    }

    /* Reverse words order and bytes in each word */
    for (i = 0; i < sizeWords / 2; i++) {
#ifndef BIG__ENDIAN
        tmp        = SaSi_COMMON_REVERSE32(buf_ptr[i]);
        buf_ptr[i] = SaSi_COMMON_REVERSE32(buf_ptr[sizeWords - i - 1]);
#else
        tmp        = buf_ptr[i];
        buf_ptr[i] = buf_ptr[sizeWords - i - 1];
#endif
        buf_ptr[sizeWords - i - 1] = tmp;
    }

    /* If sizeWords is odd revert middle word */
#ifndef BIG__ENDIAN
    if (sizeWords & 1UL) {
        buf_ptr[sizeWords / 2] = SaSi_COMMON_REVERSE32(buf_ptr[sizeWords / 2]);
    }
#endif

    return;

} /* End of SaSi_COMMON_InPlaceConvertBytesWordsAndArrayEndianness */

/* ******************************************************************** */
/*
 * @brief This function converts big endianness bytes array to aligned words
 *        array with words order according to little endian.
 *
 *            1. Assumed, that input bytes order is set according
 *           to big endianness: MS Byte is most left, i.e. order is from
 *           Msb to Lsb.
 *            2. Output words array should set according to
 *           little endianness words order: LSWord is most left, i.e. order
 *           is from Lsw to Msw. Order bytes in each word - according to
 *           processor endianness.
 *            3. Owerlapping of buffers is not allowed, besides in
 *           place operation and size aligned to full words.
 *            4. Implementation is given for both big and little
 *           endianness of processor.
 *
 * @param[out] out32_ptr - The 32-bits pointer to output buffer.
 * @param[in] sizeOutBuffBytes - The size in bytes of output buffer, must be
 *            aligned to 4 bytes and not less than sizeInBytes.
 * @param[in] in8_ptr - The pointer to input buffer.
 * @param[in] sizeInBytes - The size in bytes of input data(sizeBytes >= 1).
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
SaSiError_t SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(uint32_t *out32_ptr, uint32_t sizeOutBuffBytes,
                                                        const uint8_t *in8_ptr, uint32_t sizeInBytes)
{
    /* FUNCTION DECLARATIONS */

    uint32_t sizeInWords;

    /* FUNCTION LOGIC */

    /* Check pointers and size */
    if ((in8_ptr == NULL) || (out32_ptr == NULL))
        return SaSi_COMMON_DATA_IN_POINTER_INVALID_ERROR;

    /*  Check the size and in place operation:       *
     *   the size must be > 0 and aligned to words    */
    if ((sizeInBytes == 0) || (((SaSiVirtAddr_t)out32_ptr == (SaSiVirtAddr_t)in8_ptr) && (sizeInBytes & 3)))
        return SaSi_COMMON_DATA_SIZE_ILLEGAL;

    /* Size in words rounded up */
    sizeInWords = (sizeInBytes + 3) / 4;

    if (sizeOutBuffBytes < (sizeInWords * sizeof(uint32_t)))
        return SaSi_COMMON_OUTPUT_BUFF_SIZE_ILLEGAL;

    /*  If not in place operation zeroe output leading*
        words and copy the input into aligned output
    *   buffer starting from non zero MSB */
    if ((SaSiVirtAddr_t)out32_ptr != (SaSiVirtAddr_t)in8_ptr) {
        /* Check overlapping */
        if ((((SaSiVirtAddr_t)out32_ptr > (SaSiVirtAddr_t)in8_ptr) &&
             ((SaSiVirtAddr_t)out32_ptr < (SaSiVirtAddr_t)(in8_ptr + (sizeInWords * sizeof(uint32_t))))) ||
            (((SaSiVirtAddr_t)out32_ptr < (SaSiVirtAddr_t)in8_ptr) &&
             ((SaSiVirtAddr_t)out32_ptr + (sizeInWords * sizeof(uint32_t)) >= (SaSiVirtAddr_t)in8_ptr))) {
            return SaSi_COMMON_DATA_OUT_DATA_IN_OVERLAP_ERROR;
        }

        /* zero empty bytes */
        out32_ptr[0] = 0;
        SaSi_PalMemSetZero((uint8_t *)&out32_ptr[sizeInWords], sizeOutBuffBytes - sizeInWords * sizeof(uint32_t));
        /* copy */
        SaSi_PalMemCopy((uint8_t *)out32_ptr + sizeInWords * sizeof(uint32_t) - sizeInBytes, in8_ptr, sizeInBytes);
    }

    /* Reverse words order and set endianness of each word */
    SaSi_COMMON_InPlaceConvertBytesWordsAndArrayEndianness(out32_ptr, sizeInWords);

    return SaSi_OK;
}

/* ******************************************************************** */
/*
 * @brief This function converts LE 32bit-words array to BE bytes array.
 *
 *            1. Assumed, that output bytes order is according
 *           to big endianness: MS Byte is most left, i.e. order is from
 *           Msb to Lsb.
 *            2. Input words array should be set according to
 *           little endianness words order: LSWord is most left, i.e. order
 *           is from Lsw to Msw. Bytes order in each word - according to
 *           processor endianness.
 *            3. Owerlapping of buffers is not allowed, besides in
 *           place operation and size aligned to full words.
 *            4. Implementation is given for both big and little
 *           endianness of processor.
 *
 * @param[in] out32_ptr - The 32-bits pointer to output buffer.
 * @param[in] sizeOutBuffBytes - The size in bytes of output buffer, must be
 *       not less than sizeInBytes.
 * @param[out] in8_ptr - The pointer to input buffer.
 * @param[in] sizeInBytes - The size in bytes. The size must be not 0 and
 *       aligned to 4 bytes word.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
SaSiError_t SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(uint8_t *out8_ptr, uint32_t sizeOutBuffBytes,
                                                        uint32_t *in32_ptr, uint32_t sizeInBytes)
{
    /* FUNCTION DECLARATIONS */

    uint32_t sizeInWords;

    /* FUNCTION LOGIC */

    /* Check pointers and size */
    if ((in32_ptr == NULL) || (out8_ptr == NULL))
        return SaSi_COMMON_DATA_IN_POINTER_INVALID_ERROR;

    /* Size in words rounded up */
    sizeInWords = (sizeInBytes + 3) / 4;

    if ((sizeInBytes == 0) || (sizeOutBuffBytes < sizeInBytes))
        return SaSi_COMMON_DATA_SIZE_ILLEGAL;

    /* Check in place operation: the size must be aligned to word */
    if (((SaSiVirtAddr_t)in32_ptr == (SaSiVirtAddr_t)out8_ptr) && (sizeInBytes & 3UL))
        return SaSi_COMMON_DATA_SIZE_ILLEGAL;

    /* Reverse words order and bytes according to endianness of CPU */
    SaSi_COMMON_InPlaceConvertBytesWordsAndArrayEndianness(in32_ptr, sizeInWords);

    /* Copy output buffer */
    if ((SaSiVirtAddr_t)out8_ptr != (SaSiVirtAddr_t)in32_ptr) {
        /* Check overlapping */
        if (((SaSiVirtAddr_t)out8_ptr > (SaSiVirtAddr_t)in32_ptr &&
             (SaSiVirtAddr_t)out8_ptr < ((SaSiVirtAddr_t)in32_ptr + sizeInBytes)) ||
            ((SaSiVirtAddr_t)out8_ptr < (SaSiVirtAddr_t)in32_ptr &&
             ((SaSiVirtAddr_t)out8_ptr + sizeInBytes) >= (SaSiVirtAddr_t)in32_ptr))
            return SaSi_COMMON_DATA_OUT_DATA_IN_OVERLAP_ERROR;

        SaSi_PalMemCopy(out8_ptr, (uint8_t *)in32_ptr + ((4 - (sizeInBytes & 3UL)) & 3UL), sizeInBytes);
        /* Revert the input buffer to previous state */
        SaSi_COMMON_InPlaceConvertBytesWordsAndArrayEndianness(in32_ptr, sizeInWords);
    }

    return SaSi_OK;
}

/* ******************************************************************** */
/*
 * @brief This function converts bytes array with little endian (LE) order of
 *        bytes to 32-bit words array with little endian order of words and bytes.
 *
 *   Assuming:  No owerlapping of buffers; in/out pointers and sizes are not equall to NULL.
 *
 * @param[out] out32Le - The 32-bits pointer to output buffer. The buffer size must be
 *                       not less, than input data size.
 * @param[in] in8Le - The pointer to input buffer.
 * @param[in] sizeInBytes - The size in bytes of input data(sizeBytes > 0).
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
void SaSi_COMMON_ConvertLsbMsbBytesToLswMswWords(uint32_t *out32Le, uint8_t *in8Le, size_t sizeInBytes)
{
    uint32_t sizeInWords;

    /* Size in words rounded up */
    sizeInWords = (sizeInBytes + 3) / 4;

    /* if not in place, then zero empty bytes of MS word and copy data */
    if ((uint8_t *)out32Le != in8Le) {
        out32Le[sizeInWords - 1] = 0;
        SaSi_PalMemCopy((uint8_t *)out32Le, in8Le, sizeInBytes);
    }

#ifdef BIG__ENDIAN
    /* Reverse endianness of each word */
    {
        uint32_t i;
        for (i = 0; i < sizeInWords; i++) {
            SaSi_COMMON_REVERSE32(out32Le[i]);
        }
    }
#endif
    return;
}

/* ******************************************************************** */
/*
* @brief This function converts 32-bit words array with little endian
*        order of words to bytes array with little endian (LE) order of bytes.
*
*    Assuming: no buffers overlapping, in/out pointers and sizes not equall to NULL,
               the buffer size must be not less, than input data size.
*
* @param[out] out8Le - The bytes pointer to output buffer.
* @param[in] in32Le - The pointer to input 32-bit words buffer.
* @param[in] sizeInWords - The size in words of input data (sizeWords >= 0).
*
* @return SaSiError_t - On success SaSi_OK is returned, on failure a
*                        value MODULE_* as defined in .
*/
void SaSi_COMMON_ConvertLswMswWordsToLsbMsbBytes(uint8_t *out8Le, uint32_t *in32Le, size_t sizeInWords)
{
    /* FUNCTION LOGIC */

#ifndef BIG__ENDIAN
    if (out8Le != (uint8_t *)in32Le) {
        SaSi_PalMemCopy(out8Le, (uint8_t *)in32Le, sizeInWords * sizeof(uint32_t));
    }
#else
    /* Reverse endianness of each word and copy it to output */
    size_t i;

    for (i = 0; i < sizeInWords; i++) {
        if (out8Le != (uint8_t *)in32Le) {
            uint32_t tmp;
            tmp = in32Le[i / sizeof(uint32_t)];
            SaSi_COMMON_REVERSE32(tmp);
            out8Le[i * sizeof(uint32_t) + 0] = tmp & 0xFF;
            out8Le[i * sizeof(uint32_t) + 1] = (tmp >> 8) & 0xFF;
            out8Le[i * sizeof(uint32_t) + 2] = (tmp >> 16) & 0xFF;
            out8Le[i * sizeof(uint32_t) + 3] = (tmp >> 24) & 0xFF;
        } else {
            SaSi_COMMON_REVERSE32(in32Le[i]);
        }
    }

#endif
    return;
}

#endif
