/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef UTIL_H
#define UTIL_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  Wed Feb 23 09:03:06 2005
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief A brief description of this module
 *
 *  \version UTIL.h#1:incl:1
 *  \author adams
 *  \remarks Copyright (C) 2004 by Discretix Technologies Ltd.
 *           All Rights reserved
 */

/* *********************** Defines **************************** */

/* invers the bytes on a word- used for output from HASH */
#ifdef BIG__ENDIAN
#define UTIL_INVERSE_UINT32_BYTES(val) (val)
#else
#define UTIL_INVERSE_UINT32_BYTES(val) \
    (((val) >> 24) | (((val)&0x00FF0000) >> 8) | (((val)&0x0000FF00) << 8) | (((val)&0x000000FF) << 24))
#endif

/* invers the bytes on a word - used for input data for HASH */
#ifdef BIG__ENDIAN
#define UTIL_REVERT_UINT32_BYTES(val) \
    (((val) >> 24) | (((val)&0x00FF0000) >> 8) | (((val)&0x0000FF00) << 8) | (((val)&0x000000FF) << 24))
#else
#define UTIL_REVERT_UINT32_BYTES(val) (val)
#endif

/* the minimum and maximum macros */
#undef min
#define min(a, b) (((a) < (b)) ? (a) : (b))

#undef max
#define max(a, b) (((a) > (b)) ? (a) : (b))

/* MACRO to count one bits */
#define COUNT_ONE_BITS(number, BitCount)        \
    do {                                        \
        uint32_t tmp_num = number;              \
        BitCount         = 0;                   \
        while (tmp_num) {                       \
            tmp_num  = tmp_num & (tmp_num - 1); \
            BitCount = BitCount + 1;            \
        }                                       \
    } while (0)

#define CONVERT_BYTE_ARR_TO_WORD(inPtr, outWord, numOfBytes) \
    do {                                                     \
        outWord = 0;                                         \
        uint8_t index;                                       \
        for (index = 0; index < numOfBytes; index++) {       \
            outWord |= (*(inPtr + index) << 8 * index);      \
        }                                                    \
    } while (0)

#define ALIGN_TO_4BYTES(val)                         \
    do {                                             \
        val = val + ((4 - ((uint32_t)(val)&3)) % 4); \
    } while (0)
/* *********************** Enums ****************************** */

/* the counter comperation result enum */
typedef enum {
    UTIL_CmpCounter1AndCounter2AreIdentical = 0,
    UTIL_CmpCounter1GraterThenCounter2      = 1,
    UTIL_CmpCounter2GraterThenCounter1      = 2

} UTIL_CmpCounter_t;

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

/* ------------------------------------------------------------
 **
 * @brief This function executes a reversed words copy on a specified buffer.
 *
 *        on a 6 words byffer:
 *
 *        buff[5] <---> buff[0]
 *        buff[4] <---> buff[1]
 *        buff[3] <---> buff[2]
 *
 * @param[in] dst_ptr - The counter buffer.
 * @param[in] size    - The counter size in words.
 *
 */
void UTIL_ReverseWordsBuff(uint32_t *buff_ptr, uint32_t sizeWords);

/* ------------------------------------------------------------
 **
 * @brief This function executes a reversed byte copy on a specified buffer.
 *
 *        on a 6 byte byffer:
 *
 *        buff[5] <---> buff[0]
 *        buff[4] <---> buff[1]
 *        buff[3] <---> buff[2]
 *
 * @param[in] dst_ptr - The counter buffer.
 * @param[in] src_ptr - The counter size in bytes.
 *
 */
void UTIL_ReverseBuff(uint8_t *buff_ptr, uint32_t size);

/* ------------------------------------------------------------
 **
 * @brief This function executes a reverse bytes copying from one buffer to another buffer.
 *
 * @param[in] dst_ptr - The pointer to destination buffer.
 * @param[in] src_ptr - The pointer to source buffer.
 * @param[in] size    - The size in bytes.
 *
 */
void UTIL_ReverseMemCopy(uint8_t *dst_ptr, uint8_t *src_ptr, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif
