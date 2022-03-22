/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_COMMON_MATH_H
#define SaSi_COMMON_MATH_H

#include "sasi_common_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

/* *********************** Macros ***************************** */
#ifndef IS_ALIGNED
#define IS_ALIGNED(val, align) (((SaSiVirtAddr_t)(val) & ((align)-1)) == 0)
#endif
/* converts size given in bits to size in 32-bit words, rounded up */
#define BIT_SIZE_UP_TO_32BIT_WORDS(x) (((x) >> 5UL) + (((x)&31) != 0))

/* rotate right 32-bits word by n bits */
#define SaSi_COMMON_ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
/* rotate 32-bits word by 16 bits */
#define SaSi_COMMON_ROT32(x) ((x) >> 16 | (x) << 16)

/* inverse the bytes order in a word */
#define SaSi_COMMON_REVERSE32(x) \
    (((SaSi_COMMON_ROT32((x)) & 0xff00ff00UL) >> 8) | ((SaSi_COMMON_ROT32((x)) & 0x00ff00ffUL) << 8))

#define SHIFT_LEFT(x, nBits)  ((x) >> (nBits))
#define SHIFT_RIGHT(x, nBits) ((x) << (nBits))
#define CONVERT_LE_2_CPU_E(x) (x)
#define CONVERT_CPU_E_2_BE(x) SaSi_COMMON_REVERSE32(x)

/* inverse the bytes order in words of array */
#define SaSi_COMMON_INVERSE_UINT32_IN_ARRAY(Array, SizeWords)   \
    {                                                           \
        uint32_t ii2;                                           \
        for (ii2 = 0; ii2 < (SizeWords); ii2++) {               \
            (Array)[ii2] = SaSi_COMMON_REVERSE32((Array)[ii2]); \
        }                                                       \
    }

#ifndef BIG__ENDIAN
/* define word endiannes */
#define SaSi_SET_WORD_ENDIANESS
#else
#define SaSi_SET_WORD_ENDIANESS(val) SaSi_COMMON_REVERSE32(val)
#endif

#ifdef BIG__ENDIAN
#define SaSi_COMMON_CONVERT_TO_LE32(in32_ptr, out32_ptr, size_words) \
    {                                                                \
        uint32_t i;                                                  \
        for (i = 0; i < size_words; i++) {                           \
            (out32_ptr)[i] = SaSi_COMMON_REVERSE32((in32_ptr)[i]);   \
        }                                                            \
    }
#else
#define SaSi_COMMON_CONVERT_TO_LE32(in32_ptr, out32_ptr, size_words) \
    {                                                                \
        uint32_t i;                                                  \
        if ((in32_ptr) != (out32_ptr)) {                             \
            for (i = 0; i < size_words; i++) {                       \
                (out32_ptr)[i] = (in32_ptr)[i];                      \
            }                                                        \
        }                                                            \
    }
#endif

/* get a bit val from a word array */
#define SaSi_COMMON_GET_BIT_VAL_FROM_WORD_ARRAY(ptr, bit_pos) (((ptr)[(bit_pos) >> 5] >> ((bit_pos)&0x1FUL)) & 1UL)

/* exchange a bit on a word array */
#define SaSi_COMMON_EXCHANGE_BIT_ON_WORD_ARRAY(ptr, bit_pos) ((ptr)[(bit_pos) >> 5] ^= (1UL << ((bit_pos)&0x1FUL)))

/* macros for copying 4 words to non aligned output according to macine endianness.
Note: output is given by aligned down pointer and alignment of output data in bits,
 input must be aligned to 4 bytes */
#ifdef BIG__ENDIAN

#define SaSi_COMMON_Copy4wordsToBytes(out32_ptr, outAlign, in32_ptr)                                                   \
    if (outAlign != 0) {                                                                                               \
        (out32_ptr)[0] =                                                                                               \
            ((out32_ptr)[0] & (0xFFFFFFFF << (32 - (outAlign)))) | SaSi_COMMON_REVERSE32((in32_ptr)[0]) >> (outAlign); \
        (out32_ptr)[1] = SaSi_COMMON_REVERSE32((in32_ptr)[0]) << (32 - (outAlign)) |                                   \
                         SaSi_COMMON_REVERSE32((in32_ptr)[1]) >> (outAlign);                                           \
        (out32_ptr)[2] = SaSi_COMMON_REVERSE32((in32_ptr)[1]) << (32 - (outAlign)) |                                   \
                         SaSi_COMMON_REVERSE32((in32_ptr)[2]) >> (outAlign);                                           \
        (out32_ptr)[3] = SaSi_COMMON_REVERSE32((in32_ptr)[2]) << (32 - (outAlign)) |                                   \
                         SaSi_COMMON_REVERSE32((in32_ptr)[3]) >> (outAlign);                                           \
        (out32_ptr)[4] = ((out32_ptr)[4] & (0xFFFFFFFF >> (outAlign))) | SaSi_COMMON_REVERSE32((in32_ptr)[3])          \
                                                                             << (32 - (outAlign));                     \
    } else {                                                                                                           \
        (out32_ptr)[0] = SaSi_COMMON_REVERSE32((in32_ptr)[0]);                                                         \
        (out32_ptr)[1] = SaSi_COMMON_REVERSE32((in32_ptr)[1]);                                                         \
        (out32_ptr)[2] = SaSi_COMMON_REVERSE32((in32_ptr)[2]);                                                         \
        (out32_ptr)[3] = SaSi_COMMON_REVERSE32((in32_ptr)[3]);                                                         \
    }

#else /* LITTLE_ENDIAN */
#define SaSi_COMMON_Copy4wordsToBytes(out32_ptr, outAlign, in32_ptr)                                         \
    if (outAlign != 0) {                                                                                     \
        (out32_ptr)[0] = ((out32_ptr)[0] & (0xFFFFFFFF >> (32 - (outAlign)))) | (in32_ptr)[0] << (outAlign); \
        (out32_ptr)[1] = (in32_ptr)[0] >> (32 - (outAlign)) | (in32_ptr)[1] << (outAlign);                   \
        (out32_ptr)[2] = (in32_ptr)[1] >> (32 - (outAlign)) | (in32_ptr)[2] << (outAlign);                   \
        (out32_ptr)[3] = (in32_ptr)[2] >> (32 - (outAlign)) | (in32_ptr)[3] << (outAlign);                   \
        (out32_ptr)[4] = ((out32_ptr)[4] & (0xFFFFFFFF << (outAlign))) | (in32_ptr)[3] >> (32 - (outAlign)); \
    } else {                                                                                                 \
        (out32_ptr)[0] = (in32_ptr)[0];                                                                      \
        (out32_ptr)[1] = (in32_ptr)[1];                                                                      \
        (out32_ptr)[2] = (in32_ptr)[2];                                                                      \
        (out32_ptr)[3] = (in32_ptr)[3];                                                                      \
    }
#endif

/* macros for copying 16 bytes from non aligned input into aligned output according to machine endianness.
Note: input is given by aligned down pointer and alignment of input data in bits,
 output must be aligned to 4 bytes */

#ifdef BIG__ENDIAN

#define SaSi_COMMON_Copy16BytesToWords(in32_ptr, inAlign, out32_ptr)                                            \
    if (inAlign != 0) {                                                                                         \
        (out32_ptr)[0] = SaSi_COMMON_REVERSE32((in32_ptr)[0] << (inAlign) | (in32_ptr)[1] >> (32 - (inAlign))); \
        (out32_ptr)[1] = SaSi_COMMON_REVERSE32((in32_ptr)[1] << (inAlign) | (in32_ptr)[2] >> (32 - (inAlign))); \
        (out32_ptr)[2] = SaSi_COMMON_REVERSE32((in32_ptr)[2] << (inAlign) | (in32_ptr)[3] >> (32 - (inAlign))); \
        (out32_ptr)[3] = SaSi_COMMON_REVERSE32((in32_ptr)[3] << (inAlign) | (in32_ptr)[4] >> (32 - (inAlign))); \
    } else {                                                                                                    \
        (out32_ptr)[0] = SaSi_COMMON_REVERSE32((in32_ptr)[0]);                                                  \
        (out32_ptr)[1] = SaSi_COMMON_REVERSE32((in32_ptr)[1]);                                                  \
        (out32_ptr)[2] = SaSi_COMMON_REVERSE32((in32_ptr)[2]);                                                  \
        (out32_ptr)[3] = SaSi_COMMON_REVERSE32((in32_ptr)[3]);                                                  \
    }

#else /* LITTLE_ENDIAN */

#define SaSi_COMMON_Copy16BytesToWords(in32_ptr, inAlign, out32_ptr)                     \
    if (inAlign != 0) {                                                                  \
        (out32_ptr)[0] = (in32_ptr)[0] >> (inAlign) | (in32_ptr)[1] << (32 - (inAlign)); \
        (out32_ptr)[1] = (in32_ptr)[1] >> (inAlign) | (in32_ptr)[2] << (32 - (inAlign)); \
        (out32_ptr)[2] = (in32_ptr)[2] >> (inAlign) | (in32_ptr)[3] << (32 - (inAlign)); \
        (out32_ptr)[3] = (in32_ptr)[3] >> (inAlign) | (in32_ptr)[4] << (32 - (inAlign)); \
    } else {                                                                             \
        (out32_ptr)[0] = (in32_ptr)[0];                                                  \
        (out32_ptr)[1] = (in32_ptr)[1];                                                  \
        (out32_ptr)[2] = (in32_ptr)[2];                                                  \
        (out32_ptr)[3] = (in32_ptr)[3];                                                  \
    }
#endif

#define SaSi_COMMON_CopyWordsToBytes(out32_ptr, outAlign, in32_ptr, inOffset) \
    SaSi_COMMON_Copy4wordsToBytes(out32_ptr, outAlign, in32_ptr)
#define SaSi_COMMON_CopyBytesToWords(in32_ptr, inAlign, out32_ptr, outOffset) \
    SaSi_COMMON_Copy16BytesToWords(in32_ptr, inAlign, out32_ptr)

/* *********************** Enums ****************************** */

/* the counter comperation result enum */
typedef enum {
    SaSi_COMMON_CmpCounter1AndCounter2AreIdentical = 0,
    SaSi_COMMON_CmpCounter1GraterThenCounter2      = 1,
    SaSi_COMMON_CmpCounter2GraterThenCounter1      = 2,

    SaSi_COMMON_CmpCounterLast = 0x7FFFFFFF,

} SaSi_COMMON_CmpCounter_t;

/* shift direction  enum */
typedef enum {
    SaSi_COMMON_ShiftRight = 0,
    SaSi_COMMON_ShiftLeft  = 1,

    SaSi_COMMON_ShiftOffMode,

    SaSi_COMMON_ShiftDirectionLast = 0x7FFFFFFF,

} SaSi_COMMON_ShiftDirection_t;

/* *********************** Typedefs  *************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

/* ****************************************************************
 * @brief This function adds a value to a large counter presented in a buffer.
 *        The MSB of the counter is stored in the first cell in the array.
 *
 *        for example:
 *
 *        a counter of 64 bit : the value is :
 *
 *        byte[0] << 56 | byte[1] << 48 ............ byte[6] << 8 | byte[7]
 *
 * @param[in] CounterBuff_ptr - The buffer containing the counter.
 * @param[in] Val             - this value to add.
 * @param[in] CounterSize      - the counter size in 32bit words.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */

void SaSi_COMMON_IncMsbUnsignedCounter(uint32_t *CounterBuff_ptr, uint32_t Val, uint32_t CounterSize);

/* *******************************************************************************
 * @brief This function adds a value to a large counter presented in a buffer.
 *        The LSB of the counter is stored in the first cell in the array.
 *
 *        for example:
 *
 *        a counter of 64 bit : the value is :
 *
 *        byte[7] << 56 | byte[6] << 48 ............ byte[1] << 8 | byte[0]
 *
 * @param[in] CounterBuff_ptr - The buffer containing the counter.
 * @param[in] Val             - this value to add.
 * @param[in] CounterSize      - the counter size in 32bit words.
 *
 * @return carry bit from MS word if carry occur
 *
 */

uint32_t SaSi_COMMON_IncLsbUnsignedCounter(uint32_t *CounterBuff_ptr, uint32_t Val, uint32_t CounterSize);

/* *******************************************************************************
 * @brief This function subtracts a value from a large counter presented in a buffer.
 *        The LSB of the counter is stored in the first cell in the array.
 *
 *        for example:
 *
 *        a counter of 64 bit : the value is :
 *
 *        byte[7] << 56 | byte[6] << 48 ............ byte[1] << 8 | byte[0]
 *
 * @param[in] CounterBuff_ptr - the buffer containing the counter.
 * @param[in] Val             - the value to subtract.
 * @param[in]  CounterSize      - the counter size in 32bit words.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */

void SaSi_COMMON_DecrLsbUnsignedCounter(uint32_t *CounterBuff_ptr, uint32_t Val, uint32_t CounterSizeInWords);

/* *************************************************************
 * @brief This function compares a value of 2 large counter presented in a byte buffer.
 *        The MSB of the counter is stored in the first cell in the array.
 *
 *        for example:
 *
 *        a counter of 64 bit : the value is :
 *
 *        byte[0] << 56 | byte[1] << 48 ............ byte[6] << 8 | byte[7]
 *
 *
 * @param[in] CounterBuff1_ptr - The first counter buffer.
 * @param[in] Counter1Size     - the first counter size in bytes.
 * @param[in] CounterBuff2_ptr - The second counter buffer.
 * @param[in] Counter2Size     - the second counter size in bytes.
 * @param[in] SizeUnit         - the size units. 0 - bits , 1 - bytes
 *
 * @return result - an enum with the compare result:
 *                                0 - both counters are identical
 *                                1 - counter 1 is larger.
 *                                2 - counter 2 is larger.
 * @note This code executes in constant time, regardless of the arguments.
 */

SaSi_COMMON_CmpCounter_t SaSi_COMMON_CmpMsbUnsignedCounters(const uint8_t *CounterBuff1_ptr, uint32_t Counter1Size,
                                                            const uint8_t *CounterBuff2_ptr, uint32_t Counter2Size);

/* *************************************************************
 * @brief This function compares a value of 2 large counter presented in a byte buffer.
 *        The LSB of the counter is stored in the first cell in the array.
 *
 *        for example:
 *
 *        a counter of 64 bit : the value is :
 *
 *        byte[7] << 56 | byte[6] << 48 ............ byte[1] << 8 | byte[0]
 *
 * @param[in] CounterBuff1_ptr - The first counter buffer.
 * @param[in] Counter1Size     - the first counter size in bytes.
 * @param[in] CounterBuff2_ptr - The second counter buffer.
 * @param[in] Counter2Size     - the second counter size in bytes.
 *
 * @return result - an enum with the compare result:
 *                                0 - both counters are identical
 *                                1 - counter 1 is larger.
 *                                2 - counter 2 is larger.
 */

SaSi_COMMON_CmpCounter_t SaSi_COMMON_CmpLsbUnsignedCounters(const uint8_t *CounterBuff1_ptr, size_t Counter1Size,
                                                            const uint8_t *CounterBuff2_ptr, size_t Counter2Size);

/* *************************************************************************
 *           SaSi_COMMON_CmpLsWordsUnsignedCounters function          *
 * *********************************************************************** */
/*
 * @brief This function compares a value of 2 large counter presented in a word buffer.
 *        The LSWord of the counters is stored in the first cell in the array.
 *
 *
 * @param[in] CounterBuff1_ptr  - The first counter buffer.
 * @param[in] Counter1SizeWords - the first counter size in Words.
 * @param[in] CounterBuff2_ptr  - The second counter buffer.
 * @param[in] Counter2SizeWords - the second counter size in Words.
 *
 * @return result - an enum with the compare result:
 *                                0 - both counters are identical
 *                                1 - counter 1 is larger.
 *                                2 - counter 2 is larger.
 */
SaSi_COMMON_CmpCounter_t SaSi_COMMON_CmpLsWordsUnsignedCounters(const uint32_t *CounterBuff1_ptr,
                                                                uint32_t Counter1SizeWords,
                                                                const uint32_t *CounterBuff2_ptr,
                                                                uint32_t Counter2SizeWords);

/* *******************************************************************************
 *
 * @brief This function returns the effective number of bits in the byte stream counter
 *        ( searching the highest '1' in the counter )
 *
 *        The function has one implementations: for little and big endian machines.
 *
 *        Assumed, that LSB of the counter is stored in the first cell in the array.
 *         For example, the value of the 8-Bytes counter B is :
 *             B[7]<<56 | B[6]<<48 ............ B[1]<<8 | B[0] .
 *
 *
 * @param[in] CounterBuff_ptr -  The counter buffer.
 * @param[in] CounterSize     -  the counter size in bytes.
 *
 * @return result - The effective counters size in bits.
 */

uint32_t SaSi_COMMON_GetBytesCounterEffectiveSizeInBits(const uint8_t *CounterBuff_ptr, uint32_t CounterSize);

/* ******************************************************************************
 *             SaSi_COMMON_GetWordsCounterEffectiveSizeInBits                  *
 * ******************************************************************************
 *
 * @brief This function returns the effective number of bits in the words array
 *        ( searching the highest '1' in the counter )
 *
 *        The function may works on little and big endian machines.
 *
 *        Assumed, that the words in array are ordered from LS word to MS word.
 *        For LITTLE Endian machines assumed, that LSB of the each word is stored in the first
 *        cell in the word. For example, the value of the 8-Bytes (B) counter is :
 *             B[7]<<56 | B[6]<<48 ............ B[1]<<8 | B[0]
 *
 *        For BIG Endian machines assumed, that MS byte of each word is stored in the first
 *        cell, LS byte is stored in the last place of the word.
 *        For example, the value of the 64 bit counter is :
 *         B[3] << 56 | B[2] << 48 B[1] << 8 | B[0],  B[7]<<56 | B[6]<<48 | B[5]<<8 | B[4]
 *
 *     NOTE !!: 1. For BIG Endian the counter buffer and its size must be aligned to 4-bytes word.
 *
 * @param[in] CounterBuff_ptr   -  The counter buffer.
 * @param[in] CounterSizeWords  -  The counter size in words.
 *
 * @return result - The effective counters size in bits.
 *
 */
uint32_t SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(const uint32_t *CounterBuff_ptr, uint32_t CounterSizeWords);

/* *******************************************************************************
 * @brief This function divides a vector by 2 - in a secured way
 *
 *        The LSB of the vector is stored in the first cell in the array.
 *
 *        for example:
 *
 *        a vector of 128 bit : the value is :
 *
 *        word[3] << 96 | word[2] << 64 ............ word[1] << 32 | word[0]
 *
 * @param[in] VecBuff_ptr     -  The vector buffer.
 * @param[in] SizeInWords     -  the counter size in words.
 *
 * @return result - no return value.
 */
void SaSi_COMMON_DivideVectorBy2(uint32_t *VecBuff_ptr, uint32_t SizeInWords);

/* *******************************************************************************
 * @brief This function shifts left a big endian vector by Shift - bits (Shift < 8).
 *
 *        The MSB of the vector is stored in the first cell in the array,
 *
 *        For example, a vector of 128 bit is :
 *
 *        byte[n-1] | byte[n-2] ... byte[1] | byte[0]
 *
 * @param[in] VecBuff_ptr     -  The vector buffer.
 * @param[in] SizeInBytes     -  The counter size in bytes.
 * @param[in] Shift           -  The number of shift left bits, must be < 8.
 * @return no return value.
 */

void SaSi_COMMON_ShiftLeftBigEndVector(uint8_t *VecBuff_ptr, uint32_t SizeInBytes, int8_t Shift);

/* ******************************************************************************
 *                      SaSi_COMMON_ShiftRightVector                            *
 * ******************************************************************************
 * @brief This function shifts right a vector by Shift - bits (Shift < 8).
 *
 *        The LSB of the vector is stored in the first cell in the array.
 *        For example, a vector of 128 bit is :
 *
 *        byte[n-1] | byte[n-2] ... byte[1] | byte[0]
 *
 * @param[in] VecBuff_ptr     -  The vector buffer.
 * @param[in] SizeInBytes     -  The counter size in bytes.
 * @param[in] Shift           -  The number of shift left bits, must be < 8.
 * @return no return value.
 */
void SaSi_COMMON_ShiftRightVector(uint8_t *VecBuff_ptr, uint32_t SizeInBytes, int8_t Shift);

/* *****************************************************************************
 *                      SaSi_COMMON_ShiftLeftVector                            *
 * *****************************************************************************
 * @brief This function shifts left a vector by Shift - bits (Shift < 8).
 *
 *        The LSB of the vector is stored in the first cell in the array.
 *        For example, a vector of 128 bit is :
 *
 *        byte[n-1] | byte[n-2] ... byte[1] | byte[0]
 *
 * @param[in] VecBuff_ptr     -  The vector buffer.
 * @param[in] SizeInBytes     -  The counter size in bytes.
 * @param[in] Shift           -  The number of shift left bits, must be < 8.
 * @return no return value.
 */
void SaSi_COMMON_ShiftLeftVector(uint8_t *VecBuff_ptr, uint32_t SizeInBytes, int8_t Shift);

/* *************************************************************
 * @brief This function adds 2 vectors ( A+B).
 *
 * @param[in] A_ptr       -  input vector A.
 * @param[in] B_ptr       -  input vector B.
 * @param[in] SizeInWords - The size in words
 * @param[in] Res_ptr     - The result pointer
 *
 * @return result  - Carry from high words addition.
 */

uint32_t SaSi_COMMON_Add2vectors(uint32_t *A_ptr, uint32_t *B_ptr, uint32_t SizeInWords, uint32_t *Res_ptr);

/* ******************************************************************************
*                      SaSi_COMMON_SubtractWordArrays                         *
* ******************************************************************************

* @brief This function subtracts two little endian words arrays of length
  SizeInWords:  Res = (A - B) and returns Borrow from subtracting of high
  words.
*
* @param[in] A_ptr       -  input vector A.
* @param[in] B_ptr       -  input vector B.
* @param[in] SizeInWords -  size in words
* @param[in] Res_ptr     -  result pointer
*
* @return  Borrow from high words subtracting.
*/

uint32_t SaSi_COMMON_SubtractUintArrays(const uint32_t *A_ptr, uint32_t *B_ptr, uint32_t SizeInWords,
                                        uint32_t *Res_ptr);

/* ******************************************************************************
 *                      SaSi_COMMON_AddTwoLsbUint8Vectors                      *
 * ******************************************************************************
 *
 * @brief This function adds two little endian vectors Res = (A + B) and returns carry.
 *
 *
 * @param[in] A_ptr       -  input vector A.
 * @param[in] B_ptr       -  input vector B.
 * @param[in] SizeInWords -  size in words
 * @param[in] Res_ptr     -  result pointer
 *
 * @return - carry from adding of two high bytes.
 */

uint32_t SaSi_COMMON_AddTwoLsbUint8Vectors(uint8_t *A_ptr, uint8_t *B_ptr, uint32_t VectSizeInBytes, uint8_t *Res_ptr);

/* ******************************************************************************
*                      SaSi_COMMON_SubtractMSBUint8Arrays                     *
* ******************************************************************************

* @brief This function subtracts two big endian byte arrays.
*
*   Assuming:  SizeA >= SizeB.
*              Size of result buffer is not less, than sizeA.
*
* @param[in] A_ptr       -  Pointer to input vector A.
* @param[in] sizeA       -  Size in bytes of each of vector A.
* @param[in] B_ptr       -  Pointer to input vector B.
* @param[in] sizeB       -  Size in bytes of each of vector B.
* @param[in] Res_ptr     -  result pointer
*
* @return  Borrow from high byte of vector A.
*/
uint8_t SaSi_COMMON_SubtractMSBUint8Arrays(uint8_t *A_ptr, uint32_t sizeA, uint8_t *B_ptr, uint32_t sizeB,
                                           uint8_t *Res_ptr);

#ifdef __cplusplus
}
#endif

#endif
