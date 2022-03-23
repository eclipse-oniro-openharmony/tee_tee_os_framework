/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: common math
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "crys_common_math.h"
#include "crys_common_error.h"

#ifndef DX_OEM_FW

/*
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
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
void CRYS_COMMON_IncMsbUnsignedCounter(
    uint32_t *CounterBuff_ptr, uint32_t Val, uint32_t CounterSize)
{
    /* a value for storing the current counter word value */
    uint32_t cur_counter_word_val;
    uint32_t i;

    /* inversing the counters bytes to a word in little endian format. */
    for (i = 0 ; i < CounterSize ; i++)
        CounterBuff_ptr[i] = CRYS_COMMON_REVERSE32(CounterBuff_ptr[i]);

    /* initialize the current local counter value to the first word */
    cur_counter_word_val = CounterBuff_ptr[CounterSize - 1];

    /* adding the value to the word */
    CounterBuff_ptr[CounterSize - 1] += Val;

    /* if there is overflow on the word then handle the upper words */
    if (cur_counter_word_val > CounterBuff_ptr[CounterSize - 1]) {
        /* adding the carry to the counter loop */
        i = CounterSize - 2; /* 2 */
        while (1) {
            /* set the current word value */
            cur_counter_word_val = CounterBuff_ptr[i];

            /* adding the carry to the current word */
            CounterBuff_ptr[i]++;

            /* if there is no overflow on the current word after adding the value
               exit the loop */
            if ((cur_counter_word_val < CounterBuff_ptr[i]) || (i == 0)) {
                break;
            }
            i--;
        }
    }

    /* restore the counters bytes order */
    for (i = 0 ; i < CounterSize ; i++)
        CounterBuff_ptr[i] = CRYS_COMMON_REVERSE32(CounterBuff_ptr[i]);

    return;
}

/*
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
uint32_t CRYS_COMMON_IncLsbUnsignedCounter(
    uint32_t *CounterBuff_ptr, uint32_t Val, uint32_t CounterSize)
{
    /* a value for storing the current counter word value */
    uint32_t cur_counter_word_val;
    uint32_t i;
    uint32_t  carry = 0;

    /* initialize the current local counter value to the first word */
    cur_counter_word_val = CounterBuff_ptr[0];

    /* adding the value to the word */
    CounterBuff_ptr[0] += Val;

    /* if there is overflow on the word then handle the upper words */
    if (cur_counter_word_val > CounterBuff_ptr[0]) {
        /* adding the carry to the counter loop */
        for (i = 1 ; i < CounterSize ; i++) {
            /* set the current word value */
            cur_counter_word_val = CounterBuff_ptr[i];

            /* adding the carry to the current word */
            CounterBuff_ptr[i]++;

            /* if there is no overflow on the current word after adding the value
               exit the loop */
            if (cur_counter_word_val < CounterBuff_ptr[i]) {
                carry = 0;
                break;
            } else {
                carry = 1;
            }
        }
    }

    return carry;
}

/* @brief This function adds a value to a large counter presented in a buffer.
 *        Exactly like CRYS_COMMON_IncLsbUnsignedCounter, but when the processor is big endian
 *
 *
 * @param[in] CounterBuff_ptr - The buffer containing the counter.
 * @param[in] Val             - this value to add.
 * @param[in] CounterSize      - the counter size in 32bit words.
 *
 * @return carry bit from MS word if carry occur
 *
 */
void CRYS_COMMON_IncLsbUnsignedCounterBigEndian(
    uint32_t *CounterBuff_ptr, uint32_t Val, uint32_t CounterSize)
{
    /* a value for storing the current counter word value */
    uint32_t cur_counter_word_val;
    uint32_t i;

    /* initialize the current local counter value to the first word */
    cur_counter_word_val = CounterBuff_ptr[CounterSize - 1];

    /* adding the value to the word */
    CounterBuff_ptr[CounterSize - 1] += Val;

    /* if there is overflow on the word then handle the upper words */
    if (cur_counter_word_val > CounterBuff_ptr[CounterSize - 1]) {
        /* adding the carry to the counter loop */
        i = CounterSize - 2; /* minus 2 */
        while (1) {
            /* set the current word value */
            cur_counter_word_val = CounterBuff_ptr[i];

            /* adding the carry to the current word */
            CounterBuff_ptr[i]++;

            /* if there is no overflow on the current word after adding the value
               exit the loop */
            if ((cur_counter_word_val < CounterBuff_ptr[i]) || (i == 0)) {
                break;
            }
            i--;
        }
    }

    return;
}

/*
 * @brief This function subtracts a value from a large counter presented in a first
 *        buffer and sets result in a second buffer. The first and the second
 *        buffers may be the same.
 *        The LSB of the counter is stored in the first cell in the array,
 *
 * @param[in]  CounterBuff_ptr - the buffer containing the counter.
 * @param[in]  Val             - the value to subtract.
 * @param[in]  CounterSize      - the counter size in 32bit words.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
void CRYS_COMMON_DecrLsbUnsignedCounter(
	uint32_t *CounterBuff_ptr, uint32_t Val, uint32_t CounterSizeInWords)
{
    uint32_t borrow, temp;
    uint32_t i;

    borrow = Val;

    /* Subtracting loop */
    for (i = 0 ; i < CounterSizeInWords ; i++) {
        temp = CounterBuff_ptr[i];

        CounterBuff_ptr[i] = CounterBuff_ptr[i] - borrow;

        if (CounterBuff_ptr[i] > temp)
            borrow = 1;
        else
            break;
    }

    return;
}

/* @brief This function subtracts a value from a large counter presented in a first
 *        buffer and sets result in a second buffer. The first and the second
 *        buffers may be the same.
 *        The LSB of the counter is stored in the last cell in the array,
 *
 * @param[in]  CounterBuff_ptr - the buffer containing the counter.
 * @param[in]  Val             - the value to subtract.
 * @param[out] ResCounterBuff_ptr - the buffer containing the result counter.
 * @param[in]  CounterSize      - the counter size in 32bit words.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
void CRYS_COMMON_DecrMsbUnsignedCounter(
	uint32_t *CounterBuff_ptr, uint32_t Val, uint32_t CounterSizeInWords)
{
    uint32_t borrow, temp;
    uint32_t i;

    borrow = Val;

    /* Subtracting loop */
    i = CounterSizeInWords - 1; 
    while (1) {
        temp = CounterBuff_ptr[i];

        CounterBuff_ptr[i] = CounterBuff_ptr[i] - borrow;

        if (CounterBuff_ptr[i] > temp) {
            borrow = 1;
        } else {
            break; 
        }
        if (i == 0) {
            break;
        }
        i--;
    }

    return;
}

/* @brief This function compares a value of 2 large counters presented in a byte buffer.
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
CRYS_COMMON_CmpCounter_t CRYS_COMMON_CmpMsbUnsignedCounters(
        const uint8_t *CounterBuff1_ptr, uint32_t Counter1Size, const uint8_t *CounterBuff2_ptr, uint32_t Counter2Size)
{
    int32_t start_ind1, start_ind2, i;

    /* the result after comparing the bytes */
    CRYS_COMMON_CmpCounter_t result;

    /* the final result */
    CRYS_COMMON_CmpCounter_t final_result;

    /* the default is that the result is the same */
    result = CRYS_COMMON_CmpCounter1AndCounter2AreIdentical;
    /* just to avoid compilers warnings */
    final_result = CRYS_COMMON_CmpCounter1AndCounter2AreIdentical;

    start_ind1 = 0;
    start_ind2 = 0;
    /* a loop for adjusting the counter 1 size by neglecting the zeros */
    while (Counter1Size && (CounterBuff1_ptr[start_ind1] == 0)) {
        start_ind1++;
        Counter1Size--;
    }
    /* a loop for adjusting the counter 2 size by neglecting the zeros */
    while (Counter2Size && (CounterBuff2_ptr[start_ind2] == 0)) {
        start_ind2++;
        Counter2Size--;
    }

    /* step 1 : comparing the counters assuming the effective counter size is the same. For security reasons
       we shall execute this loop as the minimum between the counter sizes the result will be neglected in
       steps 2,3 if the actual size is different. We shall compare all of the bytes from the MSB, the first
       one that is different will determine which counter is larger, if all of the bytes are equal then the
       counters are equal */
    for (i = 0 ; i < min(Counter1Size, Counter2Size) ; i++) {
        /* if the counter 1 byte is grater then counter 2 byte - return counter 1 is bigger */
        if ((CounterBuff1_ptr[start_ind1 + i] > CounterBuff2_ptr[start_ind2 + i])
                && result == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical)
            result = CRYS_COMMON_CmpCounter1GraterThenCounter2;

        /* if the counter 2 byte is grater then counter 1 byte - return counter 2 is bigger */
        if ((CounterBuff2_ptr[start_ind2 + i] > CounterBuff1_ptr[start_ind1 + i])
                && result == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical)
            result = CRYS_COMMON_CmpCounter2GraterThenCounter1;
    }

    /* STEP 2 : the counter 1 effective size is bigger then counter 2 effective size. On this case the final
       result is then counter 1 is larger then counter 2 - neglecting the result calculated in step 1 */
    if (Counter1Size > Counter2Size)
        final_result = CRYS_COMMON_CmpCounter1GraterThenCounter2;

    /* STEP 3 : the counter 2 effective size is bigger then counter 1 effective size. On this case the final
       result is then counter 2 is larger then counter 1 - neglecting the result calculated in step 1 */
    if (Counter2Size > Counter1Size)
        final_result = CRYS_COMMON_CmpCounter2GraterThenCounter1;

    /* STEP 4 : the counter 1 effective size is the same as the counter 2 effective size. On this case the final
       result is the one calculated in STEP 1 */
    if (Counter2Size == Counter1Size)
        final_result = result;

    return final_result;
}
#endif

/* @brief This function compares a value of 2 large counter presented in a byte buffer.
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
CRYS_COMMON_CmpCounter_t CRYS_COMMON_CmpLsbUnsignedCounters(
        const uint8_t *CounterBuff1_ptr, uint32_t Counter1Size, const uint8_t *CounterBuff2_ptr, uint32_t Counter2Size)
{
    int32_t i;
    /* the result after comparing the bytes */
    CRYS_COMMON_CmpCounter_t result;
    /* the final result */
    CRYS_COMMON_CmpCounter_t final_result;

    /* the default is that the result is the same */
    result = CRYS_COMMON_CmpCounter1AndCounter2AreIdentical;
    final_result = CRYS_COMMON_CmpCounter1AndCounter2AreIdentical; /* just to avoid compilers warnings */

    /* STEP 1 : calculate the effective size (decrementing the zeros at the MS bytes). A loop for adjusting the
       counter 1 size by neglecting the zeros */
    while (Counter1Size != 0) {
        if (CounterBuff1_ptr[Counter1Size - 1] == 0)
            Counter1Size--;
        else
            break;
    }

    /* a loop for adjusting the counter 2 size by neglecting the zeros */
    while (Counter2Size != 0) {
        if (CounterBuff2_ptr[Counter2Size - 1] == 0)
            Counter2Size--;
        else
            break;
    }

    /* check the sizes */
    if (Counter1Size == 0 && Counter2Size == 0)
        return CRYS_COMMON_CmpCounter1AndCounter2AreIdentical;
    else if (Counter1Size > Counter2Size)
        return CRYS_COMMON_CmpCounter1GraterThenCounter2;
    else if (Counter2Size > Counter1Size)
        return CRYS_COMMON_CmpCounter2GraterThenCounter1;

    /* step 2 : comparing the counters assuming the effective counter size is the same. For security reasons we shall
       execute this loop as the minimum between the counter sizes the result will be neglected in steps 2,3 if the
       actual size is different. We shall compare all of the bytes from the MSB , the first one that is different
       will determine which counter is larger, if all of the bytes are equal then the counters are equal */
    for (i = min(Counter1Size - 1, Counter2Size - 1); i >= 0; i--) {
        /* if the counter 1 byte is grater then counter 2 byte - return counter 1 is bigger */
        if ((CounterBuff1_ptr[i] > CounterBuff2_ptr[i]) && result == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical)
            result = CRYS_COMMON_CmpCounter1GraterThenCounter2;

        /* if the counter 2 byte is grater then counter 1 byte - return counter 2 is bigger */
        if ((CounterBuff2_ptr[i] > CounterBuff1_ptr[i]) && result == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical)
            result = CRYS_COMMON_CmpCounter2GraterThenCounter1;
    }

    /* STEP 3 : the counter 1 effective size is bigger then counter 2 effective size. On this case the final result
       is then counter 1 is larger then counter 2 - neglecting the result calculated in step 1 */
    if (Counter1Size > Counter2Size)
        final_result = CRYS_COMMON_CmpCounter1GraterThenCounter2;

    /* STEP 4 : the counter 2 effective size is bigger then counter 1 effective size. On this case the final result
       is then counter 2 is larger then counter 1 - neglecting the result calculated in step 1 */
    if (Counter2Size > Counter1Size)
        final_result = CRYS_COMMON_CmpCounter2GraterThenCounter1;

    /* STEP 4 : the counter 1 effective size is the same as the counter 2 effective size. On this case the final result
       is the one calculated in STEP 1 */
    if (Counter2Size == Counter1Size)
        final_result = result;

    return final_result;
}

/* @brief This function compares a value of 2 large counter presented in a word buffer.
 *        The LSWord of the counters is stored in the first cell in the array.
 *
 *
 * @param[in] CounterBuff1_ptr - The first counter buffer.
 * @param[in] Counter1SizeWords     - the first counter size in Words.
 * @param[in] CounterBuff2_ptr - The second counter buffer.
 * @param[in] Counter2SizeWords     - the second counter size in Words.
 *
 * @return result - an enum with the compare result:
 *                                0 - both counters are identical
 *                                1 - counter 1 is larger.
 *                                2 - counter 2 is larger.
 */
CRYS_COMMON_CmpCounter_t CRYS_COMMON_CmpLsWordsUnsignedCounters(
        uint32_t *CounterBuff1_ptr, uint32_t Counter1SizeWords, uint32_t *CounterBuff2_ptr, uint32_t Counter2SizeWords)
{
    int32_t i;
    /* the result after comparing the bytes */
    CRYS_COMMON_CmpCounter_t result;
    /* the final result */
    CRYS_COMMON_CmpCounter_t final_result;

    /* the default is that the result is the same */
    result = CRYS_COMMON_CmpCounter1AndCounter2AreIdentical;
    final_result = CRYS_COMMON_CmpCounter1AndCounter2AreIdentical; /* just to avoid compilers warnings */

    /* a loop for adjusting the counter 1 size by neglecting the zeros */
    while (Counter1SizeWords != 0) {
        if (CounterBuff1_ptr[Counter1SizeWords - 1] == 0)
            Counter1SizeWords--;
        else
            break;
    }

    /* a loop for adjusting the counter 2 size by neglecting the zeros */
    while (Counter2SizeWords != 0) {
        if (CounterBuff2_ptr[Counter2SizeWords - 1] == 0)
            Counter2SizeWords--;
        else
            break;
    }

    /* check the sizes */
    if (Counter1SizeWords == 0 && Counter2SizeWords == 0)
        return CRYS_COMMON_CmpCounter1AndCounter2AreIdentical;
    else if (Counter1SizeWords > Counter2SizeWords)
        return CRYS_COMMON_CmpCounter1GraterThenCounter2;
    else if (Counter2SizeWords > Counter1SizeWords)
        return CRYS_COMMON_CmpCounter2GraterThenCounter1;

    /* step 1 : comparing the counters assuming the effective counter size is the same. For security reasons we shall
       execute this loop as the minimum between the counter sizes the result will be neglected in steps 2,3 if the
       actual size is different. We shall compare all of the bytes from the MSB , the first one that is different
       will determine which counter is larger , if all of the bytes are equal then the counters are equal */
    for (i = min(Counter1SizeWords - 1, Counter2SizeWords - 1) ; i >= 0 ; i--) {
        /* if the counter 1 byte is grater then counter 2 byte - return counter 1 is bigger */
        if ((CounterBuff1_ptr[i] > CounterBuff2_ptr[i]) && (result == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical))
            result = CRYS_COMMON_CmpCounter1GraterThenCounter2;

        /* if the counter 2 byte is grater then counter 1 byte - return counter 2 is bigger */
        if ((CounterBuff2_ptr[i] > CounterBuff1_ptr[i]) && (result == CRYS_COMMON_CmpCounter1AndCounter2AreIdentical))
            result = CRYS_COMMON_CmpCounter2GraterThenCounter1;
    }

    /* STEP 2 : the counter 1 effective size is bigger then counter 2 effective size. On this case the final result is
       then counter 1 is larger then counter 2 - neglecting the result calculated in step 1 */
    if (Counter1SizeWords > Counter2SizeWords)
        final_result = CRYS_COMMON_CmpCounter1GraterThenCounter2;

    /* STEP 3 : the counter 2 effective size is bigger then counter 1 effective size. On this case the final result is
       then counter 2 is larger then counter 1 - neglecting the result calculated in step 1 */
    if (Counter2SizeWords > Counter1SizeWords)
        final_result = CRYS_COMMON_CmpCounter2GraterThenCounter1;

    /* STEP 4 : the counter 1 effective size is the same as the counter 2 effective size. On this case the final result
       is the one calculated in STEP 1 */
    if (Counter2SizeWords == Counter1SizeWords)
        final_result = result;

    return final_result;
}

/* @brief This function returns the effective number of bits in the byte stream counter
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
uint32_t CRYS_COMMON_GetBytesCounterEffectiveSizeInBits(
    const uint8_t *CounterBuff_ptr, uint32_t CounterSize)
{
    int32_t i;
    /* the effective size in bits */
    uint32_t effective_size;
    /* the effective MS byte ( the one that is not zero ) */
    uint8_t effcetive_ms_byte;

    /* STEP1 : a loop for adjusting the counter size by neglecting the MSB zeros */
    while (CounterSize != 0) {
        if (CounterBuff_ptr[CounterSize - 1] == 0)
            CounterSize--;
        else
            break;
    }

    /* STEP2 : if counter size is 0 - return 0 */
    if (CounterSize == 0)
        return 0;

    /* set the effective MS byte */
    effcetive_ms_byte = CounterBuff_ptr[CounterSize - 1];

    /* initialize the effective size as the counters size ( with MSB zeros ) */
    effective_size = CounterSize * 8; /* 8 bits */

    /* STEP 3 : adjusting the effective size in bits */
    for (i = 0; i < 8 ; i++) { /* 8 bits */
        if (effcetive_ms_byte & 0x80) /* and 0x80 */
            break;

        effective_size--;
        effcetive_ms_byte <<= 1;
    }

    return effective_size;
}

#ifndef DX_OEM_FW

/* @brief This function returns the effective number of bits in the words array
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
 */
uint32_t CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(
        uint32_t *CounterBuff_ptr, uint32_t CounterSizeWords)
{
    int32_t i;
    /* the effective size in bits */
    uint32_t effective_size;
    /* the  MS word ( the first, that is not zero ) */
    uint32_t ms_word;

    /* STEP1 : a loop for adjusting the counter size by neglecting the MSW zeros */
    while (CounterSizeWords != 0) {
        if (CounterBuff_ptr[CounterSizeWords - 1] == 0)
            CounterSizeWords--;
        else
            break;
    }

    /* STEP2 : if counter size is 0 - return 0 */
    if (CounterSizeWords == 0)
        return 0;

    /* set the effective MS word and bit-size */
    ms_word = CounterBuff_ptr[CounterSizeWords - 1];
    effective_size = 32 * CounterSizeWords; /* 32 bits */

    /* STEP 3 : adjusting the effective size in bits */
    for (i = 0; i < 32 ; i++) { /* 32 bits */
        if (ms_word & 0x80000000) /* and 0x80000000 */
            break;

        effective_size--;
        ms_word <<= 1;
    }

    return effective_size;
}

/* @brief This function divides a vector by 2 - in a secured way
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
void CRYS_COMMON_DivideVectorBy2(uint32_t *VecBuff_ptr, uint32_t SizeInWords)
{
    uint32_t i;
    uint32_t temp;

    /* for loop for dividing the vectors arrays by 2 */
    for (i = 0; i < (SizeInWords) - 1 ; i++) {
        VecBuff_ptr[i] = VecBuff_ptr[i] >> 1;
        temp = VecBuff_ptr[i + 1] & 1UL;
        VecBuff_ptr[i] = VecBuff_ptr[i] | (temp << (32 - 1)); /* 32 bits */
    }

    /* dividing the MS word */
    VecBuff_ptr[SizeInWords - 1] = VecBuff_ptr[SizeInWords - 1] >> 1;

    return;
}

/* @brief This function shifts left a big endian vector by Shift - bits (Shift < 8).
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
void CRYS_COMMON_ShiftLeftBigEndVector(uint8_t *VecBuff_ptr, uint32_t SizeInBytes, int8_t Shift)
{
    uint32_t i;
    uint32_t temp = 0;

    if (SizeInBytes == 0 || Shift == 0)
        return;

    /* loop for shifting the vector by Shift bits left */
    for (i = 0; i < SizeInBytes - 1; i++) {
        VecBuff_ptr[i] = (uint8_t)(VecBuff_ptr[i] << Shift);
        temp = VecBuff_ptr[i + 1] & 0xFF ;
        VecBuff_ptr[i] = VecBuff_ptr[i] | (uint8_t)(temp >> (8 - Shift)); /* 8 bits */
    }

    /* shifting the LS byte */
    VecBuff_ptr[SizeInBytes - 1] = (uint8_t)(VecBuff_ptr[SizeInBytes - 1] << Shift);

    return;
}

/* @brief This function shifts right a vector by Shift - bits (Shift < 8).
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
void CRYS_COMMON_ShiftRightVector(uint8_t *VecBuff_ptr, uint32_t SizeInBytes, int8_t Shift)
{
    uint32_t i;
    uint32_t temp = 0;

    if (SizeInBytes == 0 || Shift == 0)
        return;

    /* loop for shifting the vector by Shift bits right */
    for (i = 0; i < SizeInBytes - 1; i++) {
        VecBuff_ptr[i] = (uint8_t)(VecBuff_ptr[i] >> Shift);
        temp = VecBuff_ptr[i + 1] & 0xFF ;
        VecBuff_ptr[i] = VecBuff_ptr[i] | (uint8_t)(temp << (8 - Shift)); /* 8 bits */
    }

    /* shifting the MS byte */
    VecBuff_ptr[SizeInBytes - 1] = (uint8_t)(VecBuff_ptr[SizeInBytes - 1] >> Shift);

    return;
}

/* @brief This function adds 2 vectors ( A+B).
 *
 * @param[in] A_ptr       -  input vector A.
 * @param[in] B_ptr       -  input vector B.
 * @param[in] SizeInWords - The size in words
 * @param[in] Res_ptr     - The result pointer
 *
 * @return - carry from high words addition.
 */
uint32_t CRYS_COMMON_Add2vectors(uint32_t *A_ptr, uint32_t *B_ptr, uint32_t SizeInWords, uint32_t *Res_ptr)
{
    uint16_t  i;
    uint32_t temp;
    uint32_t carry;
    uint32_t prev_carry = 0;
    uint32_t cur_word_res;

    for (i = 0; i < SizeInWords; i++) {
        /* execute the addition */
        cur_word_res = A_ptr[i] + B_ptr[i];

        /* check if carry */
        carry = ((cur_word_res < A_ptr[i]) || (cur_word_res < B_ptr[i]));

        /* add previous carry */
        Res_ptr[i] = cur_word_res + prev_carry;

        /*	Solve 4 problems:
            1.if result > 32 bits ==> carry to the next word.
            2.if the result=32 bits exactly ==> the result is = 0 but carry=1 to the next word.
            3.if the result=32 bit-1 and because of prev_carry the result come to 0 ==> carry to the next word.
            4.if the result=0 because the exercise is 0+0. */
        temp = 2; /* set temp to 2 */

        if (!(Res_ptr[i]))
            temp = 1;

        if (Res_ptr[i])
            temp = 0;

        prev_carry = carry | (prev_carry & temp & 0x1);
    }

    return prev_carry;
}

/* @brief This function subtracts two little endian word arrays (length SizeInWords):
 *        Res = (A - B) and returns borrow from subtracting of high words.
 *
 * @param[in] A_ptr       -  Pointer to input vector A.
 * @param[in] B_ptr       -  Pointer to input vector B.
 * @param[in] SizeInWords -  Size in words of each of vectors
 * @param[in] Res_ptr     -  result pointer
 *
 * @return  borrow from high words subtracting.
 */
uint32_t CRYS_COMMON_SubtractUintArrays(
    uint32_t *A_ptr, uint32_t *B_ptr, uint32_t SizeInWords, uint32_t *Res_ptr)
{
    uint32_t temp, i;
    uint32_t borrow = 0;

    for (i = 0; i < SizeInWords; i++) {
        /* subtract previous borrow */
        temp = A_ptr[i] - borrow;

        /* check if borrow */
        if (temp > A_ptr[i])
            borrow = 1;

        else borrow = 0;

        /* subtract B */
        Res_ptr[i] = temp - B_ptr[i];

        /* check if borrow */
        if (Res_ptr[i] > temp)
            borrow++;
    }

    return borrow;
}

/* @brief This function subtracts two big endian byte arrays.
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
 * @return  borrow from high byte of vector A.
 */
uint8_t CRYS_COMMON_SubtractMSBUint8Arrays(
    uint8_t *A_ptr, uint32_t sizeA, uint8_t *B_ptr, uint32_t sizeB, uint8_t *Res_ptr)
{
    uint8_t temp;
    uint8_t borrow = 0;
    int32_t dif_size, i;

    dif_size = sizeA - sizeB;

    for (i = sizeA - 1; i > 0; i--) {
        /* subtract previous borrow */
        temp = A_ptr[i] - borrow;

        /* check if borrow */
        if (temp > A_ptr[i])
            borrow = 1;

        else borrow = 0;

        /* subtract B */
        if ((i - dif_size) >= 0)
            Res_ptr[i] = temp - B_ptr[i - dif_size];
        else
            Res_ptr[i] = temp;

        /* check if borrow */
        if (Res_ptr[i] > temp)
            borrow++;
    }

    return borrow;
}

/* The function checks is the buffer zero;
 *
 * @author reuvenl (7/25/2016)
 *
 * @param buf  - pointer to the buffer 1;
 * @param size - size of the buffer;
 *
 * @return uint32_t value: 1 - if buffer is zero, 0 - otherwise.
 */
uint32_t CRYS_COMMON_IsBufferZero(uint8_t *buf, size_t size)
{
    size_t i;
    uint32_t res = 0;
    for (i = 0; i < size; i++)
        res |= buf[i];

    return ((res - 1) >> 31); /* right shift 31 */
}

#endif
