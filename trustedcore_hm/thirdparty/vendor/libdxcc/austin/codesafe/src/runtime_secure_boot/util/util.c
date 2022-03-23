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
#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_SECURE_BOOT

/* ************ Include Files ************** */

#include "dx_pal_types.h"
#include "util.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* ************ Private function prototype ************** */

/* *********************** Private Functions **************************** */

/* ------------------------------------------------------------
 **
 * @brief This function executes a reversed words copy on a specified buffer.
 *
 *        on a 6 words buffer:
 *
 *        buff[5] <---> buff[0]
 *        buff[4] <---> buff[1]
 *        buff[3] <---> buff[2]
 *
 * @param[in] dst_ptr - The counter buffer.
 * @param[in] size    - The counter size in words.
 *
 */
void UTIL_ReverseWordsBuff(uint32_t *buff_ptr, uint32_t sizeWords)
{
    /* FUNCTION DECLARATIONS */

    /* loop variable */
    uint32_t i;

    /* buffer swap pointers */
    uint32_t *buffHighSwap_ptr, *buffLowSwap_ptr;

    /* a temp variable */
    uint32_t temp;

    /* FUNCTION LOGIC */

    /* initialize the source and the destination poision */
    buffHighSwap_ptr = buff_ptr + sizeWords - 1;
    buffLowSwap_ptr  = buff_ptr;

    /* execute the reverse memcpoy */
    for (i = 0; i < (sizeWords / 2); i++) {
        temp                  = *buffHighSwap_ptr;
        *(buffHighSwap_ptr--) = *buffLowSwap_ptr;
        *(buffLowSwap_ptr++)  = temp;
    }

    return;

} /* END OF UTIL_ReverseWordsBuff */

/* ------------------------------------------------------------
 **
 * @brief This function executes a reversed byte copy on a specified buffer.
 *
 *        on a 6 byte buffer:
 *
 *        buff[5] <---> buff[0]
 *        buff[4] <---> buff[1]
 *        buff[3] <---> buff[2]
 *
 * @param[in] dst_ptr - The counter buffer.
 * @param[in] src_ptr - The counter size in bytes.
 *
 */
void UTIL_ReverseBuff(uint8_t *buff_ptr, uint32_t size)
{
    /* FUNCTION DECLARATIONS */

    /* loop variable */
    uint32_t i;

    /* buffer swap pointers */
    uint8_t *buffHighSwap_ptr, *buffLowSwap_ptr;

    /* a temp variable */
    uint32_t temp;

    /* FUNCTION LOGIC */

    /* initialize the source and the destination poision */
    buffHighSwap_ptr = buff_ptr + size - 1;
    buffLowSwap_ptr  = buff_ptr;

    /* execute the reverse memcpoy */
    for (i = 0; i < (size / 2); i++) {
        temp                  = *buffHighSwap_ptr;
        *(buffHighSwap_ptr--) = *buffLowSwap_ptr;
        *(buffLowSwap_ptr++)  = temp;
    }

    return;

} /* END OF UTIL_ReverseBuff */

/* ------------------------------------------------------------
**
* @brief This function executes a reverse bytes copying from one buffer to another buffer.
*
* @param[in] dst_ptr - The pointer to destination buffer.
* @param[in] src_ptr - The pointer to source buffer.
* @param[in] size    - The size in bytes.
*
*/
void UTIL_ReverseMemCopy(uint8_t *dst_ptr, uint8_t *src_ptr, uint32_t size)
{
    /* FUNCTION DECLARATIONS */

    /* loop variable */
    uint32_t i;

    /* buffers position identifiers */
    uint32_t buff_dst_pos, buff_src_pos;

    /* FUNCTION LOGIC */

    /* execute the reverse copy in case of different buffers */
    /* initialize the source and the destination position */
    buff_dst_pos = size - 1;
    buff_src_pos = 0;

    for (i = 0; i < size; i++)
        dst_ptr[buff_dst_pos--] = src_ptr[buff_src_pos++];

    return;

} /* END OF UTIL_ReverseMemCopy */
