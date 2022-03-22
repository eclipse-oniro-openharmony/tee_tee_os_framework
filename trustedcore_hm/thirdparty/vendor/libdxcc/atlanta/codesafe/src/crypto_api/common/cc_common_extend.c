/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/



/************************ Include Files *************************/

#include "cc_common_math.h"
#include "cc_common_error.h"

/************************ Defines *******************************/

/************************ Enums *********************************/

/************************ Typedefs ******************************/

/************************ Global Data ***************************/

/****************** Private function prototype ******************/

/************************ Public Functions **********************/


/*******************************************************************************
 *             CC_CommonGetBytesCounterEffectiveSizeInBits                  *
 *******************************************************************************
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

 uint32_t CC_CommonGetBytesCounterEffectiveSizeInBits( uint8_t  *CounterBuff_ptr,
                                                            uint16_t  CounterSize )
{
   /* FUNCTION LOCAL DECLERATIONS */

   /* loop variable */
   int32_t i;

   /* the effective size in bits */
   uint32_t CounterEffectiveSizeInBits;

   /* the effective MS byte ( the one that is not zero ) */
   uint8_t EffectiveMsByteVal;

   /* FUNCTION LOGIC */

   /* check that input buffer is aligned */
   if((uint32_t)CounterBuff_ptr % 4 != 0)
	 	return CC_COMMON_POINTER_NOT_ALIGNED_ERROR;


   /* STEP1 : a loop for adjusting the counter size by neglecting the MSB zeros */
   while( CounterSize && (CounterBuff_ptr[CounterSize - 1] == 0) )

     CounterSize--;

   /* STEP2 : if counter size is 0 - return 0 */
   if( CounterSize == 0 )

     return 0;

   /* set the effective MS byte */
   EffectiveMsByteVal = CounterBuff_ptr[CounterSize - 1];

   /* initialize the effective size as the counters size ( with MSB zeros ) */
   CounterEffectiveSizeInBits = CounterSize * 8;

   /* STEP 3 : adjusting the effective size in bits */
   for( i = 0; i < 8 ; i++ )
   {
     /* if the MS bit is set exit the loop */
     if( EffectiveMsByteVal & 0x80 )
       break;

     /* decrement the effective size in bits by 1 */
     CounterEffectiveSizeInBits--;

     /* shift the byte left by 1 bit */
     EffectiveMsByteVal <<= 1;

   }/* end of adjusting the effective size in bits loop */

   return CounterEffectiveSizeInBits;

}/* END OF CC_CommonGetBytesCounterEffectiveSizeInBits */




/*******************************************************************************
 *                      CC_CommonAddTwoLsbUint8Vectors                      *
 *******************************************************************************
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

uint32_t CC_CommonAddTwoLsbUint8Vectors(
                                          uint8_t  *A_ptr,
                                          uint8_t  *B_ptr,
                                          uint32_t  VectSizeInBytes,
                                          uint8_t  *Res_ptr )

{
	/* FUNCTION DECLARATIONS */

	uint32_t  i;
	uint32_t temp ;


	/* FUNCTION LOGIC */

	temp = 0;

	for (i=0; i < VectSizeInBytes; i++)
	{
		/* add A, B and previous carry */
		temp =  temp + A_ptr[i] + B_ptr[i];

		/* output current byte of result */
		Res_ptr[i] = (uint8_t)(temp & 0xFF);

		/* calculate carry */
		temp = temp >> 8;

	}/* end of adding */

	return temp;

}/* END OF CC_CommonAddTwoLsbUint8Vectors */


/*******************************************************************************
 *                      CC_CommonSubtractMSBUint8Arrays                     *
 *******************************************************************************

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
uint8_t CC_CommonSubtractMSBUint8Arrays(
                                          uint8_t  *A_ptr,
                                          uint32_t  sizeA,
                                          uint8_t  *B_ptr,
                                          uint32_t  sizeB,
                                          uint8_t  *Res_ptr )
{
  /* FUNCTION LOCAL DECLARATIONS */

	uint8_t temp;

	uint8_t Borrow = 0;

	int32_t difSizes, i;


	/* FUNCTION LOGIC */

	difSizes = sizeA - sizeB;

    for (i = sizeA - 1; i > 0; i--)
	{
		/* subtract previous borrow */
   		temp = A_ptr[i] - Borrow;

		/* check if borrow */
	    if( temp > A_ptr[i] )

	    	Borrow = 1;

		else Borrow = 0;

		/* subtract B */
		if( i - difSizes >= 0 )
  	 		Res_ptr[i] = temp - B_ptr[i - difSizes];
		else
		    Res_ptr[i] = temp;

		/* check if borrow */
	    if( Res_ptr[i] > temp )

	    	Borrow ++;

	}/* end of subtracting */

  return Borrow;

}/* END OF CC_CommonSubtractUintArrays */


/******************************************************************************
*                      CC_CommonShiftLeftVector                            *
/******************************************************************************
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

void CC_CommonShiftLeftVector(uint8_t *VecBuff_ptr,uint32_t SizeInBytes, int8_t Shift)
{
	/* FUNCTION LOCAL DECLARATIONS */

	uint32_t i;
	uint32_t Temp = 0;


	/* FUNCTION LOGIC */

	if( SizeInBytes == 0 || Shift == 0 )
		return;

	/* loop for shifting the vector by Shift bits left */
	for (i=SizeInBytes - 1;i > 0;i--)
	{
		VecBuff_ptr[i] = (uint8_t)(VecBuff_ptr[i] << Shift);
		Temp = VecBuff_ptr[i+1] & 0xFF ;
		VecBuff_ptr[i] = VecBuff_ptr[i] | (uint8_t)(Temp >> (8 - Shift));
	}

	/* shifting the LS byte */
	VecBuff_ptr[0] = (uint8_t)(VecBuff_ptr[0] >> Shift);

	return;

}/* END OF CC_CommonShiftLeftVector */