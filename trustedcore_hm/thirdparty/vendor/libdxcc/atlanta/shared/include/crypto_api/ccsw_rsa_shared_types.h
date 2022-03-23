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

#ifndef CCSW_RSA_SHARED_TYPES_H
#define CCSW_RSA_SHARED_TYPES_H

#ifdef __cplusplus
extern "C"
{
#endif


/** @file
 *  @brief This file contains the types for the CCSW RSA module.
 */

/************************ Defines ******************************/

/************************************************************************/
/* the following definitions are only relevant for RSA code on SW */
/************************************************************************/
/* Define the maximal allowed width of the exponentiation sliding window
in range 2...6. This define is actual for projects on soft platform.
To minimize code size use the minimum value. To optimize performance
choose the maximum value */

/* The valid key size in bits */
#define SW_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS          512

#define SW_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS         4096
#define SW_RSA_MAX_KEY_GENERATION_SIZE_BITS             4096

/* Define the size of the exponentiation temp buffer, used in LLF_PKI exponentiation and NON DEPENDED on
   width of the sliding window. The size defined in units equaled to maximal RSA modulus size */
#define PKI_EXP_CONST_TEMP_BUFF_SIZE_IN_MODULUS_UNITS  7

#define PKI_EXP_SLIDING_WINDOW_MAX_VALUE  2

	/* The maximum buffer size for the 'H' value */
#define SW_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS ((SW_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS + 64UL ) / 32 )


/* definition of PKI_KEY_GEN_TEMP_BUFF_SIZE_WORDS IS DEPENDED on width of the sliding window*/
#if( PKI_EXP_SLIDING_WINDOW_MAX_VALUE > 2 )
#define PKI_KEY_GEN_TEMP_BUFF_SIZE_WORDS \
	((4 + (1<<(PKI_EXP_SLIDING_WINDOW_MAX_VALUE-2))) * SW_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS)
#else
#define PKI_KEY_GEN_TEMP_BUFF_SIZE_WORDS \
	(16 * SW_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS)
#endif

#ifndef PKI_EXP_WINDOW_TEMP_BUFFER_SIZE_IN_MODULUS_UNITS
#define PKI_EXP_WINDOW_TEMP_BUFFER_SIZE_IN_MODULUS_UNITS  (3 + (1 << (PKI_EXP_SLIDING_WINDOW_MAX_VALUE-1)))
#endif


/* Define the size of the temp buffer, used in LLF_PKI exponentiation and DEPENDED on
   width of the sliding window in words */
#if (PKI_EXP_CONST_TEMP_BUFF_SIZE_IN_MODULUS_UNITS > PKI_EXP_WINDOW_TEMP_BUFFER_SIZE_IN_MODULUS_UNITS )
#define PKI_EXP_TEMP_BUFFER_SIZE_IN_WORDS  \
	(PKI_EXP_CONST_TEMP_BUFF_SIZE_IN_MODULUS_UNITS * SW_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS + 2 )
#else
#define PKI_EXP_TEMP_BUFFER_SIZE_IN_WORDS  \
	(PKI_EXP_WINDOW_TEMP_BUFFER_SIZE_IN_MODULUS_UNITS * SW_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS + 2 )
#endif

/* the RSA data type */
typedef struct SwSharedRSAPrimeData_t {
	/* The aligned input and output data buffers */
	uint32_t DataIn[SW_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
	uint32_t DataOut[SW_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];

	/* #include specific fields that are used by the low level */
	struct {
		union {
			struct { /* Temporary buffers used for the exponent calculation */
				uint32_t Tempbuff1[PKI_EXP_TEMP_BUFFER_SIZE_IN_WORDS];
				uint32_t Tempbuff2[SW_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 2];
				/* Temporary buffer for self-test support */
				uint32_t TempBuffer[SW_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
			}NonCrt;

			struct { /* Temporary buffers used for the exponent calculation */
				uint32_t Tempbuff1[PKI_EXP_TEMP_BUFFER_SIZE_IN_WORDS];
				uint32_t Tempbuff2[SW_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 2];
			}Crt;
		}Data;
	}LLF;

}SwSharedRSAPrimeData_t;




#ifdef __cplusplus
}
#endif
#endif
