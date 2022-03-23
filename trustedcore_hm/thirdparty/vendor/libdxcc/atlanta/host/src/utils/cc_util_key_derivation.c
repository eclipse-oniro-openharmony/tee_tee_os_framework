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


/************* Include Files ****************/
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_util_int_defs.h"
#include "cc_sym_error.h"
#include "cc_aes.h"
#include "cc_util_defs.h"
#include "cc_util_error.h"
#include "cc_util_key_derivation.h"
#include "cc_hal_plat.h"
#include "cc_regs.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_util_cmac.h"
#include "cc_fips_defs.h"

CCUtilError_t CC_UtilKeyDerivation(	CCUtilKeyType_t       keyType,
					CCAesUserKeyData_t    *pUserKey,
					const uint8_t     	*pLabel,
					size_t         		labelSize,
					const uint8_t   	*pContextData,
					size_t         		contextSize,
					uint8_t			*pDerivedKey,
					size_t 	 		derivedKeySize)
{
	uint32_t rc = 0;
	uint32_t dataSize, i, iterationNum, numIteration, bytesToCopy;
	uint8_t	dataIn[CC_UTIL_MAX_KDF_SIZE_IN_BYTES] = {0};
	uint8_t tmp[CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES];
	size_t length, lengthReverse;
	UtilKeyType_t       utilKeyType;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	/* Check key type */
	switch(keyType){
	case CC_UTIL_ROOT_KEY:
		utilKeyType = UTIL_ROOT_KEY;
		break;
	case CC_UTIL_USER_KEY:
		if (!pUserKey) {
			return CC_UTIL_INVALID_KEY_TYPE;
		}
		if (!pUserKey->pKey) {
			return CC_UTIL_INVALID_KEY_TYPE;
		}
		utilKeyType = UTIL_USER_KEY;
		break;
	default:
		return CC_UTIL_INVALID_KEY_TYPE;
	}

	/* Check Label, Context, DerivedKey sizes */
	if (derivedKeySize > CC_UTIL_MAX_DERIVED_KEY_SIZE_IN_BYTES)
		return CC_UTIL_ILLEGAL_PARAMS_ERROR;

	if ( ((labelSize != 0) && (pLabel == NULL)) ||
	     (labelSize == 0) ||
	     (labelSize > CC_UTIL_MAX_LABEL_LENGTH_IN_BYTES) ){
		return CC_UTIL_ILLEGAL_PARAMS_ERROR;
	}

	if ( ((contextSize != 0) && (pContextData == NULL)) ||
	     (contextSize == 0) ||
	     (contextSize > CC_UTIL_MAX_CONTEXT_LENGTH_IN_BYTES) ) {
		return CC_UTIL_ILLEGAL_PARAMS_ERROR;
	}

	/* Generate dataIn buffer for CMAC: iteration || Label || 0x00 || context || length */

	i = 1;
	numIteration = (derivedKeySize+CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES-1) / CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES;
	length = derivedKeySize*8;
	if (length > 0xFF)
		dataSize = CC_UTIL_FIX_DATA_MAX_SIZE_IN_BYTES;
	else
		dataSize = CC_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES;

	dataSize += labelSize+contextSize;

	if (labelSize!=0){
		CC_PalMemCopy((uint8_t*)&dataIn[i], pLabel, labelSize);
		i+=labelSize;
	}

	dataIn[i++] = 0x00;

	if (contextSize!=0){
		CC_PalMemCopy((uint8_t*)&dataIn[i], pContextData, contextSize);
		i+=contextSize;
	}

	if (length > 0xFF){

		/* Reverse words order and bytes in each word */
		lengthReverse = ((length & 0xFF00)>>8) | ((length & 0xFF)<<8);
		CC_PalMemCopy((uint8_t*)&dataIn[i], (uint8_t*)&lengthReverse, 2);
	}
	else
		CC_PalMemCopy((uint8_t*)&dataIn[i], (uint8_t*)&length, 1);

	for(iterationNum = 0; iterationNum < numIteration; iterationNum++){
		dataIn[0] = iterationNum+1;
		rc = UtilCmacDeriveKey(utilKeyType, pUserKey, dataIn, dataSize, tmp);
		if (rc != CC_SUCCESS)
			return rc;

		/* concatenate the latest PRF result */
		/* copy only number of bits that required... */
		if (derivedKeySize > CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES){
			bytesToCopy = CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES;
			derivedKeySize -= CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES;
		} else
			bytesToCopy = derivedKeySize;

                CC_PalMemCopy((uint8_t*)&pDerivedKey[iterationNum*CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES],
                        tmp, bytesToCopy);
	}

	return rc;
}

