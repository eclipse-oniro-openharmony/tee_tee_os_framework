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
#include "cc_plat.h"
#include "cc_pal_dma.h"
#include "cc_util_rpmb_adaptor.h"
#include "cc_util_key_derivation.h"
#include "cc_util_key_derivation_defs.h"
#include "cc_util_defs.h"
#include "cc_fips_defs.h"
#include "cc_pal_mem.h"
#include "cc_util_cmac.h"

/**********************************************************************************/
/****************         RPMB shared secret key functions    *********************/
/**********************************************************************************/

/* Computes and outputs the device RPMB Key based on fixed data & KDR */
CCUtilError_t CC_UtilDeriveRPMBKey(CCUtilRpmbKey_t pRpmbKey)
{
	CCError_t  rc = CC_UTIL_OK;

	uint8_t label[] = {RPMB_KEY_DERIVATION_LABAL};
	uint8_t context[] = {RPMB_KEY_DERIVATION_CONTEXT};

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	/* check parameters validity */
	if (NULL == pRpmbKey)
		return CC_UTIL_DATA_OUT_POINTER_INVALID_ERROR;

	/* The RPMB key derivation function should return error in any life cycle other than DM and SE */
	CC_UTIL_GET_LCS(rc);
	if( (rc != CC_LCS_DEVICE_MANUFACTURE_LCS) && (rc != CC_LCS_SECURE_LCS) )
		return CC_UTIL_ILLEGAL_LCS_FOR_OPERATION_ERR;

	/* invoke KDF with KDR to calculate the first 16 bytes of the key */
	rc = CC_UtilKeyDerivation(CC_UTIL_ROOT_KEY, NULL,
				    (const uint8_t *)&label, sizeof(label),
				    (const uint8_t *)&context, sizeof(context),
				    pRpmbKey, 2*CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES);
	if (rc != CC_UTIL_OK)
		return rc;

	return rc;
}


/* Receives a list of data frames, each 284 bytes long, as described in [JESD84], and
   calculates an HMAC-SHA256 authentication code of the callers' data buffers using RPMB key. */
CCUtilError_t CC_UtilSignRPMBFrames(unsigned long *pListOfDataFrames,
					size_t       		    listSize,
					CCUtilHmacResult_t 		pHmacResult)
{
	CCError_t  rc = CC_UTIL_OK;
	CCUtilRpmbKey_t  rpmbKey;
	CCHmacUserContext_t  UserContext;
	int i=0, size;
	CCHashResultBuf_t tempHashRes;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	/* check parameters validity */
	if ((NULL == pListOfDataFrames) || (NULL == pHmacResult))
		return CC_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
	if ((listSize < CC_UTIL_MIN_RPMB_DATA_BUFFERS) ||
	   (listSize > CC_UTIL_MAX_RPMB_DATA_BUFFERS))
		return CC_UTIL_ILLEGAL_PARAMS_ERROR;

	/* compute the device RPMB key */
	rc = CC_UtilDeriveRPMBKey(rpmbKey);

	/* in case of a single frame, perform an integrated HMAC flow */
	if (listSize == 1) {
		rc = CC_Hmac(CC_HASH_SHA256_mode, rpmbKey, sizeof(CCUtilRpmbKey_t),
						(uint8_t *)(pListOfDataFrames[0]), CC_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES, tempHashRes);
		if (rc == CC_OK){ //only on success copy the result
			CC_PalMemCopy(pHmacResult, tempHashRes, sizeof(CCUtilHmacResult_t));
		}
		return rc;
	}

	/* else,
	   join 64 data frames together to one chunk (284*64) to perform hash update,
	   only last chunk (<= 64 frames) should do finalize */

	/* initializes the HMAC machine on the CC level */
	rc = CC_HmacInit(&UserContext, CC_HASH_SHA256_mode, rpmbKey, sizeof(CCUtilRpmbKey_t));
	if (rc != CC_OK)
			return rc;

	while (listSize) {
		size = min(listSize,RPMB_MAX_BLOCKS_PER_UPDATE);

		/* performs a HASH update on each chunk (create up to 128 MLLI entries) */
		rc = RpmbHmacUpdate(&UserContext, &pListOfDataFrames[i], size);
		if(rc != CC_OK)
			return rc;

		i += size;
		listSize -= size;
	}

	/* finalizes the HMAC processing of a all data blocks */
	rc = RpmbHmacFinish(&UserContext, tempHashRes);
	if (rc == CC_OK){ //only on success copy the result
		CC_PalMemCopy(pHmacResult, tempHashRes, sizeof(CCUtilHmacResult_t));
	}

	return rc;

}



