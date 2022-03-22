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
#include "cc_util_defs.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "sym_adaptor_driver.h"
#include "cc_util_error.h"
#include "cc_sym_error.h"
#include "cc_context_relocation.h"
#include "cc_common.h"
#include "cc_common_math.h"
#include "cc_rnd.h"
#include "cc_rnd_error.h"
#include "cc_hal.h"
#include "cc_util_cmac.h"

/*!
 * Converts Symmetric Adaptor return code to CC error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CCError_t one of CC_* error codes defined in cc_error.h
 */
static CCUtilError_t SymAdaptor2CmacDeriveKeyErr(int symRetCode)
{
        switch (symRetCode) {
        case CC_RET_INVARG:
                return CC_UTIL_ILLEGAL_PARAMS_ERROR;
        case CC_RET_INVARG_BAD_ADDR:
                return CC_UTIL_BAD_ADDR_ERROR;
        case CC_RET_INVARG_CTX:
        case CC_RET_UNSUPP_ALG:
        default:
                return CC_UTIL_FATAL_ERROR;
        }
}


/************************************************************************************/
/****************         CMAC key derivation    ************************************/
/************************************************************************************/

CCUtilError_t UtilCmacDeriveKey(UtilKeyType_t    	keyType,
				CCAesUserKeyData_t     	*pUserKey,
				uint8_t			*pDataIn,
				size_t                	dataInSize,
				CCUtilAesCmacResult_t   pCmacResult)
{
        int symRc;
        uint32_t error = 0;
        uint32_t ctxBuff[CC_UTIL_BUFF_IN_WORDS];

        struct drv_ctx_cipher *pAesContext = (struct drv_ctx_cipher *)RcInitUserCtxLocation(ctxBuff,
                                                                                             CC_UTIL_BUFF_IN_BYTES,
                                                                                             sizeof(struct drv_ctx_cipher));
        if (pAesContext == NULL) {
                return CC_UTIL_ILLEGAL_PARAMS_ERROR;
        }

        /* Check inputs */
        if (NULL == pDataIn) {
                return CC_UTIL_DATA_IN_POINTER_INVALID_ERROR;
        }
        if (NULL == pCmacResult) {
                return CC_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
        }
        if ((dataInSize < CC_UTIL_CMAC_DERV_MIN_DATA_IN_SIZE) ||
            (dataInSize > CC_UTIL_CMAC_DERV_MAX_DATA_IN_SIZE)) {
                return CC_UTIL_DATA_IN_SIZE_INVALID_ERROR;
        }


        switch(keyType){
	case UTIL_ROOT_KEY:
		/* Check KDR error bit in LCS register */
		CC_UTIL_IS_OTP_KDR_ERROR(error);
		if (error != 0)
			return CC_UTIL_KDR_INVALID_ERROR;

		/* Set AES key to ROOT KEY */
		pAesContext->crypto_key_type = DRV_ROOT_KEY;
		pAesContext->key_size = CC_AES_256_BIT_KEY_SIZE;
		break;

	case UTIL_SESSION_KEY:
		/* Check session key validity */
		CC_UTIL_IS_SESSION_KEY_VALID(error);
		if ( error == CC_UTIL_SESSION_KEY_IS_UNSET)
			return CC_UTIL_SESSION_KEY_ERROR;

		/* Set AES key to SESSION KEY */
		pAesContext->crypto_key_type = DRV_SESSION_KEY;
		pAesContext->key_size = CC_AES_128_BIT_KEY_SIZE;
		break;

	case UTIL_USER_KEY:
		if (pUserKey == NULL) {
			return CC_UTIL_DATA_IN_POINTER_INVALID_ERROR;
		}
		if ( (pUserKey->keySize != CC_AES_128_BIT_KEY_SIZE) &&
		     (pUserKey->keySize != CC_AES_256_BIT_KEY_SIZE) )
			return CC_UTIL_INVALID_USER_KEY_SIZE;

		/* Set AES key to USER KEY, and copy the key to the context */
		pAesContext->crypto_key_type = DRV_USER_KEY;
		pAesContext->key_size = pUserKey->keySize;
		CC_PalMemCopy(pAesContext->key, pUserKey->pKey, pUserKey->keySize);
		break;
	default:
		return CC_UTIL_INVALID_KEY_TYPE;
	}


	pAesContext->alg = DRV_CRYPTO_ALG_AES;
	pAesContext->mode = DRV_CIPHER_CMAC;
	pAesContext->direction = DRV_CRYPTO_DIRECTION_ENCRYPT;
	CC_PalMemSetZero(pAesContext->block_state, CC_AES_BLOCK_SIZE);

	symRc = SymDriverAdaptorInit((uint32_t *)pAesContext, pAesContext->alg, pAesContext->mode);
	if (symRc != 0) {
		return SymAdaptor2CmacDeriveKeyErr(symRc);
	}


	/* call SymDriverAdaptorFinalize with CMAC:  set the data unit size if first block */
	pAesContext->data_unit_size = dataInSize;
	symRc = SymDriverAdaptorFinalize((uint32_t *)pAesContext,
					 pDataIn, (void *)pCmacResult, dataInSize, pAesContext->alg);

	if (symRc != 0) {
		return SymAdaptor2CmacDeriveKeyErr(symRc);
	}



        return CC_UTIL_OK;
}


