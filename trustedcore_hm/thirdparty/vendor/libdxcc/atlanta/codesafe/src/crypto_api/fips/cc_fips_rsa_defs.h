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

#ifndef  _CC_FIPS_RSA_DEFS_H
#define  _CC_FIPS_RSA_DEFS_H


#include "cc_rnd.h"
#include "cc_rsa_types.h"
#include "cc_rsa_schemes.h"


/*****************************************************************************/
/**
 * The function runs the conditional test for RSA key generation
 *
 *
 * @param pRndContext - pointer to RND context
 * @param pCcUserPrivKey - pointer to the private key data structure
 * @param pCcUserPubKey  - pointer to the public key data structure
 * @param pFipsCtx  - pointer to RSA fips structure used for conditional test
 *
 * @return CCError_t
 */
CCError_t CC_FipsRsaConditionalTest(CCRndContext_t 	*pRndContext,
				CCRsaUserPrivKey_t 	*pCcUserPrivKey,
				CCRsaUserPubKey_t  	*pCcUserPubKey,
				CCRsaKgFipsContext_t    *pFipsCtx);



/*****************************************************************************/
/**
 * The function runs the conditional test for RSA key generation
 *
 *
 * @param pRndContext - pointer to RND context
 * @param pFipsCtx  - pointer to RSA fips structure used for KAT test
 *
 * @return CCError_t
 */
CCFipsError_t CC_FipsRsaKat(CCRndContext_t *rndContext_ptr,
			CCRsaFipsKatContext_t    *pFipsCtx);


#endif  // _CC_FIPS_RSA_DEFS_H

