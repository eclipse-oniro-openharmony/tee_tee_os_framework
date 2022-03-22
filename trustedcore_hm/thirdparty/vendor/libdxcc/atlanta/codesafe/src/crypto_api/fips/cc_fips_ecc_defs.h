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

#ifndef  _CC_FIPS_ECC_DEFS_H
#define  _CC_FIPS_ECC_DEFS_H

#include "cc_rnd.h"
#include "cc_ecpki_types.h"
#include "cc_ecpki_ecdsa.h"


CCError_t CC_FipsEccConditionalTest(CCRndContext_t         *pRndContext,
				CCEcpkiUserPrivKey_t   *pUserPrivKey,
				CCEcpkiUserPublKey_t   *pUserPublKey,
				CCEcpkiKgFipsContext_t   *pFipsCtx);


CCFipsError_t CC_FipsEcdsaKat(CCRndContext_t *pRndContext,
			    CCEcdsaFipsKatContext_t    *pFipsCtx);


CCFipsError_t CC_FipsEcdhKat(CCEcdhFipsKatContext_t    *pFipsCtx);

#endif  // _CC_FIPS_ECC_DEFS_H

