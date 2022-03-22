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

#ifndef _CC_ECPKI_DOMAIN_DEFS_H
#define _CC_ECPKI_DOMAIN_DEFS_H

/*!
@file
@brief This file contains domains supported by project.
*/


#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_ecpki_domain_secp160k1.h"
#include "cc_ecpki_domain_secp160r2.h"
#include "cc_ecpki_domain_secp192r1.h"
#include "cc_ecpki_domain_secp224r1.h"
#include "cc_ecpki_domain_secp256r1.h"
#include "cc_ecpki_domain_secp521r1.h"
#include "cc_ecpki_domain_secp160r1.h"
#include "cc_ecpki_domain_secp192k1.h"
#include "cc_ecpki_domain_secp224k1.h"
#include "cc_ecpki_domain_secp256k1.h"
#include "cc_ecpki_domain_secp384r1.h"


typedef const CCEcpkiDomain_t * (*getDomainFuncP)(void);

#ifdef __cplusplus
}
#endif

#endif



