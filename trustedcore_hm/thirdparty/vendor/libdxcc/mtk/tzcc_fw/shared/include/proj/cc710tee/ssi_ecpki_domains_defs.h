/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_ECPKI_DOMAIN_DEFS_H
#define _SSI_ECPKI_DOMAIN_DEFS_H

/* !
@file
@brief This file contains domains supported by project.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_ecpki_domain_secp160k1.h"
#include "ssi_ecpki_domain_secp160r2.h"
#include "ssi_ecpki_domain_secp192r1.h"
#include "ssi_ecpki_domain_secp224r1.h"
#include "ssi_ecpki_domain_secp256r1.h"
#include "ssi_ecpki_domain_secp521r1.h"
#include "ssi_ecpki_domain_secp160r1.h"
#include "ssi_ecpki_domain_secp192k1.h"
#include "ssi_ecpki_domain_secp224k1.h"
#include "ssi_ecpki_domain_secp256k1.h"
#include "ssi_ecpki_domain_secp384r1.h"

typedef const SaSi_ECPKI_Domain_t *(*getDomainFuncP)(void);

#ifdef __cplusplus
}
#endif

#endif
