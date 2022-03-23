/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SSI_ECPKI_DOMAIN_SECP224K1_H
#define SSI_ECPKI_DOMAIN_SECP224K1_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "ssi_pal_types.h"
#include "sasi_ecpki_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 @brief    the function returns the domain pointer
 @return   return domain pointer

*/
const SaSi_ECPKI_Domain_t *SaSi_ECPKI_GetSecp224k1DomainP(void);

#ifdef __cplusplus
}
#endif

#endif
