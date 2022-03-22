/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_FIPS_ERROR_H
#define SaSi_FIPS_ERROR_H

/* !
@file
@brief This file contains error codes definitions for SaSi FIPS module.
*/
#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */
/* FIPS module on the SaSi layer base address - 0x00F01700 */
#define SaSi_FIPS_ERROR (SaSi_FIPS_MODULE_ERROR_BASE + 0x00UL)

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  *************************** */

/* *********************** Public Variables ******************* */

/* *********************** Public Functions ******************* */

#ifdef __cplusplus
}
#endif

#endif
