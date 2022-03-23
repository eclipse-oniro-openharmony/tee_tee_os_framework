/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_ECC_25519_ERROR_H
#define SaSi_ECC_25519_ERROR_H

/*
 *  Object % sasi_ecc_25519_error.h    : %
 *  State           :  %state%
 *  Creation date   :  09/02/ 2015
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief This module containes the definitions of the SaSi ECC-25519 errors.
 *
 *  \version sasi_ecc_25519_error.h#1:incl:1
 *  \author R.Levin
 */
/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

/* *********************************************************************************************************
 * SaSi ECC-25519 TWEET NACL MODULE ERRORS    base address - 0x00F02100                   *
 * ******************************************************************************************************* */
/* The SaSi ECPKI GEN KEY PAIR module errors */
#define SaSi_EC_EDW_INVALID_INPUT_POINTER_ERROR (SaSi_ECPKI_MODULE_ERROR_BASE + 0x00UL)
#define SaSi_EC_EDW_INVALID_INPUT_SIZE_ERROR    (SaSi_ECPKI_MODULE_ERROR_BASE + 0x01UL)

#define SaSi_EC_MONT_INVALID_INPUT_POINTER_ERROR (SaSi_ECPKI_MODULE_ERROR_BASE + 0x10UL)
#define SaSi_EC_MONT_INVALID_INPUT_SIZE_ERROR    (SaSi_ECPKI_MODULE_ERROR_BASE + 0x11UL)
#define SaSi_EC_MONT_INVALID_DOMAIN_ID_ERROR     (SaSi_ECPKI_MODULE_ERROR_BASE + 0x12UL)

/* ***********************************************************************************************************
 *    NOT SUPPORTED MODULES ERROR IDs                                                                       *
 * ********************************************************************************************************* */
#define SaSi_EC_MONT_IS_NOT_SUPPORTED (SaSi_ECPKI_MODULE_ERROR_BASE + 0xFEUL)
#define SaSi_EC_EDW_IS_NOT_SUPPORTED  (SaSi_ECPKI_MODULE_ERROR_BASE + 0xFFUL)

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
