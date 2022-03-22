/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef LLF_ECPKI_defs_H
#define LLF_ECPKI_defs_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  18 Sept. 2008
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief A brief description of this module
 *
 *  \version LLF_ECPKI_defs.h#1:incl:1
 *  \author R.Levin
 */

/* *******************    Includes   ************************** */
#include "llf_pki_defs.h"

/* *********************** Defines **************************** */

#define LLF_ECPKI_ENGINE_TYPE CRYS_DEFS_CC6_PKA_ENGINE_TYPE

/* Define the maximal allowed width of the exponentiation sliding window
in range 1...6 for ECC algorithms. This define is actual for projects on
soft platform. To minimize code size use the minimum value. To optimize
the performance choose the maximum value */
#define LLF_ECPKI_EXP_SLIDING_WINDOW_MAX_VALUE LLF_PKI_EXP_SLIDING_WINDOW_MAX_VALUE

/* size of buffer for Barrett modulus tag NP, used in PKI algorithms */
#define LLF_ECPKI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS LLF_PKI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  *************************** */

/* *********************** Public Variables ******************* */

/* *********************** Public Functions ******************* */

#ifdef __cplusplus
}
#endif

#endif
