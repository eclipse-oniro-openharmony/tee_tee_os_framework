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

#ifndef LLF_PKI_DEFS_H
#define LLF_PKI_DEFS_H

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
 *  \version LLF_PKI_defs.h#1:incl:1
 *  \author R.Levin
 */

/* *********************** Defines **************************** */

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  *************************** */

/* *********************** Public Variables ******************* */

/* *********************** Public Functions ******************* */

/* Define the maximal allowed width of the exponentiation sliding window
in range 1...6. This define is actual for projects on soft platform.
To minimize code size use the minimum value. To optimize performance
choose the maximum value */
#define LLF_PKI_EXP_SLIDING_WINDOW_MAX_VALUE 6

/* size of buffer for Barrett modulus tag NP, used in PKI algorithms */
#define LLF_PKI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS 5

#ifdef __cplusplus
}
#endif

#endif
