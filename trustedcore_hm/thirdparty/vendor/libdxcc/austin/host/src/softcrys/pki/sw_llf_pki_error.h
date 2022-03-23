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

#ifndef LLF__PKI_ERROR_H
#define LLF__PKI_ERROR_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "crys_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Object % LLF_PKI_error.h    : %
 *  State           :  %state%
 *  Creation date   :  Sun Nov 21 11:07:08 2004
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief The error definitions of the LLF PKI module
 *
 *  \version sw_llf_pki_error.h#1:incl:1
 *  \author adams
 */

/* *********************** Defines **************************** */

#define SW_LLF_PKI_KEY_GENERATION_FAILURE (LLF_PKI_MODULE_ERROR_BASE + 0x0UL)

#define SW_LLF_PKI_CONVERT_PRIV_KEY_TO_CRT_NOT_SUPPORTED     (LLF_PKI_MODULE_ERROR_BASE + 0x10UL)
#define SW_LLF_PKI_CONVERT_PRIV_KEY_TO_CRT_FACTORS_NOT_FOUND (LLF_PKI_MODULE_ERROR_BASE + 0x11UL)
#define SW_LLF_PKI_COUNTERMEASURES_DFA_FAIL_ERROR            (LLF_PKI_MODULE_ERROR_BASE + 0x12UL)
#define SW_LLF_PKI_RSA_CRT_MODE_NOT_SUPPORTED                (LLF_PKI_MODULE_ERROR_BASE + 0x13UL)

#ifdef __cplusplus
}
#endif

#endif
