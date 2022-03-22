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

#ifndef LLF_RND_ERROR_H
#define LLF_RND_ERROR_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "crys_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Object % LLF_RND_error.h    : %
 *  State           :  %state%
 *  Creation date   :  Sun Nov 21 11:07:08 2004
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief The error definitions of the LLF RND module
 *
 *  \version LLF_RND_error.h#1:incl:1
 *  \author
 */

/* *********************** Defines **************************** */
/* * RND module on the LLF layer base address -  0x00F10C00     */

#define LLF_RND_HW_VERSION_NOT_CORRECT_ERROR (LLF_RND_MODULE_ERROR_BASE + 0x0UL)
#define LLF_RND_CPRNG_TEST_FAIL_ERROR        (LLF_RND_MODULE_ERROR_BASE + 0x1UL)
#define LLF_RND_CTRNG_TEST_FAIL_ERROR        (LLF_RND_MODULE_ERROR_BASE + 0x2UL)
#define LLF_RND_STATE_PTR_INVALID_ERROR      (LLF_RND_MODULE_ERROR_BASE + 0x3UL)
#define LLF_RND_AES_256_NOT_SUPPORTED_ERROR  (LLF_RND_MODULE_ERROR_BASE + 0x4UL)

#define LLF_RND_TRNG_TIME_LIMIT_EXCEEDED_ERROR    (LLF_RND_MODULE_ERROR_BASE + 0x20UL)
#define LLF_RND_TRNG_ENTR_ESTIM_SIZE_EXCEED_ERROR (LLF_RND_MODULE_ERROR_BASE + 0x21UL)

#define LLF_RND_TRNG_PREVIOUS_PARAMS_NOT_MATCH_ERROR  (LLF_RND_MODULE_ERROR_BASE + 0x30UL)
#define LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR (LLF_RND_MODULE_ERROR_BASE + 0x31UL)
#define LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR   (LLF_RND_MODULE_ERROR_BASE + 0x32UL)
#define LLF_RND_TRNG_LOW_ENTROPY_ERROR                (LLF_RND_MODULE_ERROR_BASE + 0x33UL)
#define LLF_RND_TRNG_NULL_ENTROPY_ERROR               (LLF_RND_MODULE_ERROR_BASE + 0x34UL)
#define LLF_RND_TRNG_ILLEGAL_PTR_ERROR                (LLF_RND_MODULE_ERROR_BASE + 0x35UL)

#ifdef __cplusplus
}
#endif

#endif
