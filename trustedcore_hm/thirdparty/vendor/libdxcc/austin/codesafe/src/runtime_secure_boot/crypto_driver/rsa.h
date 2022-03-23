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

#ifndef RSA_H
#define RSA_H

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */

#include "crypto_driver_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  Sun Feb 20 14:11:42 2005
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief A brief description of this module
 *
 *  \version RSA.h#1:incl:1
 *  \author adams
 *  \remarks Copyright (C) 2004 by Discretix Technologies Ltd.
 *           All Rights reserved
 */

/* *********************** Defines **************************** */

#define DX_BOOT_RSA_VERIFIER_ALG_FAILURE DX_SB_RSA_BASE_ERROR + 0x00000001
#define DX_BOOT_RSA_VERIFIER_CMP_FAILURE DX_SB_RSA_BASE_ERROR + 0x00000002

/* the modulus size ion bits */
#define RSA_MOD_SIZE_IN_BITS    2048UL
#define RSA_MOD_SIZE_IN_BYTES   (RSA_MOD_SIZE_IN_BITS / 8)
#define RSA_MOD_SIZE_IN_WORDS   (RSA_MOD_SIZE_IN_BITS / 32)
#define RSA_MOD_SIZE_IN_256BITS (RSA_MOD_SIZE_IN_BITS / 256)
#define RSA_EXP_SIZE_IN_BITS    17UL
#define RSA_EXP_SIZE_IN_BYTES   ((RSA_EXP_SIZE_IN_BITS + 7) / 8)

/* size of buffer for Barrett modulus tag NP, used in PKA algorithms */
#define RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_BITS  132
#define RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_BYTES ((RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_BITS + 7) / 8)
#define RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_WORDS ((RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_BYTES + 3) / 4)

/* the exponent */
#ifndef BIG__ENDIAN
#define RSA_EXP_VAL 0x00010001UL
#else
#define RSA_EXP_VAL 0x01000100UL
#endif

#define RSA_PUB_KEY_VALIDATION_TAG 0x13579BDF

/* RSA PSS verify definitions */
#define RSA_PSS_SALT_LENGTH 32
#define RSA_PSS_PAD1_LEN    8

#define RSA_PKCS1_VER15 1
#define RSA_PKCS1_VER21 1

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  *************************** */

/* *********************** Public Variables ******************* */

/* ************************************************************ */

#ifdef __cplusplus
}
#endif

#endif
