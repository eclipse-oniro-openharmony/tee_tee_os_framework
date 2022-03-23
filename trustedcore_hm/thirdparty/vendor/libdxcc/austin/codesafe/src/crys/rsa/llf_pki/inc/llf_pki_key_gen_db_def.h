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

#ifndef LLF_PKI_RSA_KEY_GEN_DB_DEF_H
#define LLF_PKI_RSA_KEY_GEN_DB_DEF_H

/*
 * This file is #included in the middle of the struct declaration for CRYS_KGPrimeData_t
 * It contains the platform-specific parts of the context struct. As such:
 *
 *  1) file should not use any includes it is a part of the crys_rsa_types.h file !!!!
 *  2) only the crys_rsa_types.h file should include this file.
 */

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  Sun Dec 12 09:23:41 2004
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief A brief description of this module
 *
 *  \version LLF_RSA_pub_key_db_def.h#1:incl:1
 *  \author adams
 */

typedef struct {
    uint32_t temp[2 * CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS];
} LLF_pki_key_gen_db_t;

#endif
