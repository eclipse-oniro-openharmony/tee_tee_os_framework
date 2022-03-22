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

#ifndef LLF_PKI_PRIV_KEY_DB_DEF_H
#define LLF_PKI_PRIV_KEY_DB_DEF_H

/*
 * This file is #included in the middle of the struct declaration for CRYSRSAPrivKey_t
 * It contains the platform-specific parts of the context struct. As such:
 *
 *  1) file should not use any includes it is a part of the crys_rsa_types.h file !!!!
 *  2) only the crys_rsa_types.h file should include this file.
 */

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  13 Jan 2008
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief A brief description of this module
 *
 *  \version LLF_RSA_priv_key_db_def.h#1:incl:1
 *  \author adams, R.Levin
 */

typedef union {
    struct {
        /* the Barrett mod N tag  NP for N-modulus - used in the modular multiplication and
           exponentiation, calculated in CRYS_RSA_Build_PrivKey function */
        uint32_t NP[LLF_PKI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];

    } NonCrt;

    struct {
        /* the Barrett mod P tag  PP for P-factor - used in the modular multiplication and
           exponentiation, calculated in CRYS_RSA_Build_PrivKey function */
        uint32_t PP[LLF_PKI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];

        /* the Barrett mod Q tag  QP for Q-factor - used in the modular multiplication and
           exponentiation, calculated in CRYS_RSA_Build_PubKey function */
        uint32_t QP[LLF_PKI_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS];

    } Crt;

} LLF_pki_priv_key_db_t;

#endif
