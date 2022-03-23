/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#ifndef _CC_PKA_DEFS_HW_H_
#define _CC_PKA_DEFS_HW_H_

#include "cc_pal_types.h"
#include "cc_pka_hw_plat_defs.h"

/*!
@file
@brief Contains all of the enums and definitions that are used in the PKA related code.
*/


/* The valid key sizes in bits for RSA primitives (exponentiation) */
#define CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS ((CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS + CC_PKA_WORD_SIZE_IN_BITS) / CC_BITS_IN_32BIT_WORD )
#define CC_ECPKI_MODUL_MAX_LENGTH_IN_BITS   521

/*! size of buffers for Barrett modulus tag NP, used in PKI algorithms. */
#define CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS 5
#define CC_PKA_ECPKI_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS  CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS

#define CC_PKA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS CC_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS

#define CC_PKA_PUB_KEY_BUFF_SIZE_IN_WORDS (2*CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS)

#define CC_PKA_PRIV_KEY_BUFF_SIZE_IN_WORDS (2*CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS)

#define CC_PKA_KGDATA_BUFF_SIZE_IN_WORDS   (3*CC_PKA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS)


/*! The valid maximum EC modulus size in 32-bit words. */
#define CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS  18 /*!< \internal [(CC_ECPKI_MODUL_MAX_LENGTH_IN_BITS + 31)/(sizeof(uint32_t)) + 1] */
#define CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS  (CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1)

#define CC_PKA_DOMAIN_BUFF_SIZE_IN_WORDS (2*CC_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS)


/* ECC NAF buffer definitions */
#define COUNT_NAF_WORDS_PER_KEY_WORD  8  /*!< \internal Change according to NAF representation (? 2)*/
#define CC_PKA_ECDSA_NAF_BUFF_MAX_LENGTH_IN_WORDS (COUNT_NAF_WORDS_PER_KEY_WORD*CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + 1)

#ifndef CC_SUPPORT_ECC_SCA_SW_PROTECT
/* on fast SCA non protected mode required additional buffers for NAF key */
#define CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS (CC_PKA_ECDSA_NAF_BUFF_MAX_LENGTH_IN_WORDS + CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 2)
#else
#define CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS  1 /*(4*CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS)*/
#endif

#define CC_PKA_ECPKI_BUILD_TMP_BUFF_MAX_LENGTH_IN_WORDS (3*CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS+CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define CC_PKA_ECDSA_SIGN_BUFF_MAX_LENGTH_IN_WORDS (6*CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS+CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define CC_PKA_ECDH_BUFF_MAX_LENGTH_IN_WORDS (2*CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define CC_PKA_KG_BUFF_MAX_LENGTH_IN_WORDS (2*CC_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + CC_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define CC_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS (3*CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS)

#endif /*_CC_PKA_DEFS_HW_H_*/

