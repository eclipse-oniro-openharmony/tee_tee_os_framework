/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SaSi_PKA_DEFS_HW_H_
#define _SaSi_PKA_DEFS_HW_H_

#include "ssi_pal_types.h"
#include "ssi_pka_hw_plat_defs.h"

/* !
@file
@brief Contains all of the enums and definitions that are used in the PKA related code.
*/

/* The valid key sizes in bits for RSA primitives (exponentiation) */
#define SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS \
    ((SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS + 64) / SASI_BITS_IN_32BIT_WORD)
#define SaSi_ECPKI_MODUL_MAX_LENGTH_IN_BITS 521

/* ! size of buffers for Barrett modulus tag NP, used in PKI algorithms. */
#define SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS       5
#define SaSi_PKA_ECPKI_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS

#define SaSi_PKA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS

#define SaSi_PKA_PUB_KEY_BUFF_SIZE_IN_WORDS (2 * SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS)

#define SaSi_PKA_PRIV_KEY_BUFF_SIZE_IN_WORDS (2 * SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS)

#define SaSi_PKA_KGDATA_BUFF_SIZE_IN_WORDS (3 * SaSi_PKA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS)

/* ! The valid maximum EC modulus size in 32-bit words. */
#define SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS \
    18 /* !< \internal [(SaSi_ECPKI_MODUL_MAX_LENGTH_IN_BITS + 31)/(sizeof(uint32_t)) + 1] */
#define SaSi_ECPKI_ORDER_MAX_LENGTH_IN_WORDS (SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1)

#define SaSi_PKA_DOMAIN_BUFF_SIZE_IN_WORDS (2 * SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS)

#define SaSi_PKA_EL_GAMAL_BUFF_MAX_LENGTH_IN_WORDS (4 * SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 4)

/* ECC NAF buffer definitions */
#define COUNT_NAF_WORDS_PER_KEY_WORD 8 /* !< \internal Change according to NAF representation (? 2) */
#define SaSi_PKA_ECDSA_NAF_BUFF_MAX_LENGTH_IN_WORDS \
    (COUNT_NAF_WORDS_PER_KEY_WORD * SaSi_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + 1)

#ifndef SSI_SUPPORT_ECC_SCA_SW_PROTECT
/* on fast SCA non protected mode required additional buffers for NAF key */
#define SaSi_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS \
    (SaSi_PKA_ECDSA_NAF_BUFF_MAX_LENGTH_IN_WORDS + SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 2)
#else
#define SaSi_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS 1 /* (4*SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS) */
#endif

#define SaSi_PKA_ECPKI_BUILD_TMP_BUFF_MAX_LENGTH_IN_WORDS \
    (3 * SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + SaSi_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define SaSi_PKA_ECDSA_SIGN_BUFF_MAX_LENGTH_IN_WORDS \
    (6 * SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + SaSi_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define SaSi_PKA_ECDH_BUFF_MAX_LENGTH_IN_WORDS \
    (2 * SaSi_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + SaSi_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define SaSi_PKA_KG_BUFF_MAX_LENGTH_IN_WORDS \
    (2 * SaSi_ECPKI_ORDER_MAX_LENGTH_IN_WORDS + SaSi_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS)

#define SaSi_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS (3 * SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS)

#endif /* _SaSi_PKA_DEFS_HW_H_ */
