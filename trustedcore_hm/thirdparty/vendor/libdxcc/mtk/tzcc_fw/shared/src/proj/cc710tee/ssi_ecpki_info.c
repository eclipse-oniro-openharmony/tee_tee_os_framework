/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* this file contains the definitions of the hashes used in the ecpki */

#include "sasi_ecpki_local.h"
#include "sasi_hash.h"
#include "sasi_ecpki_types.h"
#include "ssi_ecpki_domains_defs.h"
#include "ssi_ecpki_domain_secp160k1.h"
#include "ssi_ecpki_domain_secp160r2.h"
#include "ssi_ecpki_domain_secp192r1.h"
#include "ssi_ecpki_domain_secp224r1.h"
#include "ssi_ecpki_domain_secp256r1.h"
#include "ssi_ecpki_domain_secp521r1.h"
#include "ssi_ecpki_domain_secp160r1.h"
#include "ssi_ecpki_domain_secp192k1.h"
#include "ssi_ecpki_domain_secp224k1.h"
#include "ssi_ecpki_domain_secp256k1.h"
#include "ssi_ecpki_domain_secp384r1.h"

const ecpki_hash_t ecpki_hash_info[SaSi_ECPKI_HASH_NumOfModes] = {
    /* SaSi_ECPKI_HASH_SHA1_mode         */ { SaSi_HASH_SHA1_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA1_mode },
    /* SaSi_ECPKI_HASH_SHA224_mode       */ { SaSi_HASH_SHA224_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA224_mode },
    /* SaSi_ECPKI_HASH_SHA256_mode       */ { SaSi_HASH_SHA256_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA256_mode },
    /* SaSi_ECPKI_HASH_SHA384_mode       */ { SaSi_HASH_SHA384_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA384_mode },
    /* SaSi_ECPKI_HASH_SHA512_mode       */ { SaSi_HASH_SHA512_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA512_mode },
    /* SaSi_ECPKI_AFTER_HASH_SHA1_mode   */ { SaSi_HASH_SHA1_DIGEST_SIZE_IN_WORDS, SaSi_HASH_NumOfModes },
    /* SaSi_ECPKI_AFTER_HASH_SHA224_mode */ { SaSi_HASH_SHA224_DIGEST_SIZE_IN_WORDS, SaSi_HASH_NumOfModes },
    /* SaSi_ECPKI_AFTER_HASH_SHA256_mode */ { SaSi_HASH_SHA256_DIGEST_SIZE_IN_WORDS, SaSi_HASH_NumOfModes },
    /* SaSi_ECPKI_AFTER_HASH_SHA384_mode */ { SaSi_HASH_SHA384_DIGEST_SIZE_IN_WORDS, SaSi_HASH_NumOfModes },
    /* SaSi_ECPKI_AFTER_HASH_SHA512_mode */ { SaSi_HASH_SHA512_DIGEST_SIZE_IN_WORDS, SaSi_HASH_NumOfModes },
};

const uint8_t ecpki_supported_hash_modes[SaSi_ECPKI_HASH_NumOfModes] = {
    /* SaSi_ECPKI_HASH_SHA1_mode         */ SASI_TRUE,
    /* SaSi_ECPKI_HASH_SHA224_mode       */ SASI_TRUE,
    /* SaSi_ECPKI_HASH_SHA256_mode       */ SASI_TRUE,
    /* SaSi_ECPKI_HASH_SHA384_mode       */ SASI_TRUE,
    /* SaSi_ECPKI_HASH_SHA512_mode       */ SASI_TRUE,
    /* SaSi_ECPKI_AFTER_HASH_SHA1_mode   */ SASI_TRUE,
    /* SaSi_ECPKI_AFTER_HASH_SHA224_mode */ SASI_TRUE,
    /* SaSi_ECPKI_AFTER_HASH_SHA256_mode */ SASI_TRUE,
    /* SaSi_ECPKI_AFTER_HASH_SHA384_mode */ SASI_TRUE,
    /* SaSi_ECPKI_AFTER_HASH_SHA512_mode */ SASI_TRUE
};

const getDomainFuncP ecDomainsFuncP[SaSi_ECPKI_DomainID_OffMode] = {
    (&SaSi_ECPKI_GetSecp160k1DomainP), (&SaSi_ECPKI_GetSecp160r1DomainP), (&SaSi_ECPKI_GetSecp160r2DomainP),
    (&SaSi_ECPKI_GetSecp192k1DomainP), (&SaSi_ECPKI_GetSecp192r1DomainP), (&SaSi_ECPKI_GetSecp224k1DomainP),
    (&SaSi_ECPKI_GetSecp224r1DomainP), (&SaSi_ECPKI_GetSecp256k1DomainP), (&SaSi_ECPKI_GetSecp256r1DomainP),
    (&SaSi_ECPKI_GetSecp384r1DomainP), (&SaSi_ECPKI_GetSecp521r1DomainP)
};
