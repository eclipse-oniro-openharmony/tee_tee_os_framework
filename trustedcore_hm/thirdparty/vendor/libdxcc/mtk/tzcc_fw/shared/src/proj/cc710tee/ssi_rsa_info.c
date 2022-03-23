/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* this file contains the definitions of the hashes used in the rsa */

#include "sasi_rsa_local.h"
#include "sasi_hash.h"
#include "sasi_rsa_types.h"

const rsa_hash_t rsa_hash_info[SaSi_RSA_HASH_NumOfModes] = {
    /* SaSi_RSA_HASH_MD5_mode          */ { SaSi_HASH_MD5_DIGEST_SIZE_IN_WORDS, SaSi_HASH_MD5_mode },
    /* SaSi_RSA_HASH_SHA1_mode         */ { SaSi_HASH_SHA1_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA1_mode },
    /* SaSi_RSA_HASH_SHA224_mode       */ { SaSi_HASH_SHA224_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA224_mode },
    /* SaSi_RSA_HASH_SHA256_mode       */ { SaSi_HASH_SHA256_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA256_mode },
    /* SaSi_RSA_HASH_SHA384_mode       */ { SaSi_HASH_SHA384_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA384_mode },
    /* SaSi_RSA_HASH_SHA512_mode       */ { SaSi_HASH_SHA512_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA512_mode },
    /* SaSi_RSA_After_MD5_mode         */ { SaSi_HASH_MD5_DIGEST_SIZE_IN_WORDS, SaSi_HASH_MD5_mode },
    /* SaSi_RSA_After_SHA1_mode        */ { SaSi_HASH_SHA1_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA1_mode },
    /* SaSi_RSA_After_SHA224_mode      */ { SaSi_HASH_SHA224_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA224_mode },
    /* SaSi_RSA_After_SHA256_mode      */ { SaSi_HASH_SHA256_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA256_mode },
    /* SaSi_RSA_After_SHA384_mode      */ { SaSi_HASH_SHA384_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA384_mode },
    /* SaSi_RSA_After_SHA512_mode      */ { SaSi_HASH_SHA512_DIGEST_SIZE_IN_WORDS, SaSi_HASH_SHA512_mode },
    /* SaSi_RSA_After_HASH_NOT_KNOWN_mode   */ { 0, SaSi_HASH_NumOfModes },
    /* SaSi_RSA_HASH_NO_HASH_mode           */ { 0, SaSi_HASH_NumOfModes },
};

const uint8_t rsa_supported_hash_modes[SaSi_RSA_HASH_NumOfModes] = {
    /* SaSi_RSA_HASH_MD5_mode          */ SASI_TRUE,
    /* SaSi_RSA_HASH_SHA1_mode         */ SASI_TRUE,
    /* SaSi_RSA_HASH_SHA224_mode       */ SASI_TRUE,
    /* SaSi_RSA_HASH_SHA256_mode       */ SASI_TRUE,
    /* SaSi_RSA_HASH_SHA384_mode       */ SASI_TRUE,
    /* SaSi_RSA_HASH_SHA512_mode       */ SASI_TRUE,
    /* SaSi_RSA_After_MD5_mode         */ SASI_TRUE,
    /* SaSi_RSA_After_SHA1_mode        */ SASI_TRUE,
    /* SaSi_RSA_After_SHA224_mode      */ SASI_TRUE,
    /* SaSi_RSA_After_SHA256_mode      */ SASI_TRUE,
    /* SaSi_RSA_After_SHA384_mode      */ SASI_TRUE,
    /* SaSi_RSA_After_SHA512_mode      */ SASI_TRUE,
    /* SaSi_RSA_After_HASH_NOT_KNOWN_mode   */ SASI_FALSE,
    /* SaSi_RSA_HASH_NO_HASH_mode           */ SASI_FALSE,
};
