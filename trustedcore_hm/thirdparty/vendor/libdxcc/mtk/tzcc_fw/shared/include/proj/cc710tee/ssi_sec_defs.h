/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_SEC_DEFS_H
#define _SSI_SEC_DEFS_H

/* !
@file
@brief This file contains general HASH definitions and types.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_pal_types.h"

/* ! The hashblock size in words. */
#define HASH_BLOCK_SIZE_IN_WORDS 16
/* ! The HASH - SHA2 results in words. */
#define HASH_RESULT_SIZE_IN_WORDS 8
#define HASH_RESULT_SIZE_IN_BYTES 32

/* ! Definition for HASH result array. */
typedef uint32_t SaSiHashResult_t[HASH_RESULT_SIZE_IN_WORDS];

#ifdef __cplusplus
}
#endif

#endif
