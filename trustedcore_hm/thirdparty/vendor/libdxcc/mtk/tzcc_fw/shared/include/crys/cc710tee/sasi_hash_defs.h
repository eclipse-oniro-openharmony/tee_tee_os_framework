/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_HASH_DEFS_H
#define SaSi_HASH_DEFS_H

/* !
@file
@brief This file contains HASH definitions.
*/

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

/* ! The size of user's context prototype (see SaSi_HASHUserContext_t) in words. */
/* In order to allow contiguous context the user context is doubled + 3 words for management */
#define SaSi_HASH_USER_CTX_SIZE_IN_WORDS 133

#ifdef __cplusplus
}
#endif

#endif
