/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_KEY_DERIVATION_DEFS_H
#define _SSI_UTIL_KEY_DERIVATION_DEFS_H

/* !
@file
@brief This file contains the definitions for the key derivation API.
*/

#ifdef __cplusplus
extern "C" {
#endif

/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */

#define SASI_UTIL_MAX_LABEL_LENGTH_IN_BYTES 64

#define SASI_UTIL_MAX_CONTEXT_LENGTH_IN_BYTES 64

#define SASI_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES 3 /* !< \internal counter, 0x00, lengt(-0xff) */
#define SASI_UTIL_FIX_DATA_MAX_SIZE_IN_BYTES 4 /* !< \internal counter, 0x00, lengt(0x100-0xff0) */

#define SASI_UTIL_MAX_KDF_SIZE_IN_BYTES \
    (SASI_UTIL_MAX_LABEL_LENGTH_IN_BYTES + SASI_UTIL_MAX_CONTEXT_LENGTH_IN_BYTES + SASI_UTIL_FIX_DATA_MAX_SIZE_IN_BYTES)

#define SASI_UTIL_MAX_DERIVED_KEY_SIZE_IN_BYTES 4080

#ifdef __cplusplus
}
#endif

#endif /* _SSI_UTIL_KEY_DERIVATION_DEFS_H */
