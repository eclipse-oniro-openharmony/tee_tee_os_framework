/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_GENERAL_DEFS_H
#define _SSI_GENERAL_DEFS_H

/* !
@file
@brief This file contains general definitions.
*/

#ifdef __cplusplus
extern "C" {
#endif

/* general definitions */
/* ------------------------- */
#define SASI_AES_KDR_MAX_SIZE_BYTES 32
#define SASI_AES_KDR_MAX_SIZE_WORDS (SASI_AES_KDR_MAX_SIZE_BYTES / sizeof(uint32_t))

/* Life cycle state definitions */
#define SASI_LCS_CHIP_MANUFACTURE_LCS   0x0 /* !< Life cycle CM value. */
#define SASI_LCS_DEVICE_MANUFACTURE_LCS 0x1 /* !< Life cycle DM value. */
#define SASI_LCS_SECURITY_DISABLED_LCS  0x3 /* !< Life cycle security disabled value. */
#define SASI_LCS_SECURE_LCS             0x5 /* !< Life cycle secure value. */
#define SASI_LCS_RMA_LCS                0x7 /* !< Life cycle RMA value. */

#ifdef __cplusplus
}
#endif

#endif
