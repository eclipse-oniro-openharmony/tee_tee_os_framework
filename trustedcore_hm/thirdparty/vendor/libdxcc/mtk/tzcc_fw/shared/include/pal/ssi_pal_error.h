/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_ERROR_H
#define _SSI_PAL_ERROR_H

/* !
@file
@brief This file contains the platform dependent error definitions.
*/

#ifdef __cplusplus
extern "C" {
#endif

#define SASI_PAL_BASE_ERROR 0x0F000000

/* Memory error returns */
#define SASI_PAL_MEM_BUF1_GREATER SASI_PAL_BASE_ERROR + 0x01UL
#define SASI_PAL_MEM_BUF2_GREATER SASI_PAL_BASE_ERROR + 0x02UL

/* Semaphore error returns */
#define SASI_PAL_SEM_CREATE_FAILED  SASI_PAL_BASE_ERROR + 0x03UL
#define SASI_PAL_SEM_DELETE_FAILED  SASI_PAL_BASE_ERROR + 0x04UL
#define SASI_PAL_SEM_WAIT_TIMEOUT   SASI_PAL_BASE_ERROR + 0x05UL
#define SASI_PAL_SEM_WAIT_FAILED    SASI_PAL_BASE_ERROR + 0x06UL
#define SASI_PAL_SEM_RELEASE_FAILED SASI_PAL_BASE_ERROR + 0x07UL

#define SASI_PAL_ILLEGAL_ADDRESS SASI_PAL_BASE_ERROR + 0x08UL

#ifdef __cplusplus
}
#endif

#endif
