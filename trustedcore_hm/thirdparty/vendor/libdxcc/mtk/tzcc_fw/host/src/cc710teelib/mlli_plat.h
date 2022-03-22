/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef MLLI_PLAT_H
#define MLLI_PLAT_H

#include "ssi_lli_defs.h"
#include "ssi_compiler.h"
#include "hw_queue_defs.h"

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */

#define DX_GetIsMlliExternalAlloc(qid) 0
/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * Rerturns the head of the MLLI buffer.
 *
 * \return dx_sram_addr_t.
 */
DxSramAddr_t DX_GetMLLIWorkspace(void);

#endif /* MLLI_PLAT_H */
