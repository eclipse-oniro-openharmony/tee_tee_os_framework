/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef MLLI_PLAT_H
#define MLLI_PLAT_H

#include "dx_lli_defs.h"
#include "compiler.h"
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
