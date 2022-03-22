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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CRYS_API

#include "dx_pal_types.h"
#include "crys_bypass_api.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "bypass.h"
#include "dx_macros.h"
#include "validate_crys_bypass.h"

/* !
 * validate DMA object structure
 *
 * \param dmaObj the DMA object
 * \param dataSize Data size given by the user (relevent only for SRAM data)
 *
 * \return 0 on success, (-1) if ( dataSize != dma object data size), (-2) if sram pointer is out of range
 */

int validateParams(uint8_t *data, uint32_t dataSize)
{
    return CRYS_OK;
}
