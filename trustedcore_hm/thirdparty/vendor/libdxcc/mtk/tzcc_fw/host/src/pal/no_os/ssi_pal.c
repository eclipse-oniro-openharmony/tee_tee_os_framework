/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "ssi_pal_init.h"
#include "ssi_pal_dma_plat.h"
#include "ssi_pal_log.h"

#define WORKSPACE_FREE_MEM_BASE_ADR 0x10000000
#define WORKSPACE_CONTIG_FREE_MEM   0x1001000

/*
 * @brief   PAL layer entry point.
 *          The function initializes customer platform sub components,
 *           such as memory mapping used later by SaSi to get physical contiguous memory.
 *
 *
 * @return Returns a non-zero value in case of failure
 */
int SaSi_PalInit(void)
{
    SaSi_PalLogInit();
    return SaSi_PalDmaInit(WORKSPACE_CONTIG_FREE_MEM, WORKSPACE_FREE_MEM_BASE_ADR);
}

/*
 * @brief   PAL layer entry point.
 *          The function initializes customer platform sub components,
 *           such as memory mapping used later by SaSi to get physical contiguous memory.
 *
 *
 * @return None
 */
void SaSi_PalTerminate(void)
{
    SaSi_PalDmaTerminate();
}
