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
#include "dx_reg_base_host.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_mem.h"
#include "ssi_pal_abort.h"

extern SaSi_PalMutex sasiSymCryptoMutex;
extern SaSi_PalMutex sasiAsymCryptoMutex;
extern SaSi_PalMutex sasiRndCryptoMutex;
extern SaSi_PalMutex sasiFipsMutex;
extern SaSi_PalMutex *pSaSiRndCryptoMutex;

#define SASI_MEM_SIZE 0x8000

#ifdef DX_PLAT_ZYNQ7000
/* Zynq EVBs have 1GB and we reserve the memory at offset 768M */
#else /* #elif DX_PLAT_VIRTEX5 */
/* Virtex5 platforms (PPC) have 512MB and we reserve the memory at offset 256M */
#endif

/*
 * @brief   PAL layer entry point.
 *          The function initializes customer platform sub components,
 *           such as memory mapping used later by SaSi to get physical contiguous memory.
 *
 *
 * @return Virtual start address of contiguous memory
 */
int SaSi_PalInit(void)
{
    int rc = 0;

    SaSi_PalLogInit();

    rc = sasi_pal_dma_init(SASI_MEM_SIZE);
    if (rc != 0) {
        return 1;
    }
    return 0;
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
