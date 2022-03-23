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

#ifdef DX_PLAT_ZYNQ7000
/* Zynq EVBs have 1GB and we reserve the memory at offset 768M */
#define WORKSPACE_FREE_MEM_BASE_ADR 0x34000000
#else /* #elif DX_PLAT_VIRTEX5 */
/* Virtex5 platforms (PPC) have 512MB and we reserve the memory at offset 256M */
#define WORKSPACE_FREE_MEM_BASE_ADR 0x10000000
#endif
#define WORKSPACE_CONTIG_FREE_MEM 0x1001000

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

    rc = SaSi_PalDmaInit(WORKSPACE_CONTIG_FREE_MEM, WORKSPACE_FREE_MEM_BASE_ADR);
    if (rc != 0) {
        return 1;
    }
    /* Initialize mutex that protects shared memory and crypto access */
    rc = SaSi_PalMutexCreate(&sasiSymCryptoMutex);
    if (rc != 0) {
        SaSi_PalAbort("Fail to create SYM mutex\n");
    }
    /* Initialize mutex that protects shared memory and crypto access */
    rc = SaSi_PalMutexCreate(&sasiAsymCryptoMutex);
    if (rc != 0) {
        SaSi_PalAbort("Fail to create ASYM mutex\n");
    }
#ifndef DX_CONFIG_IOT_SUPPORTED
    /* Initialize mutex that protects shared memory and crypto access */
    rc = SaSi_PalMutexCreate(&sasiRndCryptoMutex);
    if (rc != 0) {
        SaSi_PalAbort("Fail to create RND mutex\n");
    }
    pSaSiRndCryptoMutex = &sasiRndCryptoMutex;
#else
    pSaSiRndCryptoMutex = &sasiAsymCryptoMutex;
#endif
    /* Initialize mutex that protects fips access */
    rc = SaSi_PalMutexCreate(&sasiFipsMutex);
    if (rc != 0) {
        SaSi_PalAbort("Fail to create FIBS mutex\n");
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
    SaSiError_t err = 0;

    SaSi_PalDmaTerminate();

    err = SaSi_PalMutexDestroy(&sasiSymCryptoMutex);
    if (err != 0) {
        SASI_PAL_LOG_DEBUG("failed to destroy mutex sasiSymCryptoMutex\n");
    }
    SaSi_PalMemSetZero(&sasiSymCryptoMutex, sizeof(SaSi_PalMutex));
    err = SaSi_PalMutexDestroy(&sasiAsymCryptoMutex);
    if (err != 0) {
        SASI_PAL_LOG_DEBUG("failed to destroy mutex sasiAsymCryptoMutex\n");
    }
    SaSi_PalMemSetZero(&sasiAsymCryptoMutex, sizeof(SaSi_PalMutex));
#ifndef DX_CONFIG_IOT_SUPPORTED
    err = SaSi_PalMutexDestroy(&sasiRndCryptoMutex);
    if (err != 0) {
        SASI_PAL_LOG_DEBUG("failed to destroy mutex sasiRndCryptoMutex\n");
    }
    SaSi_PalMemSetZero(&sasiRndCryptoMutex, sizeof(SaSi_PalMutex));
#endif
    err = SaSi_PalMutexDestroy(&sasiFipsMutex);
    if (err != 0) {
        SASI_PAL_LOG_DEBUG("failed to destroy mutex sasiFipsMutex\n");
    }
    SaSi_PalMemSetZero(&sasiFipsMutex, sizeof(SaSi_PalMutex));
}
