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

/* ************ Include Files ************** */
#include "dx_pal_init.h"
#include "dx_pal_dma_plat.h"
#include "dx_pal_log.h"
#include "dx_reg_base_host.h"
#include "dx_pal_mutex.h"
#include "dx_pal_mem.h"
#include "dx_pal_abort.h"

extern DX_PAL_MUTEX dxSymCryptoMutex;
extern DX_PAL_MUTEX dxAsymCryptoMutex;
extern DX_PAL_MUTEX dxRndCryptoMutex;

#define DX_MEM_SIZE 0x8000
/*
 * @brief   PAL layer entry point.
 *          The function initializes customer platform sub components,
 *           such as memory mapping used later by CRYS to get physical contiguous memory.
 *
 *
 * @return Virtual start address of contiguous memory
 */
uint32_t DX_PAL_Init(void)
{
    int rc = 0;
    DX_PAL_LogInit();
    rc = dx_pal_dma_init(DX_MEM_SIZE);
    if (rc != 0) { // check this
        return 1;
    }
    /* Initialize mutex that protects shared memory and crypto access */
    // rc = DX_PAL_MutexCreate(&dxSymCryptoMutex);
    if (rc != 0) {
        DX_PAL_Abort("Fail to create SYM mutex\n");
    }
    /* Initialize mutex that protects shared memory and crypto access */
    // rc = DX_PAL_MutexCreate(&dxAsymCryptoMutex);
    if (rc != 0) {
        DX_PAL_Abort("Fail to create ASYM mutex\n");
    }
    /* Initialize mutex that protects shared memory and crypto access */
    // rc = DX_PAL_MutexCreate(&dxRndCryptoMutex);
    if (rc != 0) {
        DX_PAL_Abort("Fail to create RND mutex\n");
    }
    return 0;
}

/*
 * @brief   PAL layer entry point.
 *          The function initializes customer platform sub components,
 *           such as memory mapping used later by CRYS to get physical contiguous memory.
 *
 *
 * @return None
 */
void DX_PAL_Terminate()
{
    DxError_t err = 0;
    DX_PAL_DmaTerminate();
    // err = DX_PAL_MutexDestroy(&dxSymCryptoMutex);
    if (err != 0) {
        DX_PAL_LOG_DEBUG("failed to destroy mutex dxSymCryptoMutex\n");
    }
    DX_PAL_MemSetZero(&dxSymCryptoMutex, sizeof(DX_PAL_MUTEX));
    // err = DX_PAL_MutexDestroy(&dxAsymCryptoMutex);
    if (err != 0) {
        DX_PAL_LOG_DEBUG("failed to destroy mutex dxAsymCryptoMutex\n");
    }
    DX_PAL_MemSetZero(&dxAsymCryptoMutex, sizeof(DX_PAL_MUTEX));
    // err = DX_PAL_MutexDestroy(&dxRndCryptoMutex);
    if (err != 0) {
        DX_PAL_LOG_DEBUG("failed to destroy mutex dxRndCryptoMutex\n");
    }
    DX_PAL_MemSetZero(&dxRndCryptoMutex, sizeof(DX_PAL_MUTEX));
}
