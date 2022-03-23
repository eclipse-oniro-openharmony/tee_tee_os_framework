/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/



/************* Include Files ****************/
#include "cc_pal_init.h"
#include "cc_pal_dma_plat.h"
#include "cc_pal_log.h"
#include "dx_reg_base_host.h"
#include "cc_pal_mutex.h"
#include "cc_pal_mem.h"
#include "cc_pal_abort.h"
#include "cc_pal_dma_plat.h"
extern CC_PalMutex CCSymCryptoMutex;
extern CC_PalMutex CCAsymCryptoMutex;
extern CC_PalMutex CCRndCryptoMutex;
extern CC_PalMutex CCFipsMutex;
extern CC_PalMutex *pCCRndCryptoMutex;
extern CC_PalMutex *pCCGenVecMutex;

#ifdef DX_PLAT_ZYNQ7000
/* Zynq EVBs have 1GB and we reserve the memory at offset 768M */
#define PAL_WORKSPACE_MEM_BASE_ADDR		0x34000000
#elif defined PLAT_VIRTEX5
/* Virtex5 platforms (PPC) have 512MB and we reserve the memory at offset 256M */
#define PAL_WORKSPACE_MEM_BASE_ADDR		0x10000000
#elif defined DX_PLAT_JUNO
/* Juno platforms (AARCH64)  */
#define PAL_WORKSPACE_MEM_BASE_ADDR		0x8A0000000
#else
#error "unknown HW"
#endif
#define PAL_WORKSPACE_MEM_SIZE		0x1000000

/**
 * @brief   PAL layer entry point.
 *          The function initializes customer platform sub components,
 *           such as memory mapping used later by CRYS to get physical contiguous memory.
 *
 *
 * @return Virtual start address of contiguous memory
 */
int CC_PalInit(void)
{
        int rc = 0;

        CC_PalLogInit();

        rc = CC_PalDmaInit(PAL_WORKSPACE_MEM_SIZE, PAL_WORKSPACE_MEM_BASE_ADDR);
        if (rc != 0) {
		CC_PAL_LOG_ERR("Failed CC_PalDmaInit 0x%x", rc);
                return 1;
        }
        /* Initialize mutex that protects shared memory and crypto access */
        //rc = CC_PalMutexCreate(&CCSymCryptoMutex);
        if (rc != 0) {
                CC_PalAbort("Fail to create SYM mutex\n");
        }
        /* Initialize mutex that protects shared memory and crypto access */
        //rc = CC_PalMutexCreate(&CCAsymCryptoMutex);
        if (rc != 0) {
                CC_PalAbort("Fail to create ASYM mutex\n");
        }

        /* Initialize mutex that protects fips access */
       // rc = CC_PalMutexCreate(&CCFipsMutex);
        if (rc != 0) {
                CC_PalAbort("Fail to create FIBS mutex\n");
        }

        return 0;
}


/**
 * @brief   PAL layer entry point.
 *          The function initializes customer platform sub components,
 *           such as memory mapping used later by CRYS to get physical contiguous memory.
 *
 *
 * @return None
 */
void CC_PalTerminate(void)
{
        CCError_t err = 0;

        CC_PalDmaTerminate();

        //err = CC_PalMutexDestroy(&CCSymCryptoMutex);
        if (err != 0){
                CC_PAL_LOG_DEBUG("failed to destroy mutex CCSymCryptoMutex\n");
        }
        //CC_PalMemSetZero(&CCSymCryptoMutex, sizeof(CC_PalMutex));
        //err = CC_PalMutexDestroy(&CCAsymCryptoMutex);
        if (err != 0){
                CC_PAL_LOG_DEBUG("failed to destroy mutex CCAsymCryptoMutex\n");
        }
        //CC_PalMemSetZero(&CCAsymCryptoMutex, sizeof(CC_PalMutex));
#ifndef CC_CONFIG_IOT_SUPPORTED
        //err = CC_PalMutexDestroy(&CCRndCryptoMutex);
        if (err != 0){
                CC_PAL_LOG_DEBUG("failed to destroy mutex CCRndCryptoMutex\n");
        }
        //CC_PalMemSetZero(&CCRndCryptoMutex, sizeof(CC_PalMutex));
#endif
        //err = CC_PalMutexDestroy(&CCFipsMutex);
        if (err != 0){
                CC_PAL_LOG_DEBUG("failed to destroy mutex CCFipsMutex\n");
        }
       // CC_PalMemSetZero(&CCFipsMutex, sizeof(CC_PalMutex));
}

