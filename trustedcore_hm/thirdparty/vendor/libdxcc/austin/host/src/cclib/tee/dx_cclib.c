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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CCLIB

#include "dx_pal_types.h"
#include "dx_pal_log.h"
#include "dx_cclib.h"
#include "dx_hal.h"
#include "dx_pal_init.h"
#include "dx_pal_mutex.h"
#include "hw_queue.h"
#include "completion.h"
#include "crys_rnd.h"
#include "sym_adaptor_driver.h"
#include "dx_pal_dma.h"
#include "dx_util_rpmb_adaptor.h"
#include "dx_pal_perf.h"
#include "dx_general_defs.h"

static uint32_t dx_cclib_init_state = 0;
#ifndef CRYS_NO_RND_SUPPORT
static CRYS_RND_WorkBuff_t dx_cclib_workBuff_ptr;
#endif

DX_PAL_MUTEX dxSymCryptoMutex;
DX_PAL_MUTEX dxAsymCryptoMutex;
DX_PAL_MUTEX dxRndCryptoMutex;

/* resets the low resolution secure timer */
extern void DX_UTIL_ResetLowResTimer(void);

#define DX_CC_LIB_SECURE_LCS 0x5
#define DX_CC_LIB_RMA_LCS    0x7

#define DX_CCLIB_WAIT_ON_LCS_VALID_BIT()                                              \
    do {                                                                              \
        uint32_t regVal;                                                              \
        do {                                                                          \
            regVal = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, LCS_IS_VALID)); \
            regVal = DX_CC_REG_FLD_GET(0, LCS_IS_VALID, VALUE, regVal);               \
        } while (!regVal);                                                            \
    } while (0)

static DX_CclibRetCode_t DX_CcInitKdrRma()
{
    uint32_t regVal = 0, lcsVal = 0;
    uint32_t kdrValues[DX_CC_AES_KDR_MAX_SIZE_BYTES];
    CRYSError_t error = CRYS_OK;
    int i             = 0;

    /* Read LCS */
    regVal = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, LCS_REG));
    lcsVal = DX_CC_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);

    /* if it is not LCS == RMA return */
    if (lcsVal != DX_CC_LIB_RMA_LCS)
        return DX_CCLIB_RET_OK;
    else { // in case lcs == RMA set the KDR
        error = CRYS_RND_GenerateVector(sizeof(kdrValues), (uint8_t *)kdrValues);
        if (error != CRYS_OK)
            return error;
        /* set the random value to the KDR register */
        for (i = 0; i < DX_CC_AES_KDR_MAX_SIZE_BYTES; i++) {
            DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_RMA_RKEK_WR), kdrValues[i]);
        }
    }

    return DX_CCLIB_RET_OK;
}
/* !
 * TEE (Trusted Execution Environment) entry point.
 * Init CryptoCell for TEE.
 *
 * \return DX_CclibRetCode_t one of the error codes defined in dx_cclib.h
 */
DX_CclibRetCode_t DX_CclibInit(void)
{
    int rc       = DX_CCLIB_RET_OK;
    uint32_t reg = 0, lcsVal = 0;
    uint32_t dcuVal          = (1U << DX_HOST_DCU_EN_DEBUG_DOMAINS_BIT_SIZE) - 1;
    uint32_t virtMemBaseAddr = 0;

    if (dx_cclib_init_state) {
        printf("init done!"); // add by rockie
        return DX_CCLIB_RET_OK;
    }

    virtMemBaseAddr = DX_PAL_Init();

    if ((uint32_t *)virtMemBaseAddr == NULL) {
        rc = DX_CCLIB_RET_PAL;
        goto InitErr;
    }
    rc = DX_HAL_Init();
    if (rc != DX_CCLIB_RET_OK) {
        rc = DX_CCLIB_RET_HAL;
        goto InitErr1;
    }

    /* reset low resolution secure timer */
    DX_UTIL_ResetLowResTimer();

    /* Call sw reset to reset the CC before starting to work with it */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_CC_SW_RST), 0x1UL);
    /* wait for reset to be completed - by polling on the LCS valid register */
    DX_CCLIB_WAIT_ON_LCS_VALID_BIT();

    // lock DCU (if not already locked,with all 1's, unless LCS is SE )
    /* Read LCS */
    reg    = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, LCS_REG));
    lcsVal = DX_CC_REG_FLD_GET(0, LCS_REG, LCS_REG, reg);

    if (lcsVal == DX_CC_LIB_SECURE_LCS) {
        dcuVal = 0;
    }
    // lock the DCU
    dcuVal |= (((1 << DX_HOST_DCU_EN_LOCK_BIT_BIT_SIZE) - 1) << DX_HOST_DCU_EN_LOCK_BIT_BIT_SHIFT);
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_DCU_EN), dcuVal);

    /* verify HW version register configuration */
    reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, VERSION));
    reg = DX_CC_REG_FLD_GET(HOST_RGF, VERSION, PRODUCT, reg);
    if (reg != CC_HW_VERSION) {
        rc = DX_CCLIB_RET_EINVAL_HW_VERSION;
        goto InitErr2;
    }

    /* verify HW signature */
    reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_SIGNATURE));
    if (reg != DX_DEV_SIGNATURE) {
        rc = DX_CCLIB_RET_EINVAL_HW_SIGNATURE;
        goto InitErr2;
    }

#ifdef BIG__ENDIAN
    /* Set DMA endianess to big */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_ENDIAN), 0xCCUL);
#else /* LITTLE__ENDIAN */
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_ENDIAN), 0x00UL);
#endif

    /* setting the hw cache parameters */
    DX_HAL_InitHWCacheParams();

    rc = InitHWQueue();
    if (rc != DX_CCLIB_RET_OK) {
        rc = DX_CCLIB_RET_HW_Q_INIT;
        goto InitErr2;
    }
    rc = InitCompletion();
    if (rc != DX_CCLIB_RET_OK) {
        rc = DX_CCLIB_RET_COMPLETION;
        goto InitErr2;
    }

    rc = SymDriverAdaptorModuleInit();
    if (rc != DX_CCLIB_RET_OK) {
        rc = DX_CCLIB_RET_COMPLETION; // check
        goto InitErr2;
    }

    rc = RpmbSymDriverAdaptorModuleInit();
    if (rc != DX_CCLIB_RET_OK) {
        rc = DX_CCLIB_RET_COMPLETION;
        goto InitErr2;
    }

    DX_PAL_PERF_INIT();

#ifndef CRYS_NO_RND_SUPPORT
    /* Initialize RND module */
    // printf("\nCRYS_NO_RND_SUPPORT in!, CRYS_RND_Instantiation comming!\n");
    rc = CRYS_RND_Instantiation(&dx_cclib_workBuff_ptr);
    if (rc != CRYS_OK) {
        rc = DX_CCLIB_RET_RND_INST_ERR;
        // printf("\n CRYS_RND_Instantiation error!\n");
        goto InitErr2;
    }

    /* in case of RMA LCS set the KDR to random value */
    rc = DX_CcInitKdrRma();
    if (rc != 0) {
        rc = DX_CCLIB_RET_EINVAL;
        goto InitErr2;
    }
#endif

    dx_cclib_init_state = DX_CCLIB_RET_OK;

    return 0;
InitErr2:
    DX_HAL_Terminate();

InitErr1:
    DX_PAL_Terminate();

InitErr:
    return rc;
}

/* !
 * TEE (Trusted Execution Environment) exit point.
 * Finalize CryptoCell for TEE operation, release associated resources.
 */
void DX_CclibFini(void)
{
    SymDriverAdaptorModuleTerminate();
    RpmbSymDriverAdaptorModuleTerminate();
    DX_HAL_Terminate();
    DX_PAL_Terminate();
    CRYS_RND_UnInstantiation();
    DX_PAL_PERF_FIN();
}

/* !
 * Set requested CryptoCell priority queue
 * This function must be invoked before DX_CclibInit
 *
 * \param priority Requested priority queue
 *
 * \return DxCclib_RetCode
 */
DX_CclibRetCode_t DX_CclibSetPriority(DX_CclibDevPriority priority)
{
    return DX_CCLIB_RET_OK;
}
