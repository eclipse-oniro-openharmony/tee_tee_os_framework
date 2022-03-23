/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CCLIB

#include "ssi_pal_types.h"
#include "ssi_pal_log.h"
#include "ssi_pal_mem.h"
#include "sns_silib.h"
#include "ssi_hal.h"
#include "ssi_pal_init.h"
#include "ssi_pal_mutex.h"
#include "hw_queue.h"
#include "completion.h"
#include "sasi_rnd.h"
#include "sasi_fips.h"
#include "sym_adaptor_driver.h"
#include "ssi_pal_dma.h"
#include "ssi_util_rpmb_adaptor.h"
#include "ssi_pal_perf.h"
#include "ssi_general_defs.h"
#include "sasi_fips_defs.h"
#include "pka.h"
#include "llf_rnd_trng.h"
#include "cc_plat.h"
#include "ssi_rng_plat.h"

SaSi_PalMutex sasiSymCryptoMutex;
SaSi_PalMutex sasiAsymCryptoMutex;
SaSi_PalMutex sasiRndCryptoMutex;
SaSi_PalMutex sasiFipsMutex;
SaSi_PalMutex *pSaSiRndCryptoMutex;

/* resets the low resolution secure timer */
extern void SaSi_UtilResetLowResTimer(void);

#define SASI_LIB_WAIT_ON_LCS_VALID_BIT()                                              \
    do {                                                                              \
        uint32_t regVal;                                                              \
        do {                                                                          \
            regVal = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, LCS_IS_VALID)); \
            regVal = SASI_REG_FLD_GET(0, LCS_IS_VALID, VALUE, regVal);                \
        } while (!regVal);                                                            \
    } while (0)

static SA_SilibRetCode_t SaSiInitKdrRma(SaSi_RND_Context_t *rndContext_ptr)
{
    uint32_t regVal = 0, lcsVal = 0;
    uint32_t kdrValues[SASI_AES_KDR_MAX_SIZE_WORDS];
    SaSiError_t error = SaSi_OK;
    uint32_t i        = 0;

    /* Read LCS */
    regVal = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, LCS_REG));
    lcsVal = SASI_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);

    /* if it is not LCS == RMA return */
    if (lcsVal != SASI_LCS_RMA_LCS)
        return SA_SILIB_RET_OK;
    else { // in case lcs == RMA set the KDR
        error = SaSi_RND_GenerateVector_MTK(&rndContext_ptr->rndState, sizeof(kdrValues), (uint8_t *)kdrValues);
        if (error != SaSi_OK)
            return SA_SILIB_RET_EINVAL;
        /* set the random value to the KDR register */
        for (i = 0; i < SASI_AES_KDR_MAX_SIZE_WORDS; i++) {
            SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_RMA_RKEK_WR), kdrValues[i]);
        }
    }

    return SA_SILIB_RET_OK;
}

static void SaSiClearSram(void)
{
    uint32_t regVal = 0, lcsVal = 0;

    /* Read LCS */
    regVal = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, LCS_REG));
    lcsVal = SASI_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);

    /* if it is not LCS == RMA or secure return */
    if ((lcsVal != SASI_LCS_RMA_LCS) && (lcsVal != SASI_LCS_SECURE_LCS)) {
        return;
    }

    /* clear TRNG source from SRAM */
    _ClearSram(SASI_SRAM_RND_HW_DMA_ADDRESS, SASI_SRAM_RND_MAX_SIZE);
    /* clear symmetric context from SRAM */
    _ClearSram(SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_MAX_SIZE);
    /* clear PKA from SRAM */
    PKA_ClearAllPka();

    return;
}

static SaSiError_t SaSiStartupTest(SaSi_RND_Context_t *rndContext_ptr, SaSi_RND_WorkBuff_t *workBuff_ptr /* in/out */)
{
    /* error identifier definition */
    SaSiError_t error              = SaSi_OK;
    SaSi_RND_State_t *rndState_ptr = NULL;
    SaSi_RND_Params_t trngParams;

    rndState_ptr = &(rndContext_ptr->rndState);
    error        = RNG_PLAT_SetUserRngParameters(rndState_ptr, &trngParams);
    if (error != SASI_SUCCESS) {
        return error;
    }

    error = SaSi_PalMutexLock(pSaSiRndCryptoMutex, SASI_INFINITE);
    if (error != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }
    /* call on Instantiation mode */
    error = LLF_RND_RunTrngStartupTest(rndState_ptr, &trngParams, (uint32_t *)workBuff_ptr);

    if (SaSi_PalMutexUnlock(pSaSiRndCryptoMutex) != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to release mutex\n");
    }
    return error;
}

/* !
 * TEE (Trusted Execution Environment) entry point.
 * Init CryptoCell for TEE.
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 *
 * \return SA_SilibRetCode_t one of the error codes defined in sns_silib.h
 */
SA_SilibRetCode_t SaSi_LibInit(SaSi_RND_Context_t *rndContext_ptr, SaSi_RND_WorkBuff_t *rndWorkBuff_ptr,
                               bool isFipsSupport, SaSi_FipsKatContext_t *pFipsCtx)
{
    int rc       = SA_SILIB_RET_OK;
    uint32_t reg = 0;

    /* check parameters */
    if (rndContext_ptr == NULL)
        return SA_SILIB_RET_EINVAL;
    if (rndWorkBuff_ptr == NULL)
        return SA_SILIB_RET_EINVAL;

    rc = SaSi_PalInit();
    if (rc != SA_SILIB_RET_OK) {
        rc = SA_SILIB_RET_PAL;
        goto InitErr;
    }
    rc = SaSi_HalInit();
    if (rc != SA_SILIB_RET_OK) {
        rc = SA_SILIB_RET_HAL;
        goto InitErr1;
    }

    /* reset low resolution secure timer */
    SaSi_UtilResetLowResTimer();

    /* Call sw reset to reset the CC before starting to work with it */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_CC_SW_RST), 0x1UL);
    /* wait for reset to be completed - by polling on the LCS valid register */
    SASI_LIB_WAIT_ON_LCS_VALID_BIT();

    /* verify HW version register configuration */
    reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, VERSION));
    reg = SASI_REG_FLD_GET(HOST_RGF, VERSION, PRODUCT, reg);
    if (reg != CC_HW_VERSION) {
        rc = SA_SILIB_RET_EINVAL_HW_VERSION;
        goto InitErr2;
    }

    /* verify HW signature */
    reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_SIGNATURE));
    if (reg != DX_DEV_SIGNATURE) {
        rc = SA_SILIB_RET_EINVAL_HW_SIGNATURE;
        goto InitErr2;
    }

#ifdef BIG__ENDIAN
    /* Set DMA endianess to big */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_ENDIAN), 0xCCUL);
#else /* LITTLE__ENDIAN */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_ENDIAN), 0x00UL);
#endif

    /* setting the hw cache parameters */
    SaSi_HalInitHWCacheParams();

    rc = InitHWQueue();
    if (rc != SA_SILIB_RET_OK) {
        rc = SA_SILIB_RET_HW_Q_INIT;
        goto InitErr2;
    }
    rc = InitCompletion();
    if (rc != SA_SILIB_RET_OK) {
        rc = SA_SILIB_RET_COMPLETION;
        goto InitErr2;
    }

    rc = SymDriverAdaptorModuleInit();
    if (rc != SA_SILIB_RET_OK) {
        rc = SA_SILIB_RET_COMPLETION; // check
        goto InitErr2;
    }

    rc = RpmbSymDriverAdaptorModuleInit();
    if (rc != SA_SILIB_RET_OK) {
        rc = SA_SILIB_RET_COMPLETION;
        goto InitErr2;
    }

    SASI_PAL_PERF_INIT();
    /* clear SRAM sensitive data: PKA, TRNG source and symmetric context */
    SaSiClearSram();

#ifdef SSI_SUPPORT_FIPS
    rc = FipsSetState(isFipsSupport ? CC_FIPS_STATE_SUPPORTED : CC_FIPS_STATE_NOT_SUPPORTED);
    if (rc != SaSi_OK) {
        rc = SA_SILIB_RET_EFIPS;
        goto InitErr2; /* do not terminate hal and pal, since sasi api should work and return error */
    }
    rc = FipsRunPowerUpTest(rndContext_ptr, pFipsCtx);
    if (rc != SaSi_OK) {
        rc = SA_SILIB_RET_EFIPS;
        goto InitErr; /* do not terminate hal and pal, since sasi api should work and return error */
    }
#else
    SASI_UNUSED_PARAM(isFipsSupport);
    SASI_UNUSED_PARAM(pFipsCtx);
#endif

    /* Initialize RND module */
    SaSi_PalMemSetZero(rndContext_ptr, sizeof(SaSi_RND_Context_t));
#if 0
        rc = SaSiStartupTest(rndContext_ptr, rndWorkBuff_ptr);
    if (rc != SaSi_OK) {
        rc = SA_SILIB_RET_RND_INST_ERR;
        goto InitErr2;
    }
#endif

    SaSi_PalMemSetZero(rndContext_ptr, sizeof(SaSi_RND_Context_t));
    rc = SaSi_RND_Instantiation(rndContext_ptr, rndWorkBuff_ptr);
    if (rc != SaSi_OK) {
        rc = SA_SILIB_RET_RND_INST_ERR;
        goto InitErr2;
    }
    rc = SaSi_RND_SetGenerateVectorFunc(rndContext_ptr, SaSi_RND_GenerateVector_MTK);
    if (rc != 0) {
        rc = SA_SILIB_RET_RND_INST_ERR;
        goto InitErr2;
    }
    /* in case of RMA LCS set the KDR to random value */
    rc = SaSiInitKdrRma(rndContext_ptr);
    if (rc != 0) {
        rc = SA_SILIB_RET_EINVAL;
        goto InitErr2;
    }

#ifdef SSI_SUPPORT_FIPS
    rc = FipsSetState(CC_FIPS_STATE_SUSPENDED);
    if (rc != SaSi_OK) {
        rc = SA_SILIB_RET_EFIPS;
        goto InitErr2; /* do not terminate hal and pal, since sasi api should work and return error */
    }
    rc = SaSi_FIPS_CRYPTO_USAGE_SET_NON_APPROVED();
    if (rc != SaSi_OK) {
        rc = SA_SILIB_RET_EFIPS;
        goto InitErr2; /* do not terminate hal and pal, since sasi api should work and return error */
    }
#endif // SSI_SUPPORT_FIPS

    return 0;
InitErr2:
    SaSi_HalTerminate();

InitErr1:
    SaSi_PalTerminate();

InitErr:
    return rc;
}

/* !
 * TEE (Trusted Execution Environment) exit point.
 * Finalize CryptoCell for TEE operation, release associated resources.
 *                                                                    .
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 */
void SaSi_LibFini(SaSi_RND_Context_t *rndContext_ptr)
{
    SaSi_RND_UnInstantiation(rndContext_ptr);
    SymDriverAdaptorModuleTerminate();
    RpmbSymDriverAdaptorModuleTerminate();
    SaSi_HalTerminate();
    SaSi_PalTerminate();
    SASI_PAL_PERF_FIN();
}
