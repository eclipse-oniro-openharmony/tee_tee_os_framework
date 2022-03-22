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

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CCLIB

#include "cc_pal_types.h"
#include "cc_pal_log.h"
#include "cc_pal_mem.h"
#include "cc_lib.h"
#include "cc_hal.h"
#include "cc_pal_init.h"
#include "cc_pal_mutex.h"
#include "hw_queue.h"
#include "completion.h"
#include "cc_rnd.h"
#include "cc_fips.h"
#include "sym_adaptor_driver.h"
#include "cc_pal_dma.h"
#include "cc_util_rpmb_adaptor.h"
#include "cc_pal_perf.h"
#include "cc_general_defs.h"
#include "cc_fips_defs.h"
#include "pki.h"
#include "llf_rnd_trng.h"
#include "cc_plat.h"
#include "cc_sram_map.h"
#include "cc_rng_plat.h"
#ifdef CC_SUPPORT_FIPS
#include "cc_pal_fips.h"
#endif

CC_PalMutex CCSymCryptoMutex;
CC_PalMutex CCAsymCryptoMutex;
CC_PalMutex CCRndCryptoMutex;
CC_PalMutex CCFipsMutex;
CC_PalMutex *pCCRndCryptoMutex;
CC_PalMutex *pCCGenVecMutex;

/* resets the low resolution secure timer */
extern void CC_UtilResetLowResTimer(void);


#define CC_LIB_WAIT_ON_LCS_VALID_BIT() 						\
	do { 											\
		uint32_t regVal; 								\
		do { 										\
			regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, LCS_IS_VALID)); \
			regVal = CC_REG_FLD_GET(0, LCS_IS_VALID, VALUE, regVal); 		\
		}while( !regVal ); 								\
	}while(0)


static CClibRetCode_t InitKdrRma(CCRndContext_t  *rndContext_ptr)
{
	uint32_t regVal = 0, lcsVal = 0;
	uint32_t kdrValues[CC_AES_KDR_MAX_SIZE_WORDS];
	CCError_t error = CC_OK;
	uint32_t i = 0;

	/* Read LCS */
	regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, LCS_REG));
	lcsVal = CC_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);

	/* if it is not LCS == RMA return */
	if (lcsVal != CC_LCS_RMA_LCS)
		return CC_LIB_RET_OK;
	else{ // in case lcs == RMA set the KDR
		error = CC_RndGenerateVector(&rndContext_ptr->rndState, sizeof(kdrValues), (uint8_t*)kdrValues);
		if (error != CC_OK)
			return SA_SILIB_RET_EINVAL;
		/* set the random value to the KDR register */
		for (i = 0; i < CC_AES_KDR_MAX_SIZE_WORDS; i++){
			CC_HAL_WRITE_REGISTER( CC_REG_OFFSET(HOST_RGF, HOST_RMA_RKEK_WR), kdrValues[i] );
		}
	}

	return CC_LIB_RET_OK;
}


static void ClearSram(void)
{
	uint32_t regVal = 0, lcsVal = 0;

	/* Read LCS */
	regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, LCS_REG));
	lcsVal = CC_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);

	/* if it is not LCS == RMA or secure return */
	if ((lcsVal != CC_LCS_RMA_LCS) &&
	    (lcsVal != CC_LCS_SECURE_LCS)) {
		return;
	}

	/* clear TRNG source from SRAM */
	_ClearSram(CC_SRAM_RND_HW_DMA_ADDRESS, CC_SRAM_RND_MAX_SIZE);
	/* clear symmetric context from SRAM */
	_ClearSram(CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, CC_SRAM_DRIVER_ADAPTOR_CONTEXT_MAX_SIZE);
	/* clear PKA from SRAM */
	PkiClearAllPka();


	return;
}


static CCError_t RndStartupTest(
        CCRndContext_t   *rndContext_ptr,
        CCRndWorkBuff_t  *workBuff_ptr/*in/out*/)
{
        /* error identifier definition */
        CCError_t error = CC_OK;
        CCRndState_t   *rndState_ptr = NULL;
        CCRndParams_t  trngParams;

        rndState_ptr = &(rndContext_ptr->rndState);
        error = RNG_PLAT_SetUserRngParameters(rndState_ptr, &trngParams);
        if (error != CC_SUCCESS) {
                return error;
        }

        error = CC_PalMutexLock(pCCRndCryptoMutex, CC_INFINITE);
        if (error != CC_SUCCESS) {
                CC_PalAbort("Fail to acquire mutex\n");
        }
        /* call on Instantiation mode */
        error = LLF_RND_RunTrngStartupTest(rndState_ptr, &trngParams, (uint32_t*)workBuff_ptr);

        if (CC_PalMutexUnlock(pCCRndCryptoMutex) != CC_SUCCESS) {
                CC_PalAbort("Fail to release mutex\n");
        }
        return error;
}


/*!
 * TEE (Trusted Execution Environment) entry point.
 * Init CryptoCell for TEE.
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 *
 * \return CClibRetCode_t one of the error codes defined in cc_lib.h
 */
CClibRetCode_t CC_LibInit(CCRndContext_t *rndContext_ptr,
	CCRndWorkBuff_t  *rndWorkBuff_ptr,
	bool isFipsSupport,
	CCFipsKatContext_t  *pFipsCtx)
{
	int rc = CC_LIB_RET_OK;
	uint32_t reg = 0;

	/* check parameters */
        if (rndContext_ptr == NULL)
                return SA_SILIB_RET_EINVAL;
        if (rndWorkBuff_ptr == NULL)
                return SA_SILIB_RET_EINVAL;

	rc = CC_PalInit();
	if (rc != CC_LIB_RET_OK) {
		rc = CC_LIB_RET_PAL;
		goto InitErr;
	}
	rc = CC_HalInit();
	if (rc != CC_LIB_RET_OK) {
		rc = CC_LIB_RET_HAL;
		goto InitErr1;
	}

	/* reset low resolution secure timer */
	CC_UtilResetLowResTimer();

	/* Call sw reset to reset the CC before starting to work with it */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_CC_SW_RST) , 0x1UL);
	/* wait for reset to be completed - by polling on the LCS valid register */
	CC_LIB_WAIT_ON_LCS_VALID_BIT();


	/* verify HW version register configuration */
	reg = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_VERSION));
	reg = CC_REG_FLD_GET(HOST_RGF, VERSION, PRODUCT, reg);
	if (reg != CC_HW_VERSION) {
		rc = CC_LIB_RET_EINVAL_HW_VERSION;
		goto InitErr2;
	}

	/* verify HW signature */
	reg = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_SIGNATURE));
	if (reg != DX_DEV_SIGNATURE) {
		rc = CC_LIB_RET_EINVAL_HW_SIGNATURE;
		goto InitErr2;
	}

#ifdef BIG__ENDIAN
	/* Set DMA endianess to big */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_ENDIAN) , 0xCCUL);
#else /* LITTLE__ENDIAN */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_ENDIAN) , 0x00UL);
#endif

	/* setting the hw cache parameters */
	CC_HalInitHWCacheParams();

	rc = InitHWQueue();
	if (rc != CC_LIB_RET_OK) {
		rc = SA_SILIB_RET_HW_Q_INIT;
		goto InitErr2;
	}

	InitCompletion();

	rc = SymDriverAdaptorModuleInit();
	if (rc != CC_LIB_RET_OK) {
		rc = SA_SILIB_RET_COMPLETION;  // check
		goto InitErr2;
	}

	rc = RpmbSymDriverAdaptorModuleInit();
	if (rc != CC_LIB_RET_OK) {
		rc = SA_SILIB_RET_COMPLETION;
		goto InitErr2;
	}

	CC_PAL_PERF_INIT();
	/* clear SRAM sensitive data: PKA, TRNG source and symmetric context*/
	ClearSram();

#ifdef CC_SUPPORT_FIPS
	/* +++hisilicon */
	/*
	 * In the CAVP test, when testing CTR-DRBG, need to compile the FIPS
	 * function file of CC ENGINE, but the teeos will boot fail when FIPS
	 * enabled, so stub the FIPS related functions by add CC_CAVP_TEST_ENABLE
	 */
	/* ---hisilicon */
#ifdef CC_CAVP_TEST_ENABLE
        rc = FipsSetState(isFipsSupport ? CC_FIPS_STATE_SUPPORTED : CC_FIPS_STATE_NOT_SUPPORTED);
        if (rc != CC_OK) {
                rc = SA_SILIB_RET_EFIPS;
                goto InitErr2;
        }
        rc = FipsRunPowerUpTest(rndContext_ptr, pFipsCtx);
        if (rc != CC_OK) {
                rc = SA_SILIB_RET_EFIPS;
                goto InitErr;   /* do not terminate hal and pal, since CC api should work and return error */
        }
#endif
#else
	CC_UNUSED_PARAM(isFipsSupport);
	CC_UNUSED_PARAM(pFipsCtx);
#endif

	/* Initialize RND module */
	CC_PalMemSetZero(rndContext_ptr, sizeof(CCRndContext_t));
        rc = RndStartupTest(rndContext_ptr, rndWorkBuff_ptr);
	if (rc != CC_OK) {
		rc = CC_LIB_RET_RND_INST_ERR;
		goto InitErr2;
	}

	CC_PalMemSetZero(rndContext_ptr, sizeof(CCRndContext_t));
	rc = CC_RndInstantiation(rndContext_ptr, rndWorkBuff_ptr);
	if (rc != CC_OK) {
		rc = CC_LIB_RET_RND_INST_ERR;
		goto InitErr2;
	}

	rc = CC_RndSetGenerateVectorFunc(rndContext_ptr, CC_RndGenerateVector);
	if (rc != 0) {
		rc = CC_LIB_RET_RND_INST_ERR;
		goto InitErr2;
	}


        /* in case of RMA LCS set the KDR to random value */
	rc = InitKdrRma(rndContext_ptr);
	if (rc != 0) {
		rc = SA_SILIB_RET_EINVAL;
		goto InitErr2;
	}

#ifdef CC_SUPPORT_FIPS
	/* +++hisilicon */
	/*
	 * In the CAVP test, when testing CTR-DRBG, need to compile the FIPS
	 * function file of CC ENGINE, but the teeos will boot fail when FIPS
	 * enabled, so stub the FIPS related functions by add CC_CAVP_TEST_ENABLE
	 */
	/* ---hisilicon */
#ifdef CC_CAVP_TEST_ENABLE
        rc = FipsSetState(CC_FIPS_STATE_SUSPENDED);
        if (rc != CC_OK) {
                rc = SA_SILIB_RET_EFIPS;
                goto InitErr2;
        }
        rc = CC_FIPS_CRYPTO_USAGE_SET_NON_APPROVED();
        if (rc != CC_OK) {
                rc = SA_SILIB_RET_EFIPS;
                goto InitErr2;
        }
	rc = CC_PalFipsWaitForReeStatus();
        if (rc != CC_OK) {
                rc = SA_SILIB_RET_EFIPS;
                goto InitErr2;
        }
#endif
#endif  // CC_SUPPORT_FIPS

	return CC_LIB_RET_OK;
InitErr2:
	CC_HalTerminate();

InitErr1:
	CC_PalTerminate();

InitErr:
	return (CClibRetCode_t)rc;
}

/*!
 * TEE (Trusted Execution Environment) exit point.
 * Finalize CryptoCell for TEE operation, release associated resources.
 *                                                                    .
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 */
void CC_LibFini(CCRndContext_t  *rndContext_ptr)
{
#ifdef CC_SUPPORT_FIPS
	/* +++hisilicon */
	/*
	 * In the CAVP test, when testing CTR-DRBG, need to compile the FIPS
	 * function file of CC ENGINE, but the teeos will boot fail when FIPS
	 * enabled, so stub the FIPS related functions by add CC_CAVP_TEST_ENABLE
	 */
	/* ---hisilicon */
#ifdef CC_CAVP_TEST_ENABLE
	CC_PalFipsStopWaitingRee();
#endif
#endif
        CC_RndUnInstantiation(rndContext_ptr);
	SymDriverAdaptorModuleTerminate();
	RpmbSymDriverAdaptorModuleTerminate();
	CC_HalTerminate();
	CC_PalTerminate();
	CC_PAL_PERF_FIN();
}

