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
#include "dx_rng.h"
#include "cc_pal_mem.h"
#include "cc_plat.h"
#include "dx_crys_kernel.h"
#include "cc_hal.h"
#include "cc_regs.h"
#include "dx_host.h"
#include "cc_rnd_error.h"
#include "llf_rnd_hwdefs.h"
#include "llf_rnd.h"
#include "llf_rnd_error.h"
#include "cc_sram_map.h"
#include "llf_rnd_trng.h"
#include "cc_config_trng90b.h"
#ifndef CMPU_UTIL
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#endif

/* macro for calculation max. allowed time for */
#define LLF_RND_CalcMaxTrngTime(ehrSamples, SubSamplingRatio) \
	(((ehrSamples) * LLF_RND_TRNG_MAX_TIME_COEFF * \
	LLF_RND_TRNG_VON_NEUMAN_COEFF * \
	LLF_RND_HW_TRNG_EHR_WIDTH_IN_BITS * \
	(SubSamplingRatio)) >> LLF_RND_TRNG_MAX_TIME_SCALE)
#define ROSC_INIT_START_BIT   0x80000000

#define LLF_RND_TRNG90B_MAX_BYTES ( LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_TRNG90B_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES)
#define CC_CONFIG_TRNG90B_ADAPTIVE_PROPORTION_WINDOW_SIZE      1024     // binary noise source

#if !defined(CMPU_UTIL) && !defined(SC_TEST_MODE)
extern CC_PalMutex CCSymCryptoMutex;

#define MUTEX_LOCK_AND_RETURN_UPON_ERROR(mutex) \
        if (CC_PalMutexLock(&mutex, CC_INFINITE) != CC_SUCCESS) { \
        CC_PalAbort("Fail to acquire mutex\n"); \
        return false; \
}

#define MUTEX_UNLOCK(mutex) \
        if (CC_PalMutexUnlock(&mutex) != CC_SUCCESS) { \
        CC_PalAbort("Fail to release mutex\n"); \
}
#else
#define MUTEX_LOCK_AND_RETURN_UPON_ERROR(mutex)
#define MUTEX_UNLOCK(mutex)
#endif

/*********************************** Enums ******************************/
/*********************************Typedefs ******************************/

/**************** Global Data to be read by RNG function ****************/

/* test variables */
#ifdef RND_TEST_TRNG_WITH_ESTIMATOR
uint32_t  gEntrSize[4];
#endif

extern uint32_t LLF_RND_DescBypass(CCSramAddr_t  inSramAddr, uint32_t inSize, uint32_t *outAddr_ptr);

/******************************************************************************/
/***************   Prototypes and Private functions    ************************/
/******************************************************************************/
static CCError_t startTrngHW(
        CCRndState_t  *rndState_ptr,
        CCRndParams_t *trngParams_ptr,
        CCBool_t           isRestart,
        uint32_t          *roscsToStart_ptr,
        CCSramAddr_t       sramAddr,
        CCBool_t           isStartup);
static CCError_t getTrngSource(CCRndState_t  *rndState_ptr,
				 CCRndParams_t  *trngParams_ptr,
				 CCBool_t            isContinued,
				 uint32_t        **sourceOut_ptr_ptr,
				 uint32_t         *sourceOutSize_ptr,
				 uint32_t         *rndWorkBuff_ptr,
				 CCBool_t          isStartup);
static CCError_t runContinuousTesting(uint32_t* pData, uint32_t sizeInBytes);
CCError_t LLF_RND_RepetitionCounterTest(uint32_t* pData, uint32_t sizeInBytes, uint32_t C);
CCError_t LLF_RND_AdaptiveProportionTest(uint32_t* pData, uint32_t sizeInBytes, uint32_t C, uint32_t W);


static bool isSramSupported(CCSramAddr_t sramAddr)
{
        const uint32_t sramWordWrite = 0xFA12FA12;
        uint32_t sramWordRead  = 0;

        MUTEX_LOCK_AND_RETURN_UPON_ERROR(CCSymCryptoMutex);

        _WriteWordsToSram(sramAddr, &sramWordWrite, sizeof(sramWordWrite));
        _ReadWordsFromSram(sramAddr, &sramWordRead, sizeof(sramWordRead));

        MUTEX_UNLOCK(CCSymCryptoMutex);

        return (sramWordWrite == sramWordRead);
}
/************************************************************************************/
/**
 * The function checks that parameters, loaded in the TRNG HW
 * are match to parameters, required by trngParams_ptr structures.
 *
 * @author reuvenl (6/25/2012)
 *
 * @param trngParams_ptr
 *
 * @return CCError_t
 */
static CCError_t LLF_RND_TRNG_CheckHwParams(CCRndParams_t *trngParams_ptr)
{
	uint32_t temp;
	CCBool_t isTrue = CC_TRUE;

	/* check Debug control - masked TRNG tests according to mode */
	temp = CC_HAL_READ_REGISTER(CC_REG_OFFSET(RNG, TRNG_DEBUG_CONTROL));
	isTrue &= (temp == LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_TRNG90B_MODE);
	/* check samplesCount */
	temp = CC_HAL_READ_REGISTER(CC_REG_OFFSET(RNG,SAMPLE_CNT1));
	isTrue &= (temp == trngParams_ptr->SubSamplingRatio);

	/* if any parameters are not match return an Error */
	if (isTrue == CC_FALSE)
		return LLF_RND_TRNG_PREVIOUS_PARAMS_NOT_MATCH_ERROR;
	else
		return CC_OK;
}

/****************************************************************************************/
/*****************************       Public Functions      ******************************/
/****************************************************************************************/

CCError_t LLF_RND_StartTrngHW(
        CCRndState_t  *rndState_ptr,
        CCRndParams_t *trngParams_ptr,
        CCBool_t           isRestart,
        uint32_t         *roscsToStart_ptr,
        CCSramAddr_t       sramAddr)
{
        CCError_t error = CC_OK;

        error = startTrngHW(rndState_ptr, trngParams_ptr, isRestart, roscsToStart_ptr, sramAddr, CC_FALSE/*isStartup*/);

        return error;
}


CCError_t LLF_RND_GetTrngSource(
				 CCRndState_t  *rndState_ptr,	   /*in/out*/
				 CCRndParams_t  *trngParams_ptr,   /*in/out*/
				 CCBool_t            isContinued,	 /*in*/
				 uint32_t         *entropySize_ptr,  /*in/out*/
				 uint32_t        **sourceOut_ptr_ptr,	/*out*/
				 uint32_t         *sourceOutSize_ptr,/*in/out*/
				 uint32_t         *rndWorkBuff_ptr,      /*in*/
				 bool              isFipsSupported)      /*in*/
{
	CCError_t error = CC_OK;

	CC_UNUSED_PARAM(entropySize_ptr);
	CC_UNUSED_PARAM(isFipsSupported);

	error = getTrngSource(rndState_ptr, trngParams_ptr, isContinued,
			      sourceOut_ptr_ptr, sourceOutSize_ptr, rndWorkBuff_ptr, CC_FALSE/* isStartup*/);

	return error;
}

CCError_t LLF_RND_RunTrngStartupTest(
        CCRndState_t        *rndState_ptr,
        CCRndParams_t       *trngParams_ptr,
        uint32_t                *rndWorkBuff_ptr)
{
	CCError_t error = CC_OK;

	uint32_t        *pSourceOut;
	uint32_t         sourceOutSize;

        error = getTrngSource(rndState_ptr, trngParams_ptr, CC_FALSE/*isContinued*/,
			      &pSourceOut, &sourceOutSize, rndWorkBuff_ptr, CC_TRUE/* isStartup*/);

	return error;
}

static CCError_t startTrngHW(
        CCRndState_t  *rndState_ptr,
        CCRndParams_t *trngParams_ptr,
        CCBool_t           isRestart,
        uint32_t          *roscsToStart_ptr,
        CCSramAddr_t       sramAddr,
        CCBool_t           isStartup)
{
        /* LOCAL DECLARATIONS */

        CCError_t error = CC_OK;
        uint32_t  temp, ehrSamples, tmpSamplCnt = 0;

        /* FUNCTION LOGIC */

        /* Check pointers */
        if ((rndState_ptr == NULL) || (trngParams_ptr == NULL) ||
                (roscsToStart_ptr == NULL))
                return LLF_RND_TRNG_ILLEGAL_PTR_ERROR;

        /*--------------------------------------------------------------*/
        /* 1. If full restart, get semaphore and set initial ROSCs      */
        /*--------------------------------------------------------------*/
        if (isRestart) {
                /* set ROSC to 1 (fastest)  */
                *roscsToStart_ptr = 1UL;

                /* init rndState flags to zero */
                rndState_ptr->TrngProcesState = 0;
        }


        if (*roscsToStart_ptr == 0)
                return LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;

        /* TRNG90B mode  */
        /* Get fastest allowed ROSC */
        error = LLF_RND_GetFastestRosc(
                trngParams_ptr,
                roscsToStart_ptr	 /*in/out*/);
        if (error)
                return error;

        error = LLF_RND_GetRoscSampleCnt(*roscsToStart_ptr, trngParams_ptr);
        if (error)
                return error;

        /*--------------------------------------------------------------*/
        /* 2. Restart the TRNG and set  parameters      		*/
        /*--------------------------------------------------------------*/

        /* enable the HW RND clock   */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

        /* do software reset */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_SW_RESET), 0x1);
        /* in order to verify that the reset has completed the sample count need to be verified */
        do {
                /* enable the HW RND clock   */
                CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

                /* set sampling ratio (rng_clocks) between consequtive bits */
                CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, SAMPLE_CNT1), trngParams_ptr->SubSamplingRatio);

                /* read the sampling ratio  */
                tmpSamplCnt = CC_HAL_READ_REGISTER(CC_REG_OFFSET(RNG, SAMPLE_CNT1));

        } while (tmpSamplCnt != trngParams_ptr->SubSamplingRatio);

        /* disable the RND source for setting new parameters in HW */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_DISABLE_VAL);

        /* set TRNG_CONFIG to choose SOP_SEL = 1 - i.e. EHR output */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, TRNG_CONFIG), LLF_RND_HW_TRNG_WITH_DMA_CONFIG_VAL);


        /* Debug Control register: set to 0 - no bypasses */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, TRNG_DEBUG_CONTROL), LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_TRNG90B_MODE);

        /* set interrupt mask */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_IMR), LLF_RNG_INT_MASK_ON_TRNG90B_MODE);

        /* set EHR samples */
        ehrSamples = ((isStartup == CC_TRUE ? CC_CONFIG_TRNG90B_AMOUNT_OF_BYTES_STARTUP : CC_CONFIG_TRNG90B_AMOUNT_OF_BYTES) / LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES);

        /* Set watchdog threshold to maximal allowed time (in CPU cycles)
        maxTime = (expectTimeInClocks*timeCoeff) */
        temp = LLF_RND_CalcMaxTrngTime(ehrSamples, trngParams_ptr->SubSamplingRatio);
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_WATCHDOG_VAL), temp);

        /* set ROSCS to start and EHR samples from each ROSC to DMA transfer */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_DMA_SRC_MASK), *roscsToStart_ptr);
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_DMA_SAMPLES_NUM), ehrSamples);

        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_DMA_SRAM_ADDR), (uint32_t)sramAddr);

        /* clear RNG interrupts !!TBD */
        temp = 0;
        CC_REG_FLD_SET(HOST_RGF, HOST_ICR, RNG_INT_CLEAR, temp, 1);
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_ICR), temp);
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_ICR), 0xFFFFFFFF);

        /* enable DMA (automatically enables RNG source) */
        CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_DMA_ENABLE), LLF_RND_HW_RND_DMA_ENABLE_VAL);

        /* set indication about current started ROSCs:  */
        /*new started*/
        rndState_ptr->TrngProcesState = (rndState_ptr->TrngProcesState & 0x00ffffff) | (*roscsToStart_ptr << 24);
        /*total started*/
        rndState_ptr->TrngProcesState |= (*roscsToStart_ptr << 8);

        /* end  of function */
        return error;
}

static CCError_t getTrngSource(
				CCRndState_t  *rndState_ptr,	  /*in/out*/
				CCRndParams_t  *trngParams_ptr,   /*in/out*/
				CCBool_t            isContinued,	/*in*/
				uint32_t        **sourceOut_ptr_ptr,   /*out*/
				uint32_t         *sourceOutSize_ptr,/*in/out*/
				uint32_t         *rndWorkBuff_ptr,     /*in*/
				CCBool_t          isStartup)	       /*in*/
{
	/* LOCAL DECLARATIONS */

	/* The return error identifier */
	CCError_t error = 0, descrError = 0;

	int32_t  i;
	uint32_t isr;
	uint32_t tmp;
	uint32_t roscToStart, sizeToProcessBytes;
	CCSramAddr_t sramAddr;
	uint32_t *ramAddr;
	const uint32_t trng90bRequiredBytes = (isStartup == CC_FALSE ? CC_CONFIG_TRNG90B_AMOUNT_OF_BYTES : CC_CONFIG_TRNG90B_AMOUNT_OF_BYTES_STARTUP);

	/* FUNCTION LOGIC */

	/* ............... local initializations .............................. */
	/* -------------------------------------------------------------------- */

	/* initializing the Error to O.K */
	error = CC_OK;

	/* Set source RAM address with offset 8 bytes from sourceOut address in
	  order to remain empty bytes for CC operations */
	*sourceOut_ptr_ptr = rndWorkBuff_ptr + CC_RND_SRC_BUFF_OFFSET_WORDS;
	ramAddr = *sourceOut_ptr_ptr + CC_RND_TRNG_SRC_INNER_OFFSET_WORDS;
	sramAddr = CC_SRAM_RND_HW_DMA_ADDRESS;
	/* init to 0 for FE mode */
	*sourceOutSize_ptr = 0;

        if (isSramSupported(sramAddr) != true) {
                return CC_RND_SRAM_NOT_SUPPORTED_ERROR;
        }

	/* Case of RND KAT or TRNG KAT testing  */
	if (rndState_ptr->StateFlag & CC_RND_KAT_TRNG_Mode) {
		return CC_RND_KAT_DATA_PARAMS_ERROR;
	}

	if (rndState_ptr->StateFlag & CC_RND_KAT_DRBG_Mode) {

		/* set source sizes given by the user in KAT test and placed
		   in the rndWorkBuff with offset CC_RND_SRC_BUFF_OFFSET_WORDS */
		*sourceOutSize_ptr = (*sourceOut_ptr_ptr)[0];
		if (*sourceOutSize_ptr == 0) {
			return CC_RND_KAT_DATA_PARAMS_ERROR;
		}
		goto End;
	}

	/* If not continued mode, set TRNG parameters and restart TRNG 	*/
	/*--------------------------------------------------------------*/
	if (isContinued == CC_FALSE) {

		/* Set instantiation, TRNG errors and time   *
		* exceeding bits of State to 0  	     */
		rndState_ptr->StateFlag &= ~(CC_RND_INSTANTIATED |
					     CC_RND_INSTANTRESEED_AUTOCORR_ERRORS |
					     CC_RND_INSTANTRESEED_TIME_EXCEED |
					     CC_RND_INSTANTRESEED_LESS_ENTROPY);

		/* Full restart TRNG */
                error = startTrngHW(
					   rndState_ptr,
					   trngParams_ptr,
					   CC_TRUE/*isRestart*/,
					   &roscToStart,
					   sramAddr,
					   isStartup);

		/*Note: in case of error the TRNG HW is still not started*/
		if (error)
			goto End;
	}

	/* On continued mode check HW TRNG */
	else {
		/* check TRNG parameters */
		error = LLF_RND_TRNG_CheckHwParams(trngParams_ptr);
		if (error != CC_OK)
			goto End;

		/* previously started ROSCs */
		roscToStart = (rndState_ptr->TrngProcesState & 0xff000000)>>24;
	}

	/*====================================================*/
	/*====================================================*/
	/*         Processing after previous start            */
	/*====================================================*/
	/*====================================================*/

	/*====================================================*/
	/* TRNG90b mode processing: start Roscs sequentionally - *
	* from fast to slow Rosc 			      */
	/*====================================================*/
	sizeToProcessBytes = trng90bRequiredBytes;

	for (i = 0; i < LLF_RND_NUM_OF_ROSCS; ++i) {

		/* wait RNG interrupt: isr signals error bits */
		LLF_RND_WaitRngInterrupt(&isr);

		/* get DMA done status */
		tmp = (isr >> DX_RNG_ISR_RNG_DMA_DONE_BIT_SHIFT) & 1UL;

		/* if DMA done and no HW errors - exit */
		if ((tmp == 1) && ((isr & LLF_RNG_ERRORS_MASK) == 0)) {
			/* update output source size and sramAddr */
			*sourceOutSize_ptr = sizeToProcessBytes;

			if (*sourceOutSize_ptr >= trng90bRequiredBytes) {
				/* copy to RAM and run continuous tests */

				/* Execute BYPASS operation from initial sramAddr */
				CCSramAddr_t sramAddrBase = CC_SRAM_RND_HW_DMA_ADDRESS;

				descrError = LLF_RND_DescBypass(sramAddrBase/*in*/,
								*sourceOutSize_ptr/*inSize*/,
								ramAddr/*out*/);
				if (descrError) {
					/* Note: Priority to SW error */
					error = descrError;
					goto End;
				}

				if (error == CC_OK) {
					error = runContinuousTesting(ramAddr, *sourceOutSize_ptr);
					if (error == CC_OK) {
						break;
					}
					*sourceOutSize_ptr = 0;
				}
			}
		}

		/* update total processed ROSCs */
		rndState_ptr->TrngProcesState |= ((rndState_ptr->TrngProcesState >> 8) & 0x00FF0000);
		/*clean started & not processed*/
		rndState_ptr->TrngProcesState &= 0x00FFFFFF;


		/* case of erors or watchdog exceed  - try next rosc */
		/*  if no remain roscs to start, return error */
		if (roscToStart == 0x8) {
			error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;
			break;
		} else {
			/* Call StartTrng, with next ROSC */
			roscToStart <<= 1;
                        error = startTrngHW(
						   rndState_ptr,
						   trngParams_ptr,
						   CC_FALSE/*isRestart*/,
						   &roscToStart,
						   sramAddr,
						   isStartup);

			if (error != CC_OK)
				goto End;
		}
	}

	/* ................. end of function ..................................... */
	/* ----------------------------------------------------------------------- */
	End:

	CLEAR_TRNG_SRC();
	/* turn the RNG off    */
	if ((rndState_ptr->StateFlag & CC_RND_KAT_TRNG_Mode) == 0) {
		LLF_RND_TurnOffTrng();
	}

	return error;
}/* END of getTrngSource */

/*
implementation of Continuous Testing (NIST SP 800-90B 6.5.1.2)
*/

static CCError_t runContinuousTesting(uint32_t* pData, uint32_t sizeInBytes)
{
	CCError_t error = CC_OK;
	uint32_t repC = CC_CONFIG_TRNG90B_REPETITION_COUNTER_CUTOFF;
	uint32_t adpW = CC_CONFIG_TRNG90B_ADAPTIVE_PROPORTION_WINDOW_SIZE;
	uint32_t adpC = CC_CONFIG_TRNG90B_ADAPTIVE_PROPORTION_CUTOFF;


	error = LLF_RND_RepetitionCounterTest(pData, sizeInBytes, repC);
	if (error != CC_OK) {
		return error;
	}
        error = LLF_RND_AdaptiveProportionTest(pData, sizeInBytes, adpC, adpW);
	if (error != CC_OK) {
		return error;
	}

        return CC_OK;
}

#define UINT8_SIZE_IN_BITS  8
#define UINT32_SIZE_IN_BITS (sizeof(uint32_t) * UINT8_SIZE_IN_BITS)
static uint32_t getBitsFromUint32Array(uint32_t arrayBitsOffset, uint32_t numOfBits, uint32_t* arr)
{
	uint32_t res = 0;
	uint32_t byteOffset = arrayBitsOffset / UINT32_SIZE_IN_BITS;
	uint32_t bitOffset = arrayBitsOffset % UINT32_SIZE_IN_BITS;
	if (numOfBits > UINT32_SIZE_IN_BITS) {
		return 0;
	}
	res = arr[byteOffset] >> bitOffset;
	// (UINT32_SIZE_IN_BITS - bitOffset) bits were taken from the first dword.

	if (UINT32_SIZE_IN_BITS - bitOffset > numOfBits)
	// we copied more bits than required. zero the extra bits.
	{
		res &= (0xFFFFFFFF >> (UINT32_SIZE_IN_BITS - numOfBits));
	} else if (UINT32_SIZE_IN_BITS - bitOffset < numOfBits)
	// we copied less bits than required. copy the next bits from the next dword.
	{
		numOfBits -= UINT32_SIZE_IN_BITS - bitOffset;
		res |= (arr[byteOffset + 1] & (0xFFFFFFFF >> (UINT32_SIZE_IN_BITS - numOfBits))) << (UINT32_SIZE_IN_BITS - bitOffset);
	}

	return res;
}

/*
implementation of Repetition Counter Test (NIST SP 800-90B (2nd Draft) 4.4.1)
C = the cutoff value at which the Repetition Count Test fails
*/
CCError_t LLF_RND_RepetitionCounterTest(uint32_t* pData, uint32_t sizeInBytes, uint32_t C)
{
	uint32_t bitOffset=0;
	uint32_t newSample = 0;
	uint32_t A = 0;			/* the most recently seen sample value */
	uint32_t B = 0;			/* the number of consecutive times that the value A has been seen */
	uint32_t bitsPerSample = 1;	/* always use single bit per sample for repetition counter test */


        if (pData == NULL || sizeInBytes == 0 || LLF_RND_TRNG90B_MAX_BYTES < sizeInBytes) {
		return LLF_RND_TRNG_REPETITION_COUNTER_ERROR;
	}

        // the repetition count test is performed as follows:
	for (bitOffset = 0; bitOffset <= (sizeInBytes * UINT8_SIZE_IN_BITS) - bitsPerSample; bitOffset += bitsPerSample) {
		newSample = getBitsFromUint32Array(bitOffset, bitsPerSample, (uint32_t*)pData);

		// 1. Let A be the current sample value.
        // 2. Initialize the counter B to 1.
		if (bitOffset == 0) {
			A = newSample;
			B = 1;
		}
		// 3. If the next sample value is A, increment B by one.
		else if (A == newSample) {
			++B;
                        // If B is equal to C, return an error.
			if (B == C) {
                                return LLF_RND_TRNG_REPETITION_COUNTER_ERROR;
			}
		} else {
                        // Let A be the next sample value.
			A = newSample;
                        // Initialize the counter B to 1.
			B = 1;
                        // Repeat Step 3.
		}
	}
	return CC_OK;
}

/*
implementation of Adaptive Proportion Test (NIST SP 800-90B (2nd Draft) 4.4.2)
N = the total number of samples that must be observed in one run of the test, also known as the "window size" of the test
C = the cutoff value above which the test should fail
*/
CCError_t LLF_RND_AdaptiveProportionTest(uint32_t* pData, uint32_t sizeInBytes, uint32_t C, uint32_t W)
{
	uint32_t bitOffset=0;
	uint32_t currentSample = 0;
	uint32_t A = 0;         /* the sample value currently being counted */
        uint32_t B = 0;	        /* the current number of times that A has been seen in the S samples examined so far */
        uint32_t i = 0;         /* the counter for the number of samples examined in the current window */
        uint32_t bitsPerSample = 1; /* binary source */

	if (pData == NULL || sizeInBytes == 0 || LLF_RND_TRNG90B_MAX_BYTES < sizeInBytes || W == 0 || C == 0) {
		return LLF_RND_TRNG_ADAPTION_PROPORTION_ERROR;
	}

	// The test is performed as follows:
	for (bitOffset = 0; bitOffset <= (sizeInBytes * UINT8_SIZE_IN_BITS) - bitsPerSample; bitOffset += bitsPerSample) {
		currentSample = getBitsFromUint32Array(bitOffset, bitsPerSample, (uint32_t*)pData);

                // 1. Let A be the current sample value.
                // 2. Initialize the counter B to 1
                if ((bitOffset == 0) || (i == W)) {
                        A = currentSample;
                        B = 1;
                        i = 0;
                }
                // 3. For i = 1 to W-1
                else {
                        // If the next sample is equal to A, increment B by 1.
                        if (A == currentSample) {
                                ++B;
                        }
                }
                // 4. If B > C, return error.
                if (i == W - 1) {
                        if (B > C) {
                                return LLF_RND_TRNG_ADAPTION_PROPORTION_ERROR;
                        }
                }
                ++i;
                // 5. Go to Step 1.
	}
	return CC_OK;
}

