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
#include "cc_rng_plat.h"
#include "dx_crys_kernel.h"
#include "cc_hal.h"
#include "cc_regs.h"
#include "dx_host.h"
#include "cc_rnd_local.h"
#include "cc_rnd_error.h"
#include "llf_rnd_hwdefs.h"
#include "llf_rnd.h"
#include "llf_rnd_error.h"
#include "cc_sram_map.h"
#include "cc_plat.h"
#include "llf_rnd_trng.h"

/* macro for calculation max. allowed time for */
#define LLF_RND_CalcMaxTrngTime(ehrSamples, SubSamplingRatio) \
	(((ehrSamples) * LLF_RND_TRNG_MAX_TIME_COEFF * \
	LLF_RND_TRNG_VON_NEUMAN_COEFF * \
	LLF_RND_HW_TRNG_EHR_WIDTH_IN_BITS * \
	(SubSamplingRatio)) >> LLF_RND_TRNG_MAX_TIME_SCALE)
#define ROSC_INIT_START_BIT   0x80000000


/*********************************** Enums ******************************/
/*********************************Typedefs ******************************/

/**************** Global Data to be read by RNG function ****************/

/* test variables */
#ifdef RND_TEST_TRNG_WITH_ESTIMATOR
uint32_t  gEntrSize[4];
#endif

extern uint32_t LLF_RND_DescBypass(CCSramAddr_t  inSramAddr, uint32_t inSize, uint32_t *outAddr_ptr);

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
    isTrue &= (temp == LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_SWEE_MODE);
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
        /* swee mode - start all allowed ROSCs */
        *roscsToStart_ptr = 0x0f & trngParams_ptr->RoscsAllowed;

		/* init rndState flags to zero */
		rndState_ptr->TrngProcesState = 0;
	}

	if (*roscsToStart_ptr == 0)
		return LLF_RND_TRNG_REQUIRED_ROSCS_NOT_ALLOWED_ERROR;

	/*--------------------------------------------------------------*/
	/* 2. Restart the TRNG and set  parameters      		*/
	/*--------------------------------------------------------------*/

	/* enable the HW RND clock   */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

	/* do software reset */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG, RNG_SW_RESET), 0x1);
	/* in order to verify that the reset has completed the sample count need to be verified */
	do{
		/* enable the HW RND clock   */
		CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_CLK_ENABLE), LLF_RND_HW_RND_CLK_ENABLE_VAL);

		/* set sampling ratio (rng_clocks) between consequtive bits */
		CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,SAMPLE_CNT1), trngParams_ptr->SubSamplingRatio);

		/* read the sampling ratio  */
		tmpSamplCnt = CC_HAL_READ_REGISTER(CC_REG_OFFSET(RNG,SAMPLE_CNT1));

	}while (tmpSamplCnt != trngParams_ptr->SubSamplingRatio);

	/* disable the RND source for setting new parameters in HW */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RND_SOURCE_ENABLE), LLF_RND_HW_RND_SRC_DISABLE_VAL);

	/* set TRNG_CONFIG to choose SOP_SEL = 1 - i.e. EHR output */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,TRNG_CONFIG), LLF_RND_HW_TRNG_WITH_DMA_CONFIG_VAL);


	/* swee mode */
    /* Debug Control register: NC_BYPASS + TRNG_CRNGT_BYPASS + AUTO_CORRELATE_BYPASS set to 1   */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,TRNG_DEBUG_CONTROL), LLF_RND_HW_DEBUG_CONTROL_VALUE_ON_SWEE_MODE);

    /* set interrupt mask */
    CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_IMR), LLF_RNG_INT_MASK_ON_SWEE_MODE);
    ehrSamples = LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_SWEE_MODE;

	/* set ROSCS to start and EHR samples from each ROSC to DMA transfer */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_DMA_SRC_MASK), *roscsToStart_ptr);
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_DMA_SAMPLES_NUM), ehrSamples);

	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_DMA_SRAM_ADDR), (uint32_t)sramAddr);

	/* clear RNG interrupts !!TBD */
	temp = 0;
	CC_REG_FLD_SET(HOST_RGF, HOST_ICR, RNG_INT_CLEAR, temp, 1);                                               \
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_ICR), temp);
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_ICR), 0xFFFFFFFF);

	/* enable DMA (automatically enables RNG source) */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(RNG,RNG_DMA_ENABLE), LLF_RND_HW_RND_DMA_ENABLE_VAL);

	/* set indication about current started ROSCs:  */
	/*new started*/
	rndState_ptr->TrngProcesState = (rndState_ptr->TrngProcesState & 0x00ffffff) | (*roscsToStart_ptr << 24);
	/*total started*/
	rndState_ptr->TrngProcesState |= (*roscsToStart_ptr << 8);

	/* end  of function */
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
	/* LOCAL DECLARATIONS */

	/* The return error identifier */
	CCError_t error = 0;

	uint32_t isr;
	uint32_t tmp;
	uint32_t roscToStart, sizeToProcessBytes,prefRoscIndex;
	CCSramAddr_t sramAddr;
	uint32_t *ramAddr;

	CC_UNUSED_PARAM(isFipsSupported);

	/* FUNCTION LOGIC */

	/* ............... local initializations .............................. */
	/* -------------------------------------------------------------------- */
	/*Set initial value to entropy flag and collectionIndex*/
	int32_t entropyFlag = LLF_RNG_ENTROPY_FLAG_LOW;
	int32_t collectionIndex = 0;
	uint32_t totalEntropyValue = 0;
	uint32_t totalSourceSize = 0;
	uint32_t requirEntropy = 0;

	/* initializing the Error to O.K */
	error = CC_OK;

	/* Set source RAM address with offset 8 bytes from sourceOut address in
	  order to remain empty bytes for CC operations */
	*sourceOut_ptr_ptr = rndWorkBuff_ptr + CC_RND_SRC_BUFF_OFFSET_WORDS;
	ramAddr = *sourceOut_ptr_ptr + CC_RND_TRNG_SRC_INNER_OFFSET_WORDS;
	sramAddr = CC_SRAM_RND_HW_DMA_ADDRESS;
	/* init to 0 for FE mode */
	*sourceOutSize_ptr = 0;

	/* Case of RND KAT or TRNG KAT testing  */
	if ((rndState_ptr->StateFlag & CC_RND_KAT_DRBG_Mode) ||
	    (rndState_ptr->StateFlag & CC_RND_KAT_TRNG_Mode)) {

		/* set source sizes given by the user in KAT test and placed
		   in the rndWorkBuff with offset CC_RND_SRC_BUFF_OFFSET_WORDS */
		*sourceOutSize_ptr = (*sourceOut_ptr_ptr)[0];
		if (*sourceOutSize_ptr == 0) {
			return CC_RND_KAT_DATA_PARAMS_ERROR;
		}

		/* Go to Estimator */
		if (rndState_ptr->StateFlag & CC_RND_KAT_TRNG_Mode) {
			/* Assumed, that KAT data is set in the rnd Work      *
			   buffer as follows:   			      *
			   - full source size set in buffr[0],  	      *
			   - count blocks set in buffr[1],      	      *
			*  - KAT source begins from buffer[2].  	      */
			tmp = (*sourceOut_ptr_ptr)[1]; /*count blocks for estimation*/
			if (tmp == 0) {
				return CC_RND_KAT_DATA_PARAMS_ERROR;
			}
			sizeToProcessBytes = (*sourceOut_ptr_ptr)[0]/tmp;/*one block size*/
			goto Estimator;
		} else
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
		error = LLF_RND_StartTrngHW(
                        rndState_ptr,
                        trngParams_ptr,
					   CC_TRUE/*isRestart*/,
					   &roscToStart,
					   sramAddr);

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

	/*=========================================================*/
	/* Swee mode processing (yet started all 4 ROSCs):
	   wait interrupt, estimate entropy and output the source  */
	/*=========================================================*/
	/* save entropy */
	requirEntropy = *entropySize_ptr;

	/*Perform collection of bits until required entropy is reached or max number of iteration exceeded*/
	while ((entropyFlag == LLF_RNG_ENTROPY_FLAG_LOW) && (collectionIndex <  LLF_RNG_MAX_COLLECTION_ITERATION_SIZE)) {

		/* wait and output irr = RNG_ISR */
		LLF_RND_WaitRngInterrupt(&isr);

		/* source size from one rosc and from all started rosc's*/
		sizeToProcessBytes = LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_SWEE_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_BYTES;

		/* calculate count of rosc's started */
		tmp = LLF_RND_GetCountRoscs(trngParams_ptr->RoscsAllowed, roscToStart);

		/*Calculate size of current and total source size*/
		*sourceOutSize_ptr = tmp * sizeToProcessBytes;
		totalSourceSize += *sourceOutSize_ptr;


		/* Execute BYPASS operation similar to DescBypass() */
		error = LLF_RND_DescBypass(sramAddr/*in*/,
					   *sourceOutSize_ptr/*inSize*/,
					   (uint32_t*)ramAddr/*out*/);
		if (error)
			goto End;



#ifdef BIG__ENDIAN
		/* set endianness */
		for (i = 0; i < (*sourceOutSize_ptr)/4; ++i) {
			ramAddr[i] = CC_COMMON_REVERSE32(ramAddr[i]);
		}
#endif

		Estimator:
		if (requirEntropy != 1) {/*the condition need for performance test */

			error = LLF_RND_EntropyEstimateFull(
							   ramAddr,	      /*in*/
							   sizeToProcessBytes >> 2, /*1 block size, words*/
							   tmp/*count blocks*/,	      /*in*/
							   entropySize_ptr,   /*out*/
							   rndWorkBuff_ptr);	      /*in*/
			if (error)
				goto End;
		}
		/* save entropy size for testing */
		totalEntropyValue += *entropySize_ptr;
		rndState_ptr->EntropySizeBits = totalEntropyValue;

		/* if not KAT mode check entropy */
		if (!(rndState_ptr->StateFlag & (CC_RND_KAT_DRBG_Mode | CC_RND_KAT_TRNG_Mode))) {
			if (totalEntropyValue == 0) {
				error = LLF_RND_TRNG_NULL_ENTROPY_ERROR;
				entropyFlag = LLF_RNG_ENTROPY_FLAG_NULL;

			} else if (totalEntropyValue < requirEntropy) {

				entropyFlag = LLF_RNG_ENTROPY_FLAG_LOW;
				/*If enropy was collected from alowed ROSCs(first time) */
				if (collectionIndex == 0) {
					/* Get index of rosc with best entropy value */
					prefRoscIndex = LLF_RND_GetPreferableRosc(rndWorkBuff_ptr);

					/* Update ROSC for next entropy collection */
					if (prefRoscIndex != 0xf) {
						roscToStart = 1<<prefRoscIndex;
					} else {
						error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;//add relevant error
						goto End;
					}
					/* Update RAM address for next entropy source */
					ramAddr += (sizeToProcessBytes>>2)*tmp;
				} else { /*If entropy was collected from chosen ROSC*/
					/* Update RAM address for next entropy source */
					ramAddr +=  (LLF_RND_HW_DMA_EHR_SAMPLES_NUM_ON_SWEE_MODE * LLF_RND_HW_TRNG_EHR_WIDTH_IN_WORDS);
				}

				/*Start TRNG with updated ROSC*/
				error = LLF_RND_StartTrngHW(
                                rndState_ptr,
                                trngParams_ptr,
							   CC_FALSE/*isRestart*/,
							   &roscToStart,
							   sramAddr);
				if (error)
					goto End;

				/*In case this is the last collection iteration, save the low entropy error for return*/
				error = LLF_RND_TRNG_LOW_ENTROPY_ERROR;

			} else if (totalEntropyValue >= requirEntropy) {
				entropyFlag = LLF_RNG_ENTROPY_FLAG_REQUIRED;
				/*Update output source size and entropy*/
				*sourceOutSize_ptr = totalSourceSize;
				*entropySize_ptr = totalEntropyValue;
				error = 0;
			}

		} else { /*KAT mode*/

			entropyFlag = LLF_RNG_ENTROPY_FLAG_KAT_MODE;
		}
		collectionIndex++;
	}
	if (entropyFlag == LLF_RNG_ENTROPY_FLAG_KAT_MODE) {
		/* update processed ROSCs */
		rndState_ptr->TrngProcesState |= ((rndState_ptr->TrngProcesState >> 8) & 0x00FF0000);
		/*clean started & not processed*/
		rndState_ptr->TrngProcesState &= 0x00FFFFFF;
	} else {
		goto End;
	}
	/* end swee mode */


	/* ................. end of function ..................................... */
	/* ----------------------------------------------------------------------- */
	End:

	CLEAR_TRNG_SRC();
	/* turn the RNG off    */
	if ((rndState_ptr->StateFlag & CC_RND_KAT_TRNG_Mode) == 0) {
		LLF_RND_TurnOffTrng();
	}

	return error;


}/* END of LLF_RND_GetTrngSource */

CCError_t LLF_RND_RunTrngStartupTest(
        CCRndState_t        *rndState_ptr,
        CCRndParams_t       *trngParams_ptr,
        uint32_t                *rndWorkBuff_ptr)

{
        CCError_t error = CC_OK;
        CC_UNUSED_PARAM(rndState_ptr);
        CC_UNUSED_PARAM(trngParams_ptr);
        CC_UNUSED_PARAM(rndWorkBuff_ptr);

        return error;
}


