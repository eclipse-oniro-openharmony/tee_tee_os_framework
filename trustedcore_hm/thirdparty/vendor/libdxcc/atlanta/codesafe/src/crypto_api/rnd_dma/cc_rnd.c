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

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_pal_log.h"
#include "cc_rng_plat.h"
#include "cc_common.h"
#include "cc_common_math.h"
#include "cc_rnd.h"
#include "cc_rnd_error.h"
#include "cc_rnd_local.h"
#include "llf_rnd.h"
#include "llf_rnd_trng.h"
#include "llf_rnd_error.h"
#include "cc_pal_abort.h"
#include "cc_pal_mutex.h"
#include "cc_fips_defs.h"

/* CC RND module version compliant to NIST 800-90 standard. Based on CTR DRBG Block Cipher (AES) */

/************************ Defines ******************************/

/*********************************** Enums ******************************/

/*********************************Typedefs ******************************/
/* rotate 32-bits word by 16 bits */
#define RND_ROT32(x) ( (x) >> 16 | (x) << 16 )

/* inverse the bytes order in a word */
#define RND_REVERSE32(x)  ( ((RND_ROT32((x)) & 0xff00ff00UL) >> 8) | ((RND_ROT32((x)) & 0x00ff00ffUL) << 8) )

/**************** Global Data to be read by RNG function ****************/

extern CC_PalMutex *pCCRndCryptoMutex;
extern CC_PalMutex *pCCGenVecMutex;

/************************************************************************************/
/***********************           Private functions            *********************/
/************************************************************************************/

/**
 *      The function adds value to the number N, presented as bytes array
 *      iv_ptr, where MSbyte is a most left one.
 *
 *      Algorithm:
 *          n = (iv + val) mod 2^(8*sizeBytes).
 *      Assumed: The array (AES IV) has size 8 bytes and is aligned to 32-bit
 *               words. The val is > 0.
 *
 * @author reuvenl (7/1/2012)
 *
 * @param iv_ptr
 * @param val - value to add
 */
static void RndAddValToIv(uint32_t *iv_ptr, uint32_t val)
{
        int32_t i;
        uint32_t *ptr = iv_ptr;
        uint32_t tmp, curr;

        for (i = 3; i >= 0; i--) {
#ifndef BIG__ENDIAN
                tmp = curr = RND_REVERSE32(ptr[i]);
#else
                tmp = curr = ptr[i];
#endif
                tmp += val;

#ifndef BIG__ENDIAN
                ptr[i] = RND_REVERSE32(tmp);
#else
                ptr[i] = tmp;
#endif

                if (tmp < curr)
                        val = 1;
                else
                        break;
        }
}

/********************************************************************************
  @brief This function subtracts a value from a large vector presented in the buffer.
         The LSB of the counter is stored in the left most cell.

  @return signed value of carry (borrow)
 */

static uint8_t AddInt8ValueToUin8Vector(uint8_t  *vect, /*! [in]  vect - the buffer containing the vector. */
					int8_t    val,  /*! [in]  val  - the value to add/subtract (according to its sign). */
					uint32_t  vectSizeInBytes) /*! [in]  vectSizeInBytes - the vector size in bytes. */
{
        /* DECLARATIONS */

        /* loop index */
	uint32_t i;
	int32_t temp;

	/* FUNCTION LOGIC */

	temp = val;

        for (i = 0; i < vectSizeInBytes; i++) {
                temp = vect[i] + val;
                vect[i] = (uint32_t)temp & 0xFF;
                val = (temp >> 8) & 0xFF;
	}

	return val;

}/* End of AddInt8ValueToUin8Vector() */


/****************************************************************************************/
/**
  @brief The function performs NIST 800-90, 10.2.1.2. algorithm of Update function.

  @param [in/out] rndState_ptr  - Pointer to the RND internal state buffer.
  @param [in/out] State - The pointer to the internal State buffer of DRNG.
  @param [in] providedData_ptr - The pointer to provided data buffer. The size of data
                                must be exactly of size of Seed.
  @param [in/out] seed_ptr - The pointer to the Seed = (Key || V) buffer.
  @param [in] skipSetUp - Flag, if set, then first two steps of algorithm sould be skipped.
  @param [in/out] aesCtxID_ptr - The pointer to AES context.

    Note: Updated result (Key||V) are in Seed buffer of the State.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
static CCError_t RndUpdate(
                                CCRndState_t    *rndState_ptr,      /*in/out*/
                                uint8_t             *providedData_ptr,    /*in*/
                                uint8_t             *seed_ptr,      /*in/out - Key,V*/
                                uint8_t              skipSetUp)     /*in*/
{
	/* LOCAL DECLARATIONS */

	CCError_t  error = CC_OK;
	uint32_t keySizeWords;
	/* size of seed */
	uint32_t seedSizeInWords;
	CCAesUserContext_t aesCtxID;
	CCAesUserKeyData_t keyData;

	/* pointers to current key and iv  */
	uint8_t *k_ptr, *iv_ptr;


	/* FUNCTION LOGIC */

	/* Initializations */

	keySizeWords = rndState_ptr->KeySizeWords;

	/* seed size in AES blocks */
	seedSizeInWords = keySizeWords + CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS;

	/* set key and iv pointers */
	k_ptr = (uint8_t*)&seed_ptr[0];
	iv_ptr = (uint8_t*)&seed_ptr[keySizeWords*sizeof(uint32_t)];

	/*----------------------------------------------------------------- */
	/*    NIST 800-90, 10.2.1.2. Algorithm of Update function           */
	/*  Where: output performed into StateSeed buffer without using of  */
	/*        temp buffer                                               */
	/*----------------------------------------------------------------- */

	/* Init AES operation on CTR mode */
	error = CC_AesInit(&aesCtxID, CC_AES_ENCRYPT, CC_AES_MODE_CTR, CC_AES_PADDING_NONE);
	if (error != CC_OK) {
		return error;
	}

	keyData.pKey = k_ptr;
	keyData.keySize = keySizeWords*sizeof(uint32_t);
	error = CC_AesSetKey(&aesCtxID, CC_AES_USER_KEY, (void*)&keyData, sizeof(keyData));
	if (error != CC_OK) {
		return error;
	}

	error = CC_AesSetIv(&aesCtxID, iv_ptr);
	if (error != CC_OK) {
		return error;
	}

	/* if not set skipSetUp flag, then perform one dummy encrypt for
	   incrementing IV */
	if (!skipSetUp) {
		/* Dummy encrypt for increment the IV:  		      *
		   V = (V+1) mod 2^outLenBits  				      */
		error =  CC_AesBlock(&aesCtxID,
				       providedData_ptr,
				       CC_AES_BLOCK_SIZE_IN_BYTES,
				       seed_ptr);
		if (error != CC_OK)
			return error;
	}

	/* 2.2. Encrypt the SEED on AES CTR mode */
	{
		size_t dataSize = seedSizeInWords*sizeof(uint32_t);
		error = CC_AesFinish(&aesCtxID,
				       dataSize,
				       providedData_ptr, /*in*/
				       dataSize,
				       seed_ptr,  /*out*/
				       &dataSize );
	}

	return error;

} /* End of RndUpdate */


/****************************************************************************************/
/**
  @brief The function performs NIST 800-90, 10.2.1.4.2. algorithm of
         Seed Derivation function.

  @param [in/out] rndState_ptr - The pointer to RND internal State buffer.
  @param [in] inputBuff_ptr - The pointer to input buffer, containing the input seed source
       		      data, placed beginning from byte 8 and additional (at less 16)
       		      empty bytes for padding. The size of the buffer must be
       		      at less (8 + inputDataSizeBytes + 16) bytes.
  @param [in] inputDataSizeBytes - The size in bytes of the input data = actual size of
                                  input seed source data to process (must be multiple of 4 bytes).
  @param [out] output_ptr - The pointer to the output data buffer.
                           The size (in bytes) of the buffer and output data
                           are equal to (AES key size + AES block size).
  @param [in] outDataSizeBytes - The size of output data. According to NIST 800-90
                                the size must be <= 64 bytes.

    Note: Overlapping of inputBuff and output is not allowed.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
static CCError_t RndDf(
                            CCRndState_t    *rndState_ptr,              /*in/out*/
                            uint32_t            *inputBuff_ptr,     /*in*/
                            uint32_t            inputDataSizeBytes,         /*in*/
                            uint8_t            *output_ptr,                 /*out*/
                            size_t            outDataSizeBytes)           /*in*/
{
	/* LOCAL DECLARATIONS */

	CCError_t  error = CC_OK;

	CCAesUserContext_t    aesContext;
	CCAesUserKeyData_t keyData;

	/* AES key size in words (defining also security strength) and its ID */
	uint32_t keySizeWords;
	/* pointers to precomputed initial MAC vectors (two-dimensional) and  *
	*  current key and iv   					      */
	uint8_t *initMac_ptr, *iv_ptr;
	/* loop counter */
	uint32_t i;
        /* padded data size */
        uint32_t paddedDataSizeBytes;

	/* temp ptr */
	uint8_t *inputPtr;

	/*   Data for Security Strength = 128 and 256 bit.
		 Note: Key buffer is common for 128 and 256 bits*/
	const uint8_t Key[32] =
	{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
			0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F};
	const uint8_t InitialMac128[2][CC_RND_BASIC_BLOCK_SIZE_IN_BYTES] =
	{{0xc6,0xa1,0x3b,0x37,0x87,0x8f,0x5b,0x82,0x6f,0x4f,0x81,0x62,0xa1,0xc8,0xd8,0x79},
			{0x95,0x03,0xe3,0xa2,0x24,0x5a,0x2b,0xe4,0x3c,0x98,0x74,0xed,0xfe,0x1b,0xed,0x9e}};
	const uint8_t InitialMac256[3][CC_RND_BASIC_BLOCK_SIZE_IN_BYTES] =
	{{0xF2,0x90,0x00,0xB6,0x2A,0x49,0x9F,0xD0,0xA9,0xF3,0x9A,0x6A,0xDD,0x2E,0x77,0x80},
			{0x9D,0xBA,0x41,0xA7,0x77,0xF3,0xB4,0x6A,0x37,0xB7,0xAA,0xAE,0x49,0xD6,0xDF,0x8D},
			{0x2F,0x7A,0x3C,0x60,0x07,0x08,0xD1,0x24,0xAC,0xD3,0xC5,0xDE,0x3B,0x65,0x84,0x47}};


	/* FUNCTION LOGIC */

	/* Initializations */

	keySizeWords = rndState_ptr->KeySizeWords;

        if (keySizeWords != CC_RND_AES_KEY_128_SIZE_WORDS &&
            keySizeWords != CC_RND_AES_KEY_256_SIZE_WORDS) {
                return CC_RND_ILLEGAL_AES_KEY_SIZE_ERROR;
	}
	if (outDataSizeBytes != (keySizeWords*sizeof(uint32_t) + CC_AES_BLOCK_SIZE_IN_BYTES)) {
                return CC_RND_ILLEGAL_DATA_SIZE_ERROR;
	}

	inputPtr = (uint8_t*)inputBuff_ptr;
	/*----------------------------------------------------------------- */
	/* [1]: NIST 800-90, 10.2.1.4.2. Block_Cipher_df Process.           */
	/*      Algorithm of Seed Derivation function   		    */
	/*  Note: step 8 is done because init Key and IV are hard coded     */
	/*----------------------------------------------------------------- */

	/* Set L, N and padding 0x80....0 in the input buffer.
	   Note: input data was set before; L, N values must be in bytes  */
	#ifdef BIG__ENDIAN
	((uint32_t*)inputBuff_ptr)[0] = inputDataSizeBytes; /* L */
	((uint32_t*)inputBuff_ptr)[1] = outDataSizeBytes;   /* N */
	#else
	/* convert L,N to little endian */
	((uint32_t*)inputBuff_ptr)[0] = CC_COMMON_REVERSE32(inputDataSizeBytes); /* L */
	((uint32_t*)inputBuff_ptr)[1] = CC_COMMON_REVERSE32(outDataSizeBytes);   /* N */
	#endif
        /* size of padded data for AES MAC */
        paddedDataSizeBytes = CC_RND_TRNG_SRC_INNER_OFFSET_BYTES + inputDataSizeBytes + 1;
	inputPtr[paddedDataSizeBytes-1] = 0x80;
        /* set size of input to AES-MAC, rounded up to AES block */
        inputDataSizeBytes = ((paddedDataSizeBytes + CC_AES_BLOCK_SIZE_IN_BYTES - 1) / CC_AES_BLOCK_SIZE_IN_BYTES) * CC_AES_BLOCK_SIZE_IN_BYTES;
        /* zeroe padding */
	CC_PalMemSet(&inputPtr[paddedDataSizeBytes], 0, inputDataSizeBytes - paddedDataSizeBytes);


	/*****************************************************
	* [1] 12: Compression of seed source material        *
	******************************************************/

	for (i = 0; i < (outDataSizeBytes/CC_RND_BASIC_BLOCK_SIZE_IN_BYTES); i++) {

		/* set pointer to initial precomputed IV  value */
		if (keySizeWords == CC_RND_AES_KEY_128_SIZE_WORDS) {
			initMac_ptr = (uint8_t*)&InitialMac128[i][0];
		} else {
			initMac_ptr = (uint8_t*)&InitialMac256[i][0];
		}

		/* AES MAC */
		error = CC_AesInit(&aesContext, CC_AES_ENCRYPT, CC_AES_MODE_CBC_MAC, CC_AES_PADDING_NONE);
		if (error != CC_OK) {
			return error;
		}

		keyData.pKey = (uint8_t*)&Key[0];
		keyData.keySize = keySizeWords*sizeof(uint32_t);
		error = CC_AesSetKey(&aesContext, CC_AES_USER_KEY, (void*)&keyData, sizeof(keyData));
		if (error != CC_OK) {
			return error;
		}

		error = CC_AesSetIv(&aesContext, initMac_ptr);
		if (error != CC_OK) {
			return error;
		}

		{
			size_t dataOutSize = CC_AES_BLOCK_SIZE_IN_BYTES;
			error = CC_AesFinish(&aesContext,
						   inputDataSizeBytes,
						   inputPtr,
						   inputDataSizeBytes,
						   output_ptr + i*CC_AES_BLOCK_SIZE_IN_BYTES, /*output*/
						   &dataOutSize );
			if (error) {
				return error;
			}
		}
	}

        /* set K and IV pointers and sizes for AES_CTR encryption */
	keyData.pKey = (uint8_t*)output_ptr;
	keyData.keySize = keySizeWords*sizeof(uint32_t);
	iv_ptr = (uint8_t*)output_ptr + keySizeWords*sizeof(uint32_t);

	/* Encrypt (K,IV) by AES-CBC using output buff */
	error = CC_AesInit(&aesContext, CC_AES_ENCRYPT, CC_AES_MODE_CBC, CC_AES_PADDING_NONE);
	if (error != CC_OK) {
		return error;
	}

	error = CC_AesSetKey(&aesContext, CC_AES_USER_KEY, (void*)&keyData, sizeof(keyData));
	if (error != CC_OK) {
		return error;
	}

	error = CC_AesSetIv(&aesContext, iv_ptr);
	if (error != CC_OK) {
		return error;
	}

	CC_PalMemSet(output_ptr, 0, outDataSizeBytes);

	error = CC_AesFinish(&aesContext,
			       outDataSizeBytes,
			       output_ptr/*in*/,
			       outDataSizeBytes,
			       output_ptr,/*out*/
			       &outDataSizeBytes);
	return error;

} /* END of RndDf */


/****************************************************************************************/
/**
  @brief The function performs: NIST 800-90, 10.2.1.3.2  Instantiate function or
         NIST 800-90, 10.2.1.4.2 Reseeding function, according to given flag.

  @param [in/out] rndContext_ptr - The pointer to the internal State buffer of DRNG.
  @param [in] isInstantiate - The flag defining which algorithm to perform:
                             0 - Instantiate; 1 - Reseeding.
  @param isContinued[in] isContinued - The variable indicates is the required process should
                   continue a  previous one or restart TRNG.
  @param [in/out] workBuff_ptr - The temp buffer for specific operations
       			 on entropy generation and estimation.

       NOTE! The function works according to TRNG random source generation state as follows:

       	1. If isContinued = 0, i.e. indicates that the TRNG was not started
       	   previously, the function starts it, else waits to end of TRNG generation.
       	2. Performs deterministic part of NIST CTR_DRBG Instantiation or Reseeding algorithm.

       NOTE!! To ensure, that the function not uses the results from previous started TRNG, the user must
              call CC_RndUnInstantiation function previously to this function.


  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in cc_error.h
 */
static CCError_t RndInstantiateOrReseed(
                                             CCRndContext_t     *rndContext_ptr,    /*in/out*/
                                             CCBool_t              isInstantiate,   /*in*/
                                             CCBool_t              isContinued,     /*in*/
                                             CCRndWorkBuff_t  *workBuff_ptr )   /*in/out*/
{

        /* LOCAL DECLARATIONS */

        /* error identifier definition */
        CCError_t error = CC_OK;

        uint32_t  *entrSource_ptr;
        uint32_t  keySizeWords, entropySizeBits;
        uint32_t  sourceSizeBytes;
        size_t    seedSizeBytes;
        /* TRNG parameters structure */
        CCRndParams_t  trngParams;

        CCRndState_t   *rndState_ptr;
        bool isFipsSupported = true;


        /* FUNCTION LOGIC */

        /* ............. check parameters ............... */

        if (rndContext_ptr == NULL)
                return CC_RND_STATE_PTR_INVALID_ERROR;

        rndState_ptr = &(rndContext_ptr->rndState);

        if (workBuff_ptr == NULL)
                return CC_RND_WORK_BUFFER_PTR_INVALID_ERROR;

        /* for Reseeding check valid tag and Instantiation done bit */
        if (isInstantiate == CC_FALSE) {
                if (rndState_ptr->ValidTag != CC_RND_WORK_STATE_VALID_TAG)
                        return CC_RND_STATE_VALIDATION_TAG_ERROR;

                if (!(rndState_ptr->StateFlag & CC_RND_INSTANTIATED))
                        return CC_RND_INSTANTIATION_NOT_DONE_ERROR;
        }
        /* for instantiation, set RND generate function ptr to NULL */
        else {
                rndContext_ptr->rndGenerateVectFunc = NULL;
        }

        /* set users TRNG parameters into rndState structure */
        if (isContinued == CC_FALSE) {
                error = RNG_PLAT_SetUserRngParameters(rndState_ptr, &trngParams);
                if (error != CC_OK)
                        return error;
        }

        /* key size */
        keySizeWords = rndState_ptr->KeySizeWords;

        /* check user passed key size and additional data sizes */

        if (keySizeWords != CC_RND_AES_KEY_128_SIZE_WORDS &&
            keySizeWords != CC_RND_AES_KEY_256_SIZE_WORDS)
                return CC_RND_ILLEGAL_AES_KEY_SIZE_ERROR;

        if (rndState_ptr->AddInputSizeWords > CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS)
                return CC_RND_ADDITIONAL_INPUT_SIZE_ERROR;

        /* Set Entropy size according to operation mode and security strength:
             - for reseeding: entropySize = keySize;
             - for instantiation: entropySize = keySize + keySize/2, note: in
               the last case the size includes a random Nonce*/
        if (isInstantiate == 0)
                entropySizeBits = keySizeWords*32; /*Reseeding*/
        else
                entropySizeBits = (keySizeWords + CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS)*32; /*Instantiation*/


        /* Get entropy (including random Nonce) from TRNG and set
          it into Entropy Temp buffer. Update the needed size of
          TRNG source for receiving required entropy. Note:     */
        /*--------------------------------------------------------*/
        CHECK_FIPS_SUPPORTED(isFipsSupported);

        error = LLF_RND_GetTrngSource(
                                     rndState_ptr,    /*in/out*/
                                     &trngParams,       /*in/out*/
                                     isContinued,       /*in*/
                                     &entropySizeBits,  /*in/out*/
                                     &entrSource_ptr,   /*out*/
                                     &sourceSizeBytes,  /*out*/
                                     (uint32_t*)workBuff_ptr /*in*/,
                                     isFipsSupported);

        if (error != CC_OK)
                goto EndWithError;

        /* Set additional data into work buffer */
        CC_PalMemCopy(
                      (uint8_t*)&entrSource_ptr[(sourceSizeBytes>>2)+CC_RND_TRNG_SRC_INNER_OFFSET_WORDS],
                      (uint8_t*)&rndState_ptr->AdditionalInput[0],
                      sizeof(uint32_t)*rndState_ptr->AddInputSizeWords);

        /*--------------------------------------------------------------------- */
        /*   [1] NIST 800-90: 10.2.1.3.2  Instantiate or  10.2.1.4.2 Reseeding  */
        /*--------------------------------------------------------------------- */
        /* set input and output data sizes for DF */
        sourceSizeBytes += sizeof(uint32_t)*rndState_ptr->AddInputSizeWords;
        seedSizeBytes = keySizeWords*sizeof(uint32_t) + CC_AES_BLOCK_SIZE_IN_BYTES;


        /* 2.1. if Derivation Function is used, call it */
        error = RndDf(
                         rndState_ptr,                    /*in*/
                         entrSource_ptr,  /*in buffer - data starts from */
                         sourceSizeBytes,           /*in - size of entropy  */
                         (uint8_t*)&rndState_ptr->AdditionalInput[0],  /*out - seed material*/
                         seedSizeBytes);            /*in*/


        if (error != CC_OK)
                goto EndWithError;

        /* 3,4: Set Key = 0x00000... and IV = 0x0000... into Seed buffer */
        if (isInstantiate == 1)
                CC_PalMemSetZero(rndState_ptr->Seed, sizeof(uint32_t)*(keySizeWords + CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS));


        /* 2.2. Call Update for Additional data */
        error = RndUpdate(
                             rndState_ptr,     /*in/out*/
                             (uint8_t*)&rndState_ptr->AdditionalInput[0],        /*in - provided data*/
                             (uint8_t*)&rndState_ptr->Seed[0], /*in/out - Key||V inside the state: */
                             0);                /*in - skipSetUp*/

        if (error != CC_OK)
                goto EndWithError;

        /* [1] 6:  Reset State parameters           */
        /*------------------------------------------*/

        rndState_ptr->ReseedCounter = 1;

        /* Set Instantiation flag = 1 (because it was zeroed in TRNG) */
        rndState_ptr->StateFlag |= CC_RND_INSTANTIATED;

        /* Set a valid tag and disable previous value flag (only for
           Instantiation mode) */
        if (isInstantiate == 1) {
                rndState_ptr->ValidTag = CC_RND_WORK_STATE_VALID_TAG;
                rndState_ptr->StateFlag &= ~CC_RND_PreviousIsValid;
        }

        /* Clean additional input buffer */
        rndState_ptr->AddInputSizeWords = 0;
        CC_PalMemSetZero(rndState_ptr->AdditionalInput, sizeof(rndState_ptr->AdditionalInput));

        goto End;


        EndWithError:

        /* In case of error, clean the secure sensitive data from rndState */
        CC_PalMemSetZero(rndState_ptr, sizeof(CCRndState_t));
        if (error == LLF_RND_CRNGT_TEST_FAIL_ERROR)
        {
                error = LLF_RND_TRNG_GENERATION_NOT_COMPLETED_ERROR;
                CC_FIPS_SET_RND_CONT_ERR();
        }

        End:
        CC_PalMemSetZero((uint8_t*)workBuff_ptr, sizeof(CCRndWorkBuff_t));

        return error;

} /* End of RndInstantiateOrReseed function */


/****************************************************************************************/
/*****************************       Public Functions      ******************************/
/****************************************************************************************/


/****************************************************************************************/
/**

  @brief The function set the RND Generate vector function, provided by the User.

  @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
  @param [in] rndGenerateVectFunc - The pointer to RND Generate vector function.

  @return CCError_t - no return value
 */
CCError_t CC_RndSetGenerateVectorFunc(CCRndContext_t *rndContext_ptr,
					   CCRndGenerateVectWorkFunc_t rndGenerateVectFunc)
{

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* check parameters */
        if (rndContext_ptr == NULL)
                return CC_RND_CONTEXT_PTR_INVALID_ERROR;
        if (rndGenerateVectFunc == NULL)
                return CC_RND_GEN_VECTOR_FUNC_ERROR;


        rndContext_ptr->rndGenerateVectFunc = rndGenerateVectFunc;

        return 0;
} /* End of RNG_PLAT_SetUserRngParameters */



/****************************************************************************************/
/**
  @brief The function performs NIST 800-90, 10.2.1.5.2 algorithm of Generate function.

  NOTE: The function should change the data in given output buffer also if an error occurs.

  @param [in/out] rndState_ptr  - Pointer to the RND state buffer.
  @param [out] outSizeBytes - The required size of random data in bytes.
  @param [in] out_ptr - The pointer to output buffer.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
CEXPORT_C CCError_t CC_RndGenerateVector(CCRndState_t *rndState_ptr,
					      size_t    outSizeBytes,   /*in*/
					      uint8_t   *out_ptr)        /*out*/
{
	/* LOCAL DECLARATIONS */

	CCError_t  error = CC_OK;

	uint32_t keySizeWords;
    size_t seedSizeWords;
	uint32_t remainBytes, countBlocks;
	CCAesUserContext_t  AesUserContext;
	CCAesUserKeyData_t keyData;

	uint32_t *temp;


	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	/* ................... checking parameters validity ..................... */
	/* ---------------------------------------------------------------------- */

	if (rndState_ptr == NULL){
		return CC_RND_CONTEXT_PTR_INVALID_ERROR;
	}

	if (out_ptr == NULL) {
		return CC_RND_DATA_OUT_POINTER_INVALID_ERROR;
	}

	if (outSizeBytes == 0) {
		return CC_OK ; /* because of PSS*/
	}

	/* Verify max value of outSizeBytes */
	if (outSizeBytes > 0xFFFF)
		return CC_RND_ILLEGAL_PARAMETER_ERROR;

	error = CC_PalMutexLock(pCCGenVecMutex, CC_INFINITE);
	if (error != CC_OK) {
		CC_PalAbort("Fail to acquire mutex\n");
	}

	if (rndState_ptr->ValidTag != CC_RND_WORK_STATE_VALID_TAG) {
		error = CC_RND_STATE_VALIDATION_TAG_ERROR;
		goto End;
	}

	/* Check, that instantiation was done */
	if (!(rndState_ptr->StateFlag & CC_RND_INSTANTIATED)) {
		error = CC_RND_INSTANTIATION_NOT_DONE_ERROR;
		goto End;
	}

	/* [1] 1: Check Reseed counter in the rndState
	Note: In [1] reseedCounter must be less than 2^48. In our implementation
	supplied more severe limitation of this parameter (counter < 2^32) that
	may only increase security */
	if (rndState_ptr->ReseedCounter >= CC_RND_MAX_RESEED_COUNTER) {
		error = CC_RND_RESEED_COUNTER_OVERFLOW_ERROR;
		goto End;
	}

	/* Initializations */
	/*-----------------*/
	temp = rndState_ptr->PreviousAdditionalInput;

	/* Set key and seed sizes */
	keySizeWords = rndState_ptr->KeySizeWords;
	seedSizeWords = keySizeWords + CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS;

	/* check user provided parameters */
	if (keySizeWords != CC_RND_AES_KEY_128_SIZE_WORDS &&
	    keySizeWords != CC_RND_AES_KEY_256_SIZE_WORDS) {
		error = CC_RND_ILLEGAL_AES_KEY_SIZE_ERROR;
		goto End;
	}

	if (rndState_ptr->AddInputSizeWords > CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS) {
		error = CC_RND_ADDITIONAL_INPUT_SIZE_ERROR;
		goto End;
	}

	/* Function logic  */
	/*-----------------*/

	/*----------------------------------------------------------------- */
	/*   [1] NIST 800-90, 10.2.1.5.2. CTR_DRBG Generate Process         */
	/*----------------------------------------------------------------- */

	/* [1] 2:  If additional input valid, then call Derivation and Update functions */
	if (rndState_ptr->AddInputSizeWords  > 0) {

		/* move additional data two words right for DF operation */
		CC_PalMemCopy( (uint8_t*)&temp[CC_RND_TRNG_SRC_INNER_OFFSET_WORDS],
				 (uint8_t*)&rndState_ptr->AdditionalInput[0],
				 sizeof(uint32_t)*rndState_ptr->AddInputSizeWords);

		/* 2.1. Derivation Function call. If prediction resistance */
		error = RndDf(rndState_ptr,                                     /*in*/
				   &temp[0], /*in - AdditionalInput*/
				   sizeof(uint32_t)*rndState_ptr->AddInputSizeWords, /*in - AddInputSizeWords*/
				   (uint8_t*)&rndState_ptr->AdditionalInput[0],      /*out - recalculated additional data*/
				   sizeof(uint32_t)*seedSizeWords);                  /*in*/
		if (error != CC_OK) {
			goto End;
		}

		/* 2.2. Call Update with recalculated additional (provided) data */
		error = RndUpdate(rndState_ptr,  /*in/out*/
				       (uint8_t*)&rndState_ptr->AdditionalInput[0], /*in - provided data*/
				       (uint8_t*)&rndState_ptr->Seed[0],            /*in/out - Key||V*/
				       0);   /*in - skipSetUp*/
		if (error != CC_OK) {
			goto End;
		}
	} else {   /* 2.3. Set AdditionalInput = 000000...0  */
		CC_PalMemSetZero(rndState_ptr->AdditionalInput, sizeof(rndState_ptr->AdditionalInput));
	}


	/*------------------------------------------------------------------------------*/
	/* [1] 4: Calculation of random: In loop {V = V+1; out = AES_ECB(Key,CTR=V)}    */
	/*        Note: This algorithm is equaled to out = AES_CTR(Key,dataIn=00000...) */
	/*------------------------------------------------------------------------------*/

	/*   Initialization of AES engine with calculated Key on CTR mode */

	/* Increment counter V = V+1 */
	RndAddValToIv(&rndState_ptr->Seed[keySizeWords], 1/*val*/);

	/* Init AES operation on CTR mode */
	error = CC_AesInit(&AesUserContext, CC_AES_ENCRYPT, CC_AES_MODE_CTR, CC_AES_PADDING_NONE);
	if (error != CC_OK) {
		goto End;
	}

	keyData.pKey = (uint8_t*)&rndState_ptr->Seed[0];
	keyData.keySize = keySizeWords*sizeof(uint32_t);
	error = CC_AesSetKey(&AesUserContext, CC_AES_USER_KEY, (void*)&keyData, sizeof(keyData));
	if (error != CC_OK) {
		goto End;
	}

	error = CC_AesSetIv(&AesUserContext, (uint8_t*)&rndState_ptr->Seed[keySizeWords]);
	if (error != CC_OK) {
		goto End;
	}

	/* If mode is working mode and previous generated block is not valid,*
	*  then generate one dummy block and save it as previous value        */
	if (!(rndState_ptr->StateFlag & CC_RND_KAT_Mode) &&
		!(rndState_ptr->StateFlag & CC_RND_PreviousIsValid)) {

		CC_PalMemSetZero(rndState_ptr->PreviousRandValue, sizeof(rndState_ptr->PreviousRandValue));

		error = CC_AesBlock(&AesUserContext,
				      (uint8_t*)&rndState_ptr->PreviousRandValue[0],
				      CC_AES_BLOCK_SIZE_IN_BYTES,
				      (uint8_t*)&rndState_ptr->PreviousRandValue[0]);
		if (error != CC_OK) {
			goto End;
		}

		/* set previous valid */
		rndState_ptr->StateFlag |= CC_RND_PreviousIsValid;
	}

	/* calculate remaining size in bytes  (must be > 0 for       *
	*  finish operation) */
	remainBytes = outSizeBytes & (CC_AES_BLOCK_SIZE_IN_BYTES-1);
	countBlocks = outSizeBytes >> 4;
	if (remainBytes == 0) {
		remainBytes = CC_AES_BLOCK_SIZE_IN_BYTES;
	} else {
		countBlocks++;
	}

	/* generate full blocks of input data */
	if (outSizeBytes - remainBytes > 0) {

		CC_PalMemSetZero(out_ptr, outSizeBytes-remainBytes);

		error = CC_AesBlock(&AesUserContext,
				      out_ptr,
				      outSizeBytes - remainBytes,
				      out_ptr);
		if (error != CC_OK) {
			goto End;
		}
	}

	/* save PreviousRandValue in temp buffer */
	CC_PalMemCopy(temp, rndState_ptr->PreviousRandValue, sizeof(rndState_ptr->PreviousRandValue));

	/* Generate full random block for last output data */
	CC_PalMemSetZero(rndState_ptr->PreviousRandValue, sizeof(rndState_ptr->PreviousRandValue));

	{
		size_t dataOutSize = CC_AES_BLOCK_SIZE_IN_BYTES;
		error = CC_AesFinish(&AesUserContext,
				       CC_AES_BLOCK_SIZE_IN_BYTES,
				       (uint8_t*)&rndState_ptr->PreviousRandValue[0],
				       CC_AES_BLOCK_SIZE_IN_BYTES,
				       (uint8_t*)&rndState_ptr->PreviousRandValue[0],
				       &dataOutSize);
	}
	if (error != CC_OK) {
		goto End;
	}

	/* output remain bytes */
        CC_PalMemCopy( out_ptr + outSizeBytes  - remainBytes,
			 (uint8_t*)&rndState_ptr->PreviousRandValue[0], remainBytes );


	/*  Perform CPRNGT - continuous test on each block  */
	/*---------------------------------------------------*/
	if (!(rndState_ptr->StateFlag & CC_RND_KAT_Mode)) {
		error = LLF_RND_RndCprngt((uint8_t*)&temp[0], /*prev*/
				       out_ptr,              /*buff_ptr*/
				       (uint8_t*)&rndState_ptr->PreviousRandValue[0], /*last_ptr*/
				       countBlocks);   /*in*/
		if (error != CC_OK) {
			CC_FIPS_SET_RND_CONT_ERR();
			goto End;
		}
	}

	/* calculate current value of the counter: V = V+countBlocks */
	RndAddValToIv(&rndState_ptr->Seed[keySizeWords], countBlocks);

	/*------------------------------------------*/
	/* [1] 6:    Update Key,V in the State      */
	/*------------------------------------------*/


	error = RndUpdate(rndState_ptr, /*in/out*/
			       (uint8_t*)&rndState_ptr->AdditionalInput[0],  /*in - saved additional input */
			       (uint8_t*)&rndState_ptr->Seed[0], /*in/out - Key||V*/
			       1);  /*skipSetUp*/
	if (error != CC_OK) {
		goto End;
	}

	/* [1] 6:    Increment Reseed counter       */
	/*------------------------------------------*/
	rndState_ptr->ReseedCounter++;


End:
	if (error != CC_OK) {
		CC_PalMemSetZero (out_ptr, outSizeBytes);
	}
	/* Clean additional input  */
	if (rndState_ptr->AddInputSizeWords != 0) {
		rndState_ptr->AddInputSizeWords = 0;
		CC_PalMemSetZero(rndState_ptr->AdditionalInput, sizeof(rndState_ptr->AdditionalInput));
	}

		if (CC_PalMutexUnlock(pCCGenVecMutex) != CC_OK) {
		CC_PalAbort("Fail to release mutex\n");
	}

	return error;

} /* End of CC_RndGenerateVector */



/** -----------------------------------------------------------------------------
  @brief The function performs instantiation of RNG and creates new
         internal State (including Seed) of RNG.

         It implements the CTR_DRBG_Instantiate function of 9.1 [1].
   	  This function must be called at least once per system reset (boot) and
         required before any random generation can be produced.

  @param [in/out] rndContext_ptr    - Pointer to the RND context buffer.
  @param [in/out] entrEstimBuff_ptr - The temp buffer for specific operations
                                on entropy estimator.
                          Note: for projects, which not use entropy estimator (e.g.
                                SW projects), the pointer may be set to NULL.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
CEXPORT_C CCError_t CC_RndInstantiation(
                                            CCRndContext_t   *rndContext_ptr,
                                            CCRndWorkBuff_t  *workBuff_ptr/*in/out*/ )
{


        /* error identifier definition */
        CCError_t error = CC_OK;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* check parameters */
        if (rndContext_ptr == NULL)
                return CC_RND_CONTEXT_PTR_INVALID_ERROR;
        if (workBuff_ptr == NULL)
                return CC_RND_WORK_BUFFER_PTR_INVALID_ERROR;


	error = CC_PalMutexLock(pCCRndCryptoMutex, CC_INFINITE);
        if (error != CC_SUCCESS) {
                CC_PalAbort("Fail to acquire mutex\n");
        }
        /* call on Instantiation mode */
        error = RndInstantiateOrReseed(
                                          rndContext_ptr,
                                          CC_TRUE/*isInstantiate*/,
                                          CC_FALSE/*isContinued*/,
                                          workBuff_ptr);

        if (CC_PalMutexUnlock(pCCRndCryptoMutex) != CC_SUCCESS) {
                CC_PalAbort("Fail to release mutex\n");
        }
        return error;

}


#ifndef _INTERNAL_CC_ONE_SEED
/** -----------------------------------------------------------------------------
 * @brief The CC_RndUnInstantiation cleans the unused RNG State for security goals.
 *
 * @return CCError_t - On success CC_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CCError_t CC_RndUnInstantiation(CCRndContext_t *rndContext_ptr)
{

        CCError_t error = CC_OK;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* check parameters */
        if (rndContext_ptr == NULL) {
                return CC_RND_CONTEXT_PTR_INVALID_ERROR;
	}

        CC_PalMemSetZero(rndContext_ptr, sizeof(CCRndContext_t));

        return error;
}


/** ------------------------------------------------------------/
  @brief The function performs reseeding of RNG Seed, and performs:
  	     1. Mixing of additional entropy into the working state.
 		 2. Mixing additional input provided by the user called additional input buffer.

         The function implements the CTR_DRBG_Reseeding function of 9.2 [1].
   	  This function must be called if reseed counter > reseed interval,
         in our implementation it is 2^32-1.

  @param [in/out] rndContext_ptr    - Pointer to the RND context buffer.
  @param [in/out] entrEstimBuff_ptr - The temp buffer for specific operations
                                on entropy estimator.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
CEXPORT_C CCError_t CC_RndReseeding(
                                        CCRndContext_t     *rndContext_ptr,
                                        CCRndWorkBuff_t  *workBuff_ptr/*in/out*/)
{

        /* FUNCTION DECLARATIONS */

        /* error identifier definition */
        CCError_t error;

        /* FUNCTION LOGIC */

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();
        /* check parameters */
        if (workBuff_ptr == NULL) {
                return CC_RND_WORK_BUFFER_PTR_INVALID_ERROR;
	}
        if (rndContext_ptr == NULL) {
                return CC_RND_CONTEXT_PTR_INVALID_ERROR;
	}

        error = CC_PalMutexLock(pCCRndCryptoMutex, CC_INFINITE);
        if (error != CC_SUCCESS) {
                CC_PalAbort("Fail to acquire mutex\n");
        }
        /* call on Reseeding mode */
        error = RndInstantiateOrReseed(
                                          rndContext_ptr, /*in/out*/
                                          CC_FALSE/*isInstantiate*/,
                                          CC_FALSE/*isContinued*/,
                                          workBuff_ptr );   /*in/out*/

        if (CC_PalMutexUnlock(pCCRndCryptoMutex) != CC_SUCCESS) {
                CC_PalAbort("Fail to release mutex\n");
        }
        return error;


}/* END OF CC_RndReseeding */

#endif /*_INTERNAL_CC_ONE_SEED*/


#ifndef _INTERNAL_CC_ONE_SEED
/******************************************************************************************/
/**
  @brief This function loads the AdditionaInput and its Size, given by the
        user, into the rndContext_ptr buffer;

  @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
  @param [in] AdditonalInput_ptr - The pointer to Additional input buffer.
  @param [in] AdditonalInputSize - The size of Additional input in bytes - must
        be up to 12 words and multiple of 4 bytes.

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in cc_rnd_error.h
*/
CEXPORT_C CCError_t CC_RndAddAdditionalInput(
                                                 CCRndContext_t *rndContext_ptr,
                                                 uint8_t *additonalInput_ptr,
                                                 size_t  additonalInputSizeBytes)
{


        /* The return error identifiers */
        CCError_t error = CC_OK;

        CCRndState_t   *rndState_ptr;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        if (rndContext_ptr == NULL) {
                return CC_RND_CONTEXT_PTR_INVALID_ERROR;
	}
        if ((additonalInput_ptr == NULL) &&
            (additonalInputSizeBytes != 0))
                return CC_RND_ADDITIONAL_INPUT_BUFFER_NULL;

        /* check Additional Input size - must be up to 12 words and multiple  *
        *  of 4 bytes   						      */
        if (additonalInputSizeBytes > sizeof(uint32_t)*CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS ||
                additonalInputSizeBytes % sizeof(uint32_t)) {
                return CC_RND_ADDITIONAL_INPUT_SIZE_ERROR;

        }
		error = CC_PalMutexLock(pCCGenVecMutex, CC_INFINITE);
        if (error != CC_OK) {
                CC_PalAbort("Fail to acquire mutex\n");
        }

        rndState_ptr = &(rndContext_ptr->rndState);

        CC_PalMemSetZero( rndState_ptr->AdditionalInput,
                           sizeof(rndState_ptr->AdditionalInput));

        if (additonalInput_ptr != NULL) {
                /* Copy the data from user to the global buffer: AdditionalInput */
                CC_PalMemCopy( rndState_ptr->AdditionalInput,
                                additonalInput_ptr,
                                additonalInputSizeBytes );
        }

        /* Set the AdditionalInput flag to indicate that data written to the buffer
        and the size of the data */
        rndState_ptr->AddInputSizeWords = additonalInputSizeBytes / sizeof(uint32_t);

		if (CC_PalMutexUnlock(pCCGenVecMutex) != CC_OK) {
                CC_PalAbort("Fail to release mutex\n");
        }

        return error;
}

/**********************************************************************************************************/
/**
  @brief The CC_RndEnterKatMode function sets KAT mode bit into StateFlag
         of global rndContext_ptr structure.

    The user must call this function before calling functions performing KAT tests.

  @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
  @param entrData_ptr  - entropy data,
  @param entrSize      - entropy size in bytes,
  @param nonce_ptr     - nonce,
  @param nonceSize     - nonce size in bytes,
  @param workBuff_ptr  - RND working buffer, must be the same buffer,
       		  which should be passed into Instantiation/Reseeding functions.

     Note: Total size of entropy and nonce must be not great than:
     	    CC_RND_MAX_KAT_ENTROPY_AND_NONCE_SIZE, defined

  @return CCError_t - On success CC_OK is returned, on failure a
                         value MODULE_* as defined in ...
 */
CEXPORT_C CCError_t CC_RndEnterKatMode(
                                           CCRndContext_t   *rndContext_ptr,
                                           uint8_t              *entrData_ptr,
                                           size_t               entrSize,
                                           uint8_t              *nonce_ptr,
                                           size_t               nonceSize,
                                           CCRndWorkBuff_t  *workBuff_ptr/*out*/)
{

        /* FUNCTION DECLARATIONS */

        /* error identifier definition */
        CCError_t error = CC_OK;
        uint8_t  *buf_ptr;

        CCRndState_t   *rndState_ptr;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* check Entropy Input size - must be up to 12 words*/
        if ((entrData_ptr == NULL) && (entrSize == 0)) {
                return CC_OK;
        } else if ((entrData_ptr == NULL) || (entrSize == 0)) {
                return CC_RND_ILLEGAL_PARAMETER_ERROR;
        }

        if ((nonce_ptr == NULL) && (nonceSize != 0)) {
                return CC_RND_ILLEGAL_DATA_PTR_ERROR;
        }

        if (workBuff_ptr == NULL) {
                return CC_RND_WORK_BUFFER_PTR_INVALID_ERROR;
        }
        if (rndContext_ptr == NULL) {
                return CC_RND_CONTEXT_PTR_INVALID_ERROR;
	}

        /* check entropy size */
        if (entrSize > sizeof(uint32_t)*CC_RND_ENTROPY_TEMP_BUFFER_MAX_SIZE_WORDS) {
                return CC_RND_ILLEGAL_DATA_SIZE_ERROR;
        }

	error = CC_PalMutexLock(pCCGenVecMutex, CC_INFINITE);
        if (error != CC_OK) {
                CC_PalAbort("Fail to acquire mutex\n");
        }

        rndState_ptr = &(rndContext_ptr->rndState);
        /* Set KAT mode */
        rndState_ptr->StateFlag |= CC_RND_KAT_DRBG_Mode;

        /* Copy concatenated entropy and nonce data with defined offset  */
        /*---------------------------------------------------------------*/
        /* set pointer to begin of RND entropy source */
        buf_ptr = (uint8_t*)workBuff_ptr +
                  sizeof(uint32_t)*(CC_RND_SRC_BUFF_OFFSET_WORDS + CC_RND_TRNG_SRC_INNER_OFFSET_WORDS);

        CC_PalMemCopy(buf_ptr, entrData_ptr, entrSize);

        if ((nonce_ptr != NULL) && (nonceSize != 0)) {

                /* check nonce size */
                if ((entrSize + nonceSize) > sizeof(uint32_t)*CC_RND_ENTROPY_TEMP_BUFFER_MAX_SIZE_WORDS) {
                        error = CC_RND_ILLEGAL_DATA_SIZE_ERROR;
                        goto End;
                }

                CC_PalMemCopy(buf_ptr + entrSize, nonce_ptr, nonceSize);

                /* Calculate total source size */
                entrSize += nonceSize;
        }

        /* Set total size into workBuff on begin of RND source buffer, i.e.   *
        *  two words backward   					      */
        *((uint32_t*)workBuff_ptr + CC_RND_SRC_BUFF_OFFSET_WORDS) = entrSize;

End:
		if (CC_PalMutexUnlock(pCCGenVecMutex) != CC_OK) {
				CC_PalAbort("Fail to release mutex\n");
		}

		return error;

}/* END OF CC_RndEnterKatMode  */

/**********************************************************************************************************/
/**
 * @brief The CC_RndDisableKatMode function disables KAT mode bit into StateFlag
 *        of global rndContext_ptr structure.
 *
 * @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
 *
 *   The user must call this function after KAT tests before actual using RND module
 *   (Instantiation etc.).
 *
 * @return - no return value.
 */
CEXPORT_C void CC_RndDisableKatMode(CCRndContext_t   *rndContext_ptr)
{
        /* FUNCTION LOGIC */

        CCRndState_t   *rndState_ptr = &(rndContext_ptr->rndState);

	CHECK_AND_RETURN_UPON_FIPS_ERROR();

        /* Disable KAT mode bit */
        rndState_ptr->StateFlag &= ~CC_RND_KAT_Mode;

        return;

}/* END OF CC_RndDisableKatMode  */



/**********************************************************************************************************/
/**
  @brief The function generates a random vector Rand in range  1 < RandVect < MaxVect
              by testing candidates (described and used in FIPS 186-4: B.1.2, B.4.2 etc.):
         The function performs the following:
         1.  Check input parameters, in partial, check that value of max. vector > 3 (our requirement).
         2.  If maxVect != 0 (maxVect is provided), then calculate required size of random
             equaled to actual bit size of MaxVector, else set it = rndSizeInBits.
         3.  Calls the CC_RndGenerateVector() function for generating random vector
             RndVect of required size.
         4.  If maxVect is provided, then:
              4.0. Subtract maxVect  -= 2;
              4.1. Sets all high bits of RndVect, greatest than MSBit of MaxVector, to 0.
              4.2. If size of random vector > 16 bytes, then:
                      4.2.1. Compares high 16 bytes of randVect to maxVect.
                      4.2.2. If condition is not satisfied, then generate new high 16 bytes
                             of rndVect and go to step 4.2.1.
              4.3. Compare the full RndVect with MaxVector. If condition is not satisfied,
                   then generate new random RndVect and go to step 4.1, else go to 6.
         5. Else if maxVect is not provided, then set MSBit of rndVect to 1.
         6. Output the result and Exit.

          Note: Random and Max vectors are given as sequence of bytes, where LSB is most left byte
                and MSB = most right one.

  @param rndContext_ptr [in/out] - Pointer to the RND context buffer.
  @param rndSizeInBits [in]   - If maxVect_ptr is not given, then rndSizeInBits defining the exact size (in bits)
                         of generated random vector. If maxVect is given, then it defines the
 	                  size (rounded up to bytes) of the maxVect_ptr buffer.
  @param maxVect_ptr [in]     - The pointer to vector defining a high limit
                         of random vector.
  @param rndVect_ptr [in,out] - The output buffer for the random vector.

  @return CCError_t  - On success CC_OK is returned, on failure - a value,
       		  defined in cc_rnd_error.h.
 */
CEXPORT_C CCError_t CC_RndGenerateVectorInRange(
                                                    CCRndContext_t *rndContext_ptr,
                                                    size_t   rndSizeInBits,
                                                    uint8_t  *maxVect_ptr,
                                                    uint8_t  *rndVect_ptr )
{
        /* FUNCTION DECLARATIONS */

        CCError_t Error = CC_OK;
        int32_t   k, extraBytes;
        int8_t    shift;
        uint8_t   mask;
        uint32_t   rndSizeInBytes, checkingSizeBytes = 0;
        uint32_t   maxVectSizeBits;
        uint32_t   maxVectSizeBytes = 0;
        CCCommonCmpCounter_t CompRes;
        /* RND state and function pointers */
        CCRndState_t   *rndState_ptr;
        CCRndGenerateVectWorkFunc_t RndGenerateVectFunc;

        /* FUNCTION LOGIC */
	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /*  Check input parameters */
        if (rndVect_ptr == NULL)
                return CC_RND_VECTOR_OUT_PTR_ERROR;

	/* verify that rndSizeInBits is not greater than 2^19 -1 */
	if (rndSizeInBits > 0x7FFFF)
		return CC_RND_VECTOR_OUT_SIZE_ERROR;

        /* given size of random vector in bytes */
        rndSizeInBytes = CALC_FULL_BYTES(rndSizeInBits);

        if (rndSizeInBits <= 1 || (uint32_t)rndSizeInBytes > CC_RND_MAX_GEN_VECTOR_SIZE_BYTES)
                return CC_RND_VECTOR_OUT_SIZE_ERROR;

        /* check parameters */
        if (rndContext_ptr == NULL)
                return CC_RND_CONTEXT_PTR_INVALID_ERROR;

        rndState_ptr = &(rndContext_ptr->rndState);
        RndGenerateVectFunc = rndContext_ptr->rndGenerateVectFunc;

        if (RndGenerateVectFunc == NULL)
                return CC_RND_GEN_VECTOR_FUNC_ERROR;


        /*--------------------------------------*/
        /* generation in case of exact bit size */
        /*--------------------------------------*/

        if (maxVect_ptr == NULL) {

                Error = RndGenerateVectFunc(rndState_ptr, rndSizeInBytes, rndVect_ptr);

                if (Error != CC_OK)
                        goto End;

                /* correction of bit size */
                rndVect_ptr[rndSizeInBytes-1] |= 0x80;
                if (rndSizeInBits%8 != 0) {
                        rndVect_ptr[rndSizeInBytes-1] >>= (8 - (rndSizeInBits&0x7))&0x7;
                }

                goto End;
        }

        /*------------------------------------------*/
        /* generation in case of given max. vector  */
        /*------------------------------------------*/

        /* calculate actual size of MaxVector in bits*/
        maxVectSizeBits = CC_CommonGetBytesCounterEffectiveSizeInBits(
                                                                        maxVect_ptr, (uint16_t)rndSizeInBytes);
        /* if maxVect < 4 then return an error */
        if (maxVectSizeBits < 3 || (maxVectSizeBits == 3 && maxVect_ptr[0] < 4)) {
                Error = CC_RND_MAX_VECTOR_IS_TOO_SMALL_ERROR;
		goto End;
	}

        /* temporary subtract 2 from maxVect */
        AddInt8ValueToUin8Vector(maxVect_ptr, -2/*val*/, maxVectSizeBytes);

        maxVectSizeBytes = CALC_FULL_BYTES(maxVectSizeBits);

        /* calculate count of extra 0-bytes in maxVector */
        extraBytes = rndSizeInBytes - maxVectSizeBytes;

        /* zeroing 0-bytes in rndVect_ptr buffer */
        CC_PalMemSetZero(rndVect_ptr + maxVectSizeBytes, extraBytes);

        /* calc. intermediate checking size */
        if ((uint32_t)maxVectSizeBytes > CC_AES_BLOCK_SIZE_IN_BYTES) {
                checkingSizeBytes = CC_AES_BLOCK_SIZE_IN_BYTES;
        } else {
                checkingSizeBytes = maxVectSizeBytes;
        }

        /* calculate count of extra 0-bits for mask shifting */
        shift = (int8_t)(8 - (maxVectSizeBits & 7))&7;
        mask = 0xFF >> shift;

        /* main loop for generating random number    */
        /*-------------------------------------------*/
        k = 0;

        while (k < 0xFFFF) {
                /* generate full size random vector */
                Error = RndGenerateVectFunc(rndState_ptr, (uint16_t)maxVectSizeBytes, rndVect_ptr);

                if (Error != CC_OK)
                        goto End;

                /* mask the non significant high bits */
                rndVect_ptr[maxVectSizeBytes - 1] &= mask;

                /* step1 check high part of random */
                if (checkingSizeBytes == CC_AES_BLOCK_SIZE_IN_BYTES) {
                        while (1) {
                                CompRes = CC_CommonCmpLsbUnsignedCounters(
                                                                            rndVect_ptr + maxVectSizeBytes - CC_AES_BLOCK_SIZE_IN_BYTES,
                                                                            CC_AES_BLOCK_SIZE_IN_BYTES,
                                                                            maxVect_ptr + maxVectSizeBytes - CC_AES_BLOCK_SIZE_IN_BYTES,
                                                                            CC_AES_BLOCK_SIZE_IN_BYTES);

                                if (CompRes == CC_COMMON_CmpCounter2GreaterThenCounter1) {
                                        goto End;  /* random is found */
                                } else if (CompRes == CC_COMMON_CmpCounter1AndCounter2AreIdentical)
                                        break; /* go to check full size */

                                /* generate new 16 random high bytes - without*
                                *  repeat the same Additional Data            */
                                Error = RndGenerateVectFunc(rndState_ptr, CC_AES_BLOCK_SIZE_IN_BYTES,
                                                                rndVect_ptr + maxVectSizeBytes - CC_AES_BLOCK_SIZE_IN_BYTES);
                                if (Error != CC_OK)
                                        goto End;

                                /* mask the non significant high bits */
                                rndVect_ptr[maxVectSizeBytes - 1] &= mask;
                        }
                }

                /* check full size relating to max vector */
                CompRes = CC_CommonCmpLsbUnsignedCounters(rndVect_ptr, (uint16_t)maxVectSizeBytes,
                                                             maxVect_ptr, (uint16_t)maxVectSizeBytes);

                if (CompRes == CC_COMMON_CmpCounter2GreaterThenCounter1) {
                        goto End;
                }

                /* increment counter and continue the loop */
                k++;
        }

        /* if all tries are Fail, then return the Error */
        Error = CC_RND_CAN_NOT_GENERATE_RAND_IN_RANGE;

End:

	if (Error != CC_OK) {
		CC_PalMemSetZero(rndVect_ptr, rndSizeInBytes);
                return Error;
	}


        if (maxVect_ptr != NULL) {
                /* add 1 to rndVect, so that 1 < rndVect < maxVect */
                AddInt8ValueToUin8Vector(rndVect_ptr, 1/*val*/, maxVectSizeBytes);
                /* reset the maxVect to original value */
                AddInt8ValueToUin8Vector(maxVect_ptr, 2/*val*/, maxVectSizeBytes);
        }

        return Error;

} /* End of CC_RndGenerateVectorInRange function */

#endif /*_INTERNAL_CC_ONE_SEED*/


/**********************************************************************************************************/
/**
 * @brief The RndGenerateWordsArrayInRange function generates a random words vector in range:
 *            1 < RndVect < MaxVect,   using the FIPS-PUB 186-2 standard appendix 3 :
 *
 *        The function generates random array  using CC_RndGenerateVectorInRange function and
 *        conversion of bytes to words.
 *
 *         Note: RndVect and MaxVect arrayss are given as sequence of words, where LSWord is most left byte
 *               and MSWord - most right.
 *
 * @param rndContext_ptr [in/out]  - Pointer to the RND context buffer.
 * @param rndSizeInBits [in]   - If maxVect_ptr is not given, then rndSizeInBits defining the exact size (in bits)
 *                        of generated random vector. If maxVect is given, then it defines the
 *	                  size (rounded up to words) of the maxVect_ptr buffer. The size must be not greate
 *      		  than CC_RND_MAX_SIZE_OF_OUTPUT_BYTES/4
 * @param maxVect_ptr [in]     - The pointer to vector defining a high limit of random vector.
 * @param rndVect_ptr [out]    - The output buffer for the random vector.
 * @param tmp_ptr [int]        - The temp buffer for the random generation. The size must be not
 *      		  less, than rndSizeInBits converted to words (rounded up).
 *
 * @return CCError_t  - On success CC_OK is returned, on failure - a value,
 *      		  defined in cc_rnd_error.h.
 */
CCError_t RndGenerateWordsArrayInRange(  // TODO- use maxVect_ptr and temp_ptr as the same vector to save space
                                            CCRndContext_t *rndContext_ptr,
                                            uint32_t   rndSizeInBits,
                                            uint32_t  *maxVect_ptr,
                                            uint32_t  *rndVect_ptr,
                                            uint32_t  *tmp_ptr)
{
        /* FUNCTION DECLARATIONS */

        CCError_t err;
        uint32_t rndSizeInWords = CALC_FULL_32BIT_WORDS(rndSizeInBits);


        /* check parameters */
        if (rndVect_ptr == NULL)
                return CC_RND_DATA_OUT_POINTER_INVALID_ERROR;

        /* given size of random vector in bytes */
        if (rndSizeInBits == 0 || rndSizeInWords*4 > CC_RND_MAX_GEN_VECTOR_SIZE_BYTES)
                return CC_RND_VECTOR_SIZE_ERROR;

        /* copy the maxVector into temp buffer and set endiannes as LE bytes  *
        *  array							      */
        CC_PalMemMove((uint8_t*)tmp_ptr, (uint8_t*)maxVect_ptr, rndSizeInWords*sizeof(uint32_t));

#ifdef BIG__ENDIAN
        CC_COMMON_INVERSE_UINT32_IN_ARRAY(tmp_ptr, rndSizeInWords);
#endif
        /* generate vector in range [1...MaxVect] as LE bytes array */
        rndVect_ptr[rndSizeInWords-1] = 0;
        err = CC_RndGenerateVectorInRange(rndContext_ptr, rndSizeInBits, (uint8_t*)tmp_ptr, (uint8_t*)rndVect_ptr);

        if (err)
                return err;

        /* set endianness in output words according to LE words array */
#ifdef BIG__ENDIAN
        CC_COMMON_INVERSE_UINT32_IN_ARRAY(rndVect_ptr, rndSizeInWords);
#endif

        return err;
}



