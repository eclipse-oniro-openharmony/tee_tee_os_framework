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

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_ASYM_RSA_DH

/************* Include Files ****************/

#include "cc_pal_mem.h"
#include "cc_rsa_error.h"
#include "cc_rsa_prim.h"
#include "cc_common_math.h"
#include "cc_rsa_local.h"
#include "cc_fips_defs.h"

/************************ Defines ******************************/

#if ( CC_HASH_USER_CTX_SIZE_IN_WORDS > CC_PKA_RSA_HASH_CTX_SIZE_IN_WORDS )
#error CC_PKA_RSA_HASH_CTX_SIZE_IN_WORDS OR CC_HASH_USER_CTX_SIZE_IN_WORDS do not defined correctly.
#endif

/************************ Enums ******************************/
/************************ Typedefs ***************************/
/************************ Global Data ************************/


/************* Private function prototype ********************/


#ifndef	_INTERNAL_CC_NO_RSA_VERIFY_SUPPORT

/************************ Private Functions ******************************/

/**
   \brief  RSA_VerifyInit initializes the Verify
   multi-call algorithm as defined in PKCS#1 v1.5 and 2.1

	NOTE: 1. In PSS_Sign v2.1 MD5 is not supported, since it is not recommended
		 by the PKCS#1 v2.1.
	      2. According to thesaid standard, implementation of the function
		 for version v1.5 is based on DER encoding of the algorithm info.


   @param[in] UserContext_ptr - A pointer to the public Context
			 structure of the User.
   @param[in] UserPubKey_ptr - A pointer to the public key data
			   structure.
   @param[in] rsaHashMode - The hash function to be used. Currently
			 avaliable HASH functions: SHA1/SHA-256/384/512/MD5
			 (MD5 - allowed only for PKCS#1 v1.5).
			 Also allowed "After" HASH modes for said functions.
   @param[in] MGF - The mask generation function, relevant only for PKCS#1 v2.1.
		    The currently allowed value for v2.1 is CC_PKCS1_MGF1.
   @param[in] SaltLen - The Length of the Salt buffer. Relevant for PKCS#1 Ver 2.1 only.
			Typical lengths are 0 and hashLen (20 for SHA1).
			The maximum length allowed is NSize - hLen - 2.
			If the salt length is not available in this process, the user
			can use the define: CC_RSA_VERIFY_SALT_LENGTH_UNKNOWN.
			Security Note: it is recommended not to use this flag and provide
	                the Salt length on each verify
   @param[in] PKCS1_ver - Ver 1.5 or 2.1, according to the functionality required.

   @return CCError_t - CC_OK, or error
*/

CEXPORT_C CCError_t CC_RsaVerifyInit(CCRsaPubUserContext_t *UserContext_ptr,
					 CCRsaUserPubKey_t *UserPubKey_ptr,
					 CCRsaHashOpMode_t rsaHashMode,
					 CCPkcs1Mgf_t MGF,
					 size_t  SaltLen,
					 CCPkcs1Version_t PKCS1_ver)
{
	/* FUNCTION DECLARATIONS */

	/* The return error identifier */
	CCError_t Error = CC_OK;

	/* defining a pointer to the active context allcated by the CCM */
	RSAPubContext_t *ccmWorkingContext_ptr;
	/*Pointer to the public key for lengths checking*/
	CCRsaPubKey_t *PubKey_ptr;
	/*The size of the modulus for lengths checking*/
	uint32_t ModulusSizeBytes;

	/* FUNCTION LOGIC */

	/* ............... local initializations .............................. */
	/* -------------------------------------------------------------------- */

	/* initialize the module size to cancel compilers warnings */
	ModulusSizeBytes = 0;


	/* ............... checking the parameters validity ................... */
	/* -------------------------------------------------------------------- */


	/* if the users context ID pointer is NULL return an error */
	if (UserContext_ptr == NULL)
		return CC_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

	/*if the private key object is NULL return an error*/
	if (UserPubKey_ptr == NULL)
		return CC_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

	/* check if the hash operation mode is legal */
	if (rsaHashMode >= CC_RSA_HASH_NumOfModes)
		return CC_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

	/* check if the MGF operation mode is legal */
	if (MGF >= CC_RSA_NumOfMGFFunctions)
		return CC_RSA_MGF_ILLEGAL_ARG_ERROR;

	/* check that the PKCS1 version argument is legal*/
	if (PKCS1_ver >= CC_RSA_NumOf_PKCS1_versions)
		return CC_RSA_PKCS1_VER_ARG_ERROR;

	/*According to the PKCS1 ver 2.1 standart it is not recommended to use MD5 hash
	     therefore we do not support it */
	if (PKCS1_ver == CC_PKCS1_VER21 && rsaHashMode == CC_RSA_HASH_MD5_mode)
		return CC_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

	/*If the validation tag is incorrect*/
	if (UserPubKey_ptr->valid_tag != CC_RSA_PUB_KEY_VALIDATION_TAG)
		return CC_RSA_PUB_KEY_VALIDATION_TAG_ERROR;

	/*Checking if a check on salt length is needed*/
	if (SaltLen != CC_RSA_VERIFY_SALT_LENGTH_UNKNOWN && PKCS1_ver == CC_PKCS1_VER21) {
		/*Initializing the Modulus Size in Bytes needed for SaltLength parameter check*/
		PubKey_ptr = (CCRsaPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;

		/*Note: the (-1) is due to the PKCS#1 Ver2.1 standard section 9.1.1*/
		ModulusSizeBytes =  (PubKey_ptr->nSizeInBits - 1) / 8;
		if ((PubKey_ptr->nSizeInBits - 1) % 8)
			ModulusSizeBytes++;
	}

	/* ............... initializing local variables ................ */
	/* ------------------------------------------------------------- */

	ccmWorkingContext_ptr = (RSAPubContext_t*)UserContext_ptr->context_buff;

	/*Reset the Context handler for improper previous values initialized*/
	CC_PalMemSetZero(UserContext_ptr, sizeof(CCRsaPubUserContext_t));


	/* Initializing the Hash operation mode in the RSA Context level */
	/* ------------------------------------------------------------- */

	ccmWorkingContext_ptr->RsaHashOperationMode = rsaHashMode;

	if (RsaSupportedHashModes_t[rsaHashMode] == CC_FALSE){
            Error = CC_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
            goto End;
	}

	ccmWorkingContext_ptr->HashOperationMode = RsaHashInfo_t[rsaHashMode].hashMode;
	ccmWorkingContext_ptr->HASH_Result_Size = RsaHashInfo_t[rsaHashMode].hashResultSize;

	if ( (ccmWorkingContext_ptr->HashOperationMode == CC_HASH_SHA384_mode) ||
	     (ccmWorkingContext_ptr->HashOperationMode == CC_HASH_SHA512_mode) )
		ccmWorkingContext_ptr->HashBlockSize = CC_HASH_SHA512_BLOCK_SIZE_IN_WORDS;
	else
		ccmWorkingContext_ptr->HashBlockSize = CC_HASH_BLOCK_SIZE_IN_WORDS;

	if ( (rsaHashMode == CC_RSA_HASH_MD5_mode ) ||
	     (rsaHashMode == CC_RSA_HASH_SHA1_mode ) ||
	     (rsaHashMode == CC_RSA_HASH_SHA224_mode ) ||
	     (rsaHashMode == CC_RSA_HASH_SHA256_mode ) ||
	     (rsaHashMode == CC_RSA_HASH_SHA384_mode ) ||
	     (rsaHashMode == CC_RSA_HASH_SHA512_mode ) )
		ccmWorkingContext_ptr->doHash = true; /* for actual Hash modes */
	else
		ccmWorkingContext_ptr->doHash = false;


	/* Init HASH */
	if (ccmWorkingContext_ptr->doHash) {
		Error = CC_HashInit(
			((CCHashUserContext_t *)((ccmWorkingContext_ptr->RsaHashCtxBuff))),
			ccmWorkingContext_ptr->HashOperationMode);
		if (Error != CC_OK)
			goto End;
	}


	/* Switch to appropriate PKCS1_version */
	/*-------------------------------------*/
	switch (PKCS1_ver) {
	case CC_PKCS1_VER15:
		ccmWorkingContext_ptr->PKCS1_Version = CC_PKCS1_VER15;
		break;
	case CC_PKCS1_VER21:
		ccmWorkingContext_ptr->PKCS1_Version = CC_PKCS1_VER21;
		/*Checking restriction of Salt Length ; Hash output size and the mosulus*/
		if (SaltLen != CC_RSA_VERIFY_SALT_LENGTH_UNKNOWN &&
		    ModulusSizeBytes < (uint32_t)(ccmWorkingContext_ptr->HASH_Result_Size*4 + SaltLen + 2)) {
			Error = CC_RSA_PSS_ENCODING_MODULUS_HASH_SALT_LENGTHS_ERROR;
			goto End;
		}
		break;
	default:
		Error = CC_RSA_PKCS1_VER_ARG_ERROR;
		goto End;
	}

	switch (MGF) {
	case CC_PKCS1_MGF1:
	case CC_PKCS1_NO_MGF:
		ccmWorkingContext_ptr->MGF_2use = MGF;
		break;
	default:
		Error = CC_RSA_MGF_ILLEGAL_ARG_ERROR;
		goto End;
	}

	/*Copy the RSA Pub key to the context*/
	CC_PalMemCopy((uint8_t *)&ccmWorkingContext_ptr->PubUserKey,(uint8_t *)UserPubKey_ptr,sizeof(CCRsaUserPubKey_t));

	/*Initial the Salt random length relevant for PKCS#1 Ver2.1*/
	ccmWorkingContext_ptr->SaltLen = SaltLen;

	/* Initialize the size of the modulus */
	ccmWorkingContext_ptr->nSizeInBytes = CALC_FULL_BYTES(((CCRsaPubKey_t*)UserPubKey_ptr->PublicKeyDbBuff)->nSizeInBits);

	/* set the RSA tag to the users context */
	UserContext_ptr->valid_tag = CC_RSA_VERIFY_CONTEXT_VALIDATION_TAG;

End:

	/* .............. clearing the users context in case of error.......... */
	/* -------------------------------------------------------------------- */
	if (Error != CC_OK) {
		CC_PalMemSetZero(UserContext_ptr, sizeof(CCRsaPubUserContext_t));
	}

	return Error;


}/* END OF CC_RsaVerifyInit */


/**********************************************************************************************************/
/**
   \brief RSA_VerifyUpdate processes the data to be verified
   in a given context, according to PKCS1 v1.5 and 2.1

   \note RSA_VerifyUpdate can be called multiple times with data

   @param[in] UserContext_ptr - A pointer to the public Context
	                           structure of the User.
   @param[in] DataIn_ptr - A pointer to the data whose signature is
                         to be verified.
   @param[in] DataInSize - The size, in bytes, of the data whose
                         signature is to be verified.

   @return CCError_t - CC_OK, or error
*/

CEXPORT_C CCError_t CC_RsaVerifyUpdate(CCRsaPubUserContext_t *UserContext_ptr,
					   uint8_t     *DataIn_ptr,
					   size_t      DataInSize)
{
	/* FUNCTION DECLERATIONS */

	/* The return error identifier */
	CCError_t Error = CC_OK;
	/* defining a pointer to the active context allcated by the CCM */
	RSAPubContext_t *ccmWorkingContext_ptr;

	/* FUNCTION LOGIC */


	/* ............... checking the parameters validity ................... */
	/* -------------------------------------------------------------------- */

	/* if the users context pointer is NULL return an error */
	if (UserContext_ptr == NULL)
		return CC_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

	/* if the users Data In pointer is illegal return an error */
	if (DataIn_ptr == NULL && DataInSize) {
		Error = CC_RSA_DATA_POINTER_INVALID_ERROR;
		goto End;
	}

	/* if the data size is larger then 2^29 (to prevant an overflow on the transition to bits )
	   return error */
	if (DataInSize >= (1UL << 29)) {
		Error = CC_RSA_INVALID_MESSAGE_DATA_SIZE;
		goto End;
	}

	/* if the users context TAG is illegal return an error - the context is invalid */
	if (UserContext_ptr->valid_tag != CC_RSA_VERIFY_CONTEXT_VALIDATION_TAG) {
		Error = CC_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR;
		goto End;
	}

	/*  extract the RSA context structure */
	ccmWorkingContext_ptr = (RSAPubContext_t*)UserContext_ptr->context_buff;

	if (ccmWorkingContext_ptr->doHash) {
		/*Operate the Hash update function for relevant versions*/
		Error = CC_HashUpdate(((CCHashUserContext_t*)(ccmWorkingContext_ptr->RsaHashCtxBuff)),
				       DataIn_ptr,
				       DataInSize );
		if (Error != CC_OK)
			goto End;
	} else {
		/* DataInSize must fit exactly to the size of Hash output that we support */
		if (DataInSize != ccmWorkingContext_ptr->HASH_Result_Size*sizeof(uint32_t)) {
			Error = CC_RSA_INVALID_MESSAGE_DATA_SIZE_IN_SSL_CASE;
			goto End;
		}
		/* Copy the DataIn_ptr to the HashResult in case it is an SSL mode*/
		CC_PalMemCopy((uint8_t *)ccmWorkingContext_ptr->HASH_Result, DataIn_ptr, DataInSize);
	}

End:

	/* ..... clearing the users context in case of error  .... */
	if (Error != CC_OK) {
		CC_PalMemSetZero(UserContext_ptr, sizeof(CCRsaPubUserContext_t));
	}

	return Error;

}/* END OF CC_RsaVerifyUpdate */


/**********************************************************************************************************/
/**

   \brief RSA_VerifyFinish implements the Finish Phase of the Verify algorithm
   as defined in PKCS#1 v2.1 or PKCS#1 v1.5

   @param[in] UserContext_ptr - A pointer to the public Context
	                           structure of the User.
   @param[in] Sig_ptr - A pointer to the signature to be verified.
                        The length of the signature is PubKey_ptr->N.len bytes
                        (that is, the size of the modulus, in bytes).

   @return CCError_t - CC_OK, or error
*/

CEXPORT_C CCError_t CC_RsaVerifyFinish(CCRsaPubUserContext_t *UserContext_ptr,
					   uint8_t *Sig_ptr)
{
	/* FUNCTION DECLERATIONS */

	/* The return error identifier */
	CCError_t Error = CC_OK;

	/* defining a pointer to the active context allcated by the CCM */
	RSAPubContext_t *ccmWorkingContext_ptr ;

	/*Parameter for the new size of the modulus N in bytes according to PKCS1 Ver 2.1*/
	uint16_t modSizeBytes; /*rounded number of Bytes for padding2 length*/

	/*Temporary for the N size*/
	CCRsaPubKey_t *PubKey_ptr;


	/* FUNCTION LOGIC */

	/* ............... checking the parameters validity ................... */
	/* -------------------------------------------------------------------- */

	/* if the users context pointer is NULL return an error */
	if (UserContext_ptr == NULL)
		return CC_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

	/* if the users context pointer is NULL return an error */
	if (Sig_ptr == NULL) {
		Error = CC_RSA_INVALID_SIGNATURE_BUFFER_POINTER;
		goto End;
	}

	/* if the users context TAG is illegal return an error - the context is invalid */
	if (UserContext_ptr->valid_tag != CC_RSA_VERIFY_CONTEXT_VALIDATION_TAG) {
		Error = CC_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR;
		goto End;
	}

	/* ................. aquiring the RSA context ............................. */
	ccmWorkingContext_ptr = (RSAPubContext_t*)UserContext_ptr->context_buff;
	PubKey_ptr = (CCRsaPubKey_t *)ccmWorkingContext_ptr->PubUserKey.PublicKeyDbBuff;
	modSizeBytes = (uint16_t)(CALC_FULL_BYTES(PubKey_ptr->nSizeInBits));

	/* execute the RSA encription of formatted sign block */
	Error = CC_RsaPrimEncrypt(&ccmWorkingContext_ptr->PubUserKey,
				      &ccmWorkingContext_ptr->PrimeData,
				      Sig_ptr,
				      modSizeBytes,
				      (uint8_t*)ccmWorkingContext_ptr->EBD);
	if (Error != CC_OK)
		goto End;

	/* Initialize the Effective size in bits of the result */
	ccmWorkingContext_ptr->EBDSizeInBits = CC_CommonGetBytesCounterEffectiveSizeInBits((uint8_t*)&ccmWorkingContext_ptr->EBD,
                                                                                              modSizeBytes);

	/*Operating the HASH Finish function only in case that Hash operation is needed*/
	if (ccmWorkingContext_ptr->doHash) {
		/*Operating the HASH Finish function*/
		Error=CC_HashFinish(((CCHashUserContext_t *)(ccmWorkingContext_ptr->RsaHashCtxBuff)),
				       ccmWorkingContext_ptr->HASH_Result);
	}
	if (Error != CC_OK)
		goto End;

	/*-------------------------------------*/
	/* switch to appropriate PKCS1 Version */
	/*-------------------------------------*/
	switch (ccmWorkingContext_ptr->PKCS1_Version) {

#ifndef _INTERNAL_CC_NO_RSA_SCHEME_21_SUPPORT
	case CC_PKCS1_VER21:
		/*Operating the Verify primitive*/
		Error = RsaPssVerify21(ccmWorkingContext_ptr);
		if (Error!=CC_OK)
			goto End;
		break;
#endif

#ifndef _INTERNAL_CC_NO_RSA_SCHEME_15_SUPPORT
	case CC_PKCS1_VER15:

		/* Create expected decrypted signature buff.  */
		Error = RsaEmsaPkcs1v15Encode(
				modSizeBytes,
				ccmWorkingContext_ptr->HashOperationMode,
				(uint8_t*)ccmWorkingContext_ptr->HASH_Result,
				ccmWorkingContext_ptr->HASH_Result_Size*sizeof(uint32_t),
				(uint8_t*)&ccmWorkingContext_ptr->PrimeData/*expected buff*/);
		if (Error!=CC_OK)
			goto End;



		/* compare actual and expected values of signature buffer */
		if (CC_PalMemCmp(&ccmWorkingContext_ptr->PrimeData,
				  (uint8_t*)ccmWorkingContext_ptr->EBD, modSizeBytes)) {
			Error = CC_RSA_ERROR_VER15_INCONSISTENT_VERIFY;
			goto End;
		}
		break;
#endif
	default:
		Error = CC_RSA_PKCS1_VER_ARG_ERROR;
		goto End;

	}/*End of switch()*/


End:
	/* ..... clearing the users context in case of error ..... */
	CC_PalMemSetZero(UserContext_ptr, sizeof(CCRsaPubUserContext_t));

	return Error;


}/* END OF CC_RsaVerifyFinish */


/**********************************************************************************************************/
/**
   \brief RSA_Verify implements the RSASSA-PKCS1v15 algorithm
    in a single function as defined in PKCS#1 v2.1 (including v1.5).

	The user can call the function by appropriate macro according to choosen
	(and allowed) HASH algorithm SHA1, SHA224... (see macros below).

	NOTE: 1. In PSS_Verify v2.1 MD5 is not supported, since it is not recommended
		 by the PKCS#1 ver2.1.
	      2. According to the said standard, implementation of the function
		 for version v1.5 is based on DER encoding of hash algorithm ID.


   @param[in] UserContext_ptr - A pointer to the public Context,
   				for the use of the function as a space to work on
   @param[in] UserPubKey_ptr - A pointer to the public key data
                           structure of the user.
   @param[in] rsaHashMode - The hash function to be used. Currently
		      avaliable HASH functions: SHA1/SHA-224/256/384/512, MD5
		      (MD5 - allowed only for PKCS#1 v1.5).
		      Also allowed "After" HASH modes for said functions.
   @param[in] MGF - The mask generation function. only for PKCS#1 v2.1
                    defines MGF1, so the only value allowed for v2.1
                    is CC_PKCS1_MGF1.
   @param[in] SaltLen - The Length of the Salt buffer. relevant for PKCS#1 Ver 2.1 Only
			Typical lengths are 0 and hLen (20 for SHA1)
			The maximum length allowed is NSize - hLen - 2
   @param[in] DataIn_ptr - A pointer to the data whose signature is
                         to be verified.
   @param[in] DataInSize - The size, in bytes, of the data whose
                         signature is to be verified.
   @param[in] Sig_ptr - A pointer to the signature to be verified.
                        The length of the signature is PubKey_ptr->N.len bytes
                        (that is, the size of the modulus, in bytes).
   @param[in] PKCS1_ver - Ver 1.5 or 2.1, according to the functionality required

   @return CCError_t - CC_OK, or error
*/

CEXPORT_C CCError_t CC_RsaVerify(CCRsaPubUserContext_t *UserContext_ptr,
				     CCRsaUserPubKey_t *UserPubKey_ptr,
				     CCRsaHashOpMode_t rsaHashMode,
				     CCPkcs1Mgf_t MGF,
				     size_t    SaltLen,
				     uint8_t  *DataIn_ptr,
				     size_t    DataInSize,
				     uint8_t  *Sig_ptr,
				     CCPkcs1Version_t PKCS1_ver)
{
	/* FUNCTION DECLERATIONS */

	/* The return error identifier */
	CCError_t Error = CC_OK;

	/* FUNCTION LOGIC */

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	/**********************************************************************
	 *  RSA_VerifyInit
	 **********************************************************************/
	Error = CC_RsaVerifyInit(UserContext_ptr,
				   UserPubKey_ptr,
				   rsaHashMode,
				   MGF,
				   SaltLen,
				   PKCS1_ver);
	if (Error!=CC_OK)
		return Error;

	/**********************************************************************
	 *  RSA_VerifyUpdate
	 **********************************************************************/
	Error = CC_RsaVerifyUpdate(UserContext_ptr,
				     DataIn_ptr,
				     DataInSize);
	if (Error!=CC_OK)
		return Error;

	/**********************************************************************
	 *  RSA_VerifyFinish
	 **********************************************************************/
	Error = CC_RsaVerifyFinish(UserContext_ptr,
				     Sig_ptr);

	return Error;

}/* END OF CC_RsaVerify */

#endif /*_INTERNAL_CC_NO_RSA_VERIFY_SUPPORT*/
