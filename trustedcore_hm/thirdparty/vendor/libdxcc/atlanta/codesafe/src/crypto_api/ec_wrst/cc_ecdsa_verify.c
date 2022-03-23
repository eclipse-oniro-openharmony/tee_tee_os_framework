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

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_ASYM_ECC

/************* Include Files ****************/

#include "cc_pal_mem.h"
#include "cc_ecpki_error.h"
#include "cc_ecpki_local.h"
#include "cc_common.h"
#include "cc_rsa_types.h"
#include "cc_fips_defs.h"
#include "ec_wrst.h"

/************************ Defines *****************************************/
#if ( CC_HASH_USER_CTX_SIZE_IN_WORDS > CC_PKA_RSA_HASH_CTX_SIZE_IN_WORDS )
        #error CC_PKA_RSA_HASH_CTX_SIZE_IN_WORDS or CC_HASH_USER_CTX_SIZE_IN_WORDS  defined not correctly.
#endif

/************************ Enums *******************************************/
/************************ Typedefs ****************************************/
/************************ Global Data *************************************/
extern const CCEcpkiHash_t ecpki_hash_info[CC_ECPKI_HASH_NumOfModes];
extern const uint8_t ecpki_supported_hash_modes[CC_ECPKI_HASH_NumOfModes];
/************* Private function prototype *********************************/

/************************ Public Functions ********************************/

/**************************************************************************
 *	              EcdsaVerifyInit  function
 **************************************************************************/
/**
   @brief  Prepares a context that is used by the Update and Finish functions
           but does not perform elliptic curve cryptographic processing

                    The function:
                        - Receives and decrypts user data (working context).
                        - Checks input parameters of  ECDSA Vrifying primitive.
                        - Calls hash init function.
                        - Initializes variables and structures for calling next functions.
                        - Encrypts and releases working context.

                        NOTE: Using of HASH functions with HASH size great, than EC modulus size,
                        is not recommended!

   @param[in,out] pVerifyUserContext - A pointer to the user buffer for verifying database.
   @param[in] pSignerPublKey - A pointer to a Signer public key structure.
   @param[in] hashMode - The enumerator variable defines the hash function to be used.

   @return <b>CCError_t</b>: <br>
                         CC_OK<br>
                         CC_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
                         CC_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR <br>
                         CC_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR <br>
                         CC_ECDSA_VERIFY_INVALID_DOMAIN_ID_ERROR <br>
                         CC_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
**/
CEXPORT_C CCError_t EcdsaVerifyInit(
                                           CCEcdsaVerifyUserContext_t  *pVerifyUserContext, /*in/out*/
                                           CCEcpkiUserPublKey_t        *pSignerPublKey,     /*in*/
                                           CCEcpkiHashOpMode_t         hashMode               /*in*/ )
{
        /* FUNCTION DECLERATIONS */

        /* The return error identifier */
        CCError_t err = CC_OK;
        /* defining a pointer to the active context allcated by the CCM */
        EcdsaVerifyContext_t *pWorkingContext;

        /* FUNCTION LOGIC */

        /* ............... checking the parameters validity ................... */
        /* -------------------------------------------------------------------- */

        /* if the users context ID pointer is NULL return an error */
        if (pVerifyUserContext == NULL)
                return CC_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR;

        /*if the private key object is NULL return an error*/
        if (pSignerPublKey == NULL)
                return CC_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR;

        /* check if the hash operation mode is legal */
        if (hashMode >= CC_ECPKI_HASH_NumOfModes)
                return CC_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;

        if (pSignerPublKey->valid_tag != CC_ECPKI_PUBL_KEY_VALIDATION_TAG)
                return CC_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR;

        pWorkingContext = (EcdsaVerifyContext_t*)&pVerifyUserContext->context_buff;

        /* reset the Context handler for improper previous values initialized */
        CC_PalMemSet(pWorkingContext, 0, sizeof(EcdsaVerifyContext_t));

        /* ................. loading the context .................................. */
        /* ------------------------------------------------------------------------ */

        /*Initializing the Hash operation mode in the ECDSA Context */
        if (hashMode > CC_ECPKI_HASH_NumOfModes) {
                err = CC_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;
                goto End;
        }

        if (ecpki_supported_hash_modes[hashMode] == CC_FALSE) {
                err = CC_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;
                goto End;
        }

        pWorkingContext->hashMode = hashMode;
        pWorkingContext->hashResultSizeWords = ecpki_hash_info[pWorkingContext->hashMode].hashResultSize;

        if (ecpki_hash_info[pWorkingContext->hashMode].hashMode < CC_HASH_NumOfModes) {
                err = CC_HashInit(&(pWorkingContext->hashUserCtxBuff),
                                     ecpki_hash_info[pWorkingContext->hashMode].hashMode);
                if (err != CC_OK)
                        goto End;
        }

        /* copy the ECPKI Public key to the context*/
        CC_PalMemCopy(&pWorkingContext->ECDSA_SignerPublKey, pSignerPublKey, sizeof(CCEcpkiUserPublKey_t));

        /* set the ECDSA validation tag */
        pVerifyUserContext->valid_tag = CC_ECDSA_VERIFY_CONTEXT_VALIDATION_TAG;

        End:
        /*  clear the users context in case of error */
        if (err != CC_OK) {
                CC_PalMemSetZero(pVerifyUserContext, sizeof(CCEcdsaVerifyUserContext_t));
        }

        return err;

}/* EcdsaVerifyInit */


/**************************************************************************
 *	              EcdsaVerifyUpdate function
 **************************************************************************/
/**
   @brief  Performs a hash  operation on data allocated by the user
           before finally verifying its signature.

           In case user divides signing data by block, he must call the Update function
           continuously a number of times until processing of the entire data block is complete.

       NOTE: Using of HASH functions with HASH size greater, than EC modulus size,
             is not recommended.

   @param [in,out] pVerifyUserContext - The pointer to the user buffer for verifying database.
   @param [in] pMessageDataIn - The message data for calculating Hash.
   @param [in]dataInSize - The size of the message data block, in bytes. The data size,
                   passed on each call of the function, besides the last call, must be
                   a multiple of the HASH block size according to used HASH mode.

   @return <b>CCError_t</b>: <br>
                         CC_OK<br>
                         CC_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
                         CC_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
                         CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR <br>
                         CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR <br>
                         CC_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
 **/
CEXPORT_C CCError_t EcdsaVerifyUpdate(
                                             CCEcdsaVerifyUserContext_t *pVerifyUserContext, /*in/out*/
                                             uint8_t                        *pMessageDataIn,     /* in */
                                             size_t                         dataInSize          /* in */ )
{
        /* FUNCTION DECLARATIONS */

        /* The return error identifier */
        CCError_t err = CC_OK;
        /* defining a pointer to the active context allcated by the CCM */
        EcdsaVerifyContext_t *pWorkingContext;

        /* FUNCTION LOGIC */

        /* ............... checking the parameters validity ................... */
        /* -------------------------------------------------------------------- */

        /* if the users context pointer is NULL return an error */
        if (pVerifyUserContext == NULL)
                return CC_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR;

        /* if the users context TAG is illegal return an error - the context is invalid */
        if (pVerifyUserContext->valid_tag != CC_ECDSA_VERIFY_CONTEXT_VALIDATION_TAG)
                return CC_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR;

        /* if the users MessageDataIn pointer is illegal return an error */
        if (pMessageDataIn == NULL && dataInSize)
                return CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR;

        /* check that the data size < 2^29 (to prevent an overflow on the
           transition to bits ) */
        if (dataInSize >= (1UL << 29))
                return CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;

        /* sign working context */
        pWorkingContext = (EcdsaVerifyContext_t*)&pVerifyUserContext->context_buff;

        /* HASH update operations */
        if (ecpki_hash_info[pWorkingContext->hashMode].hashMode < CC_HASH_NumOfModes) {
                /*Operate the Hash update function for relevant version */
                err = CC_HashUpdate( &(pWorkingContext->hashUserCtxBuff),
                                        pMessageDataIn, dataInSize );
                if (err != CC_OK) {
                        goto End;
                }
        } else {
                if (dataInSize != ecpki_hash_info[pWorkingContext->hashMode].hashResultSize*CC_32BIT_WORD_SIZE) {
                        /* DataInSize must fit exactly to the size of Hash output that we support */
                        err = CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;
                        goto End;
                }
                /* Copy the DataIn_ptr to the HASH_Result */
                CC_PalMemCopy((uint8_t *)pWorkingContext->hashResult,pMessageDataIn,dataInSize);
        }

        End:
        /*  clear the users context in case of error */
        if (err != CC_OK) {
                CC_PalMemSetZero(pVerifyUserContext, sizeof(CCEcdsaVerifyUserContext_t));
        }

        return err;

}/* EcdsaVerifyUpdate */



/**************************************************************************
 *	              EcdsaVerifyFinish function
 **************************************************************************/
/**
   @brief  Performs initialization of variables and structures,
           calls the hash function for the last block of data (if necessary),
           than calls EcWrstDsaVerify function for verifying signature
           according to EC DSA algorithm.

       NOTE: Using of HASH functions with HASH size greater, than EC modulus size,
             is not recommended!
             Algorithm according ANS X9.62 standard

   @param[in] pVerifyUserContext - A pointer to the user buffer for verifying the database.
   @param[in] pSignatureIn       - A pointer to a buffer for the signature to be compared
   @param[in] SignatureSizeBytes    - The size of a user passed signature (must be 2*orderSizeInBytes).

   @return <b>CCError_t</b>: <br>
              CC_OK <br>
                          CC_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
                          CC_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
                          CC_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR <br>
                          CC_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
                          CC_ECDSA_VERIFY_INVALID_SIGNATURE_SIZE_ERROR <br>
                          CC_ECDSA_VERIFY_INCONSISTENT_VERIFY_ERROR <br>
**/
CEXPORT_C CCError_t EcdsaVerifyFinish(
                                             CCEcdsaVerifyUserContext_t *pVerifyUserContext,  /*in*/
                                             uint8_t                        *pSignatureIn,        /*in*/
                                             size_t                         SignatureSizeBytes  /*in*/)
{
        /* FUNCTION DECLARATIONS */

        /* The return error identifier */
        CCError_t err = CC_OK;

        /* pointer to the active context  */
        EcdsaVerifyContext_t *pWorkingContext;
        /* pointer to public key structure in ccmWorkingContext  */
        CCEcpkiPublKey_t  *PublKey_ptr;
        /*  EC domain ID and pointer to the current domain */
        /*  pointer to the current domain */
        CCEcpkiDomain_t   *pDomain;

        uint32_t  *pMessRepres, *pSignatureC, *pSignatureD;
        uint32_t   hashSizeWords;
        uint32_t   orderSizeInBytes, orderSizeInWords;

        /* FUNCTION LOGIC */

        /* ............... checking the parameters validity ................... */
        /* -------------------------------------------------------------------- */

        /* if the users context pointer is NULL return an error */
        if (pVerifyUserContext == NULL)
                return CC_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR;

        /* if the users context TAG is illegal return an error - the context is invalid */
        if (pVerifyUserContext->valid_tag != CC_ECDSA_VERIFY_CONTEXT_VALIDATION_TAG)
                return CC_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR;

        /* if the users Signature pointer is illegal then return an error */
        if (pSignatureIn == NULL)
                return CC_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR;


        /* ............. checking the validity of context ........ */
        /* ------------------------------------------------------- */

        /* the pointer to the internal Verify context */
        pWorkingContext = (EcdsaVerifyContext_t*)&pVerifyUserContext->context_buff;

        /* check Hash mode */
        if (pWorkingContext->hashMode >= CC_ECPKI_HASH_NumOfModes)
                return CC_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;

        PublKey_ptr = (CCEcpkiPublKey_t *)&pWorkingContext->ECDSA_SignerPublKey.PublKeyDbBuff;

        /* Initializing domain parameters */
        pDomain = &PublKey_ptr->domain;
        orderSizeInBytes  =  CALC_FULL_BYTES(pDomain->ordSizeInBits);
        orderSizeInWords  =  CALC_FULL_32BIT_WORDS(pDomain->ordSizeInBits);

        /* if the user signature size is not equal to 2*ModSizeInBytes, then return an error */
        if (SignatureSizeBytes != 2*orderSizeInBytes)
                return CC_ECDSA_VERIFY_INVALID_SIGNATURE_SIZE_ERROR;

        /*Operating the HASH Finish function only in case that Hash operation is needed*/
        if (pWorkingContext->hashMode <= CC_ECPKI_HASH_SHA512_mode) {
                err = CC_HashFinish(&(pWorkingContext->hashUserCtxBuff),
                                       pWorkingContext->hashResult);
                if (err != CC_OK)
                        return err;
        }

        /*  Initialization of  EcWrstDsaVerify arguments */
        hashSizeWords        = pWorkingContext->hashResultSizeWords;
        /* Temp buffers */
        pSignatureC       = ((EcWrstDsaVerifyDb_t*)(pWorkingContext->ccEcdsaVerIntBuff))->tempBuff;
        pSignatureD       = pSignatureC + orderSizeInWords; /* Max lengths of C in whole words */
        pMessRepres = pSignatureD + orderSizeInWords;

        // Check shortened cleaning
        /* Clean memory  */
        CC_PalMemSetZero(pSignatureC, 2*4*orderSizeInWords); //-> pSignatureC[orderSizeInWords-1] = 0;
        //-> pSignatureD[orderSizeInWords-1] = 0;
        CC_PalMemSetZero(pMessRepres, 4*orderSizeInWords);   //-> pMessRepres[orderSizeInWords-1] = 0;

        /* Derive message representative = leftmost OrderSizeInBits bits of HASH_Result */
        if (pDomain->ordSizeInBits >= 32*hashSizeWords) {
                CC_CommonReverseMemcpy((uint8_t*)pMessRepres,
                                          (uint8_t*)(pWorkingContext->hashResult), 4*hashSizeWords);
        } else {
                EcWrstDsaTruncateMsg(pMessRepres,
                                      (uint8_t*)(pWorkingContext->hashResult), pDomain->ordSizeInBits);

        }

        /* Convert signature data to words array with little entian order of  *
        *  words							      */
        pSignatureC[orderSizeInWords-1] = 0;
        CC_CommonReverseMemcpy((uint8_t*)pSignatureC, pSignatureIn, orderSizeInBytes);
        pSignatureD[orderSizeInWords-1] = 0;
        CC_CommonReverseMemcpy((uint8_t*)pSignatureD, pSignatureIn + orderSizeInBytes, orderSizeInBytes);

        /*------------------------------*/
        /* Verifying operation  	*/
        /*------------------------------*/
        err =  EcWrstDsaVerify(PublKey_ptr, pMessRepres, orderSizeInWords, pSignatureC, pSignatureD);

        /* clear the users context  */
        CC_PalMemSetZero(pVerifyUserContext, sizeof(CCEcdsaVerifyUserContext_t));

        return err;

}/* End EcdsaVerifyFinish */


/**************************************************************************
 *	              CC_EcdsaVerify integrated function
 **************************************************************************/
/**
   @brief  Performs all ECDSA verifying operations simultaneously.

           This function simply calls the Init, Update and Finish functions continuously.

       NOTE: Using of HASH functions with HASH size great, than EC modulus size,
             is not recommended!
             Algorithm according ANS X9.62 standard


   @param[in]  pVerifyUserContext - A pointer to the user buffer for verifying database.
   @param[in]  pUserPublKey       - A pointer to a user public key structure.
   @param[in]  hashMode              - The enumerator variable defines the hash function to be used.
   @param[in]  pMessageDataIn     - Message data for calculating hash.
   @param[in]  messageSizeInBytes    - Size of block of message data in bytes.
   @param[in]  pSignatureIn       - A pointer to a buffer for output of signature.
   @param[in]  SignatureSizeBytes    - Size of signature, in bytes (must be 2*orderSizeInBytes).

   @return <b>CCError_t</b>: <br>
                        CC_OK <br>
                        CC_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
                        CC_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
                        CC_ECDSA_VERIFY_INVALID_DOMAIN_ID_ERROR <br>
                        CC_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR <br>
                        CC_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR <br>
                        CC_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
                        CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR <br>
                        CC_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR <br>
                        CC_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR <br>
                        CC_ECDSA_VERIFY_INVALID_SIGNATURE_SIZE_ERROR <br>
                        CC_ECDSA_VERIFY_INCONSISTENT_VERIFY_ERROR <br>
**/
CEXPORT_C CCError_t CC_EcdsaVerify (
                                        CCEcdsaVerifyUserContext_t *pVerifyUserContext,  /*in/out*/
                                        CCEcpkiUserPublKey_t       *pUserPublKey,        /*in*/
                                        CCEcpkiHashOpMode_t        hashMode,            /*in*/
                                        uint8_t                        *pSignatureIn,        /*in*/
                                        size_t                         SignatureSizeBytes,  /*in*/
                                        uint8_t                        *pMessageDataIn,      /*in*/
                                        size_t                         messageSizeInBytes  /*in*/)
{
        /* FUNCTION DECLERATIONS */

        CCError_t err = CC_OK;

        /* FUNCTION LOGIC */
        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();


        err = EcdsaVerifyInit(pVerifyUserContext, pUserPublKey, hashMode);

        if (err!=CC_OK)
                return err;

        err = EcdsaVerifyUpdate(pVerifyUserContext, pMessageDataIn, messageSizeInBytes);
        if (err!=CC_OK)
                return err;

        err = EcdsaVerifyFinish(pVerifyUserContext, pSignatureIn,
                                      SignatureSizeBytes);
        return err;

}/* END OF CC_EcdsaVerify */

