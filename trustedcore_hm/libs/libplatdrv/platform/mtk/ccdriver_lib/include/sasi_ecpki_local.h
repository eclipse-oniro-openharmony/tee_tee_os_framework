/****************************************************************************
* This confidential and proprietary software may be used only as authorized *
* by a licensing agreement from ARM Israel.                                 *
* Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
* The entire notice above must be reproduced on all authorized copies and   *
* copies may only be made to the extent permitted by a licensing agreement  *
* from ARM Israel.                                                          *
*****************************************************************************/

 
#ifndef SaSi_ECPKI_LOCAL_H
#define SaSi_ECPKI_LOCAL_H
  /** @file
   *  @brief this file contains the prototype of the service functions for
   *         the SaSi ECPKI module that are intendet for internaly usage.  */


#include "sasi_error.h" 
#include "sasi_ecpki_types.h"
#include "sasi_rnd.h"

#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

/*-------------------------------------------------*/
/*  User passed structures validation tags         */
/*-------------------------------------------------*/

/* the ECPKI user public key user validity TAG */
#define SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG  0xEC000001
/* the ECPKI user private key user validity TAG */
#define SaSi_ECPKI_PRIV_KEY_VALIDATION_TAG 0xEC000002

/* the ECDSA signing user context validity TAG */
#define SaSi_ECDSA_SIGN_CONTEXT_VALIDATION_TAG   0xEC000003
/* the ECDSA verifying user context validity TAG */
#define SaSi_ECDSA_VERIFY_CONTEXT_VALIDATION_TAG 0xEC000004

typedef struct {
	uint16_t hashResultSize;
	SaSi_HASH_OperationMode_t hashMode;
}ecpki_hash_t;




/************************ macros ********************************/
               
/************************ Typedefs  *****************************/

/************************ Structs  ******************************/

/************************ Public Variables **********************/

/************************ Public Functions **********************/
/**************************************************************************
 *	              SaSi_ECDSA_Sign_Init function
 **************************************************************************/
/*!
@brief    
The SaSi_ECDSA_Sign_Init functions user shall call first to perform the EC DSA Signing operation.

   The function performs the following steps:
   -# Validates all the inputs of the function. If one of the received 
      parameters is not valid, the function returns an error. 
   -# Decrypts the received context to the working context after capturing 
      the working context by calling the SaSi_CCM_GetContext() function.
   -# Initializes the working context and other variables and structures. 
   -# Calls the SaSi_HASH_Init_MTK() function.
   -# Calls the SaSi_CCM_EncryptAndReleaseContext() function to encrypt 
      the information in the working context, store it in the user's 
      received context, and then release the working context.
   -# Exits the handler with the OK code.

   This function does not do ECDSA cryptographic processing. Rather, it
   prepares a context that is used by the Update() and Finish() functions.
   
@note
Using of HASH functions with HASH size great, than EC modulus size, is not recommended!

@return SaSi_OK on success.
@return a non-zero value on failure as defined sasi_ecpki_error.h.	 
*/
CIMPORT_C SaSiError_t SaSi_ECDSA_SignInit_MTK(
			 SaSi_ECDSA_SignUserContext_t  *pSignUserContext,    /*!< [in/out] A pointer to the user buffer for signing data. */
			 SaSi_ECPKI_UserPrivKey_t      *pSignerPrivKey,      /*!< [in]  A pointer to the private key that is used to sign the data. */
			 SaSi_ECPKI_HASH_OpMode_t       hashMode             /*!< [in]  Defines the hash mode used for DSA. */
			 );

/**************************************************************************
 *	              SaSi_ECDSA_Sign_Update function
 **************************************************************************/
/*!
@brief Performs a hash  operation on data allocated by the user 
before finally signing it.
  
In case user divides signing data by block, he must call the Update function 
continuously a number of times until processing of the entire data block is complete.
 
@note
Using of HASH functions with HASH size great, than EC modulus size, is not recommended!

@return SaSi_OK on success.
@return a non-zero value on failure as defined sasi_ecpki_error.h.
 */
CIMPORT_C SaSiError_t SaSi_ECDSA_SignUpdate_MTK(
			   SaSi_ECDSA_SignUserContext_t    *pSignUserContext,  /*!< [in/out] The pointer to the user buffer for signing the database. */
			   uint8_t                         *pMessageDataIn,    /*!< [in]  The pointer to the message data block for calculating the HASH. */
			   uint32_t                         dataInSize         /*!< [in]  The size of the message data block, in bytes. 
											  The data size, passed on each call of the function, besides the last call, 
											  must be a multiple of the HASH block size according to used HASH mode. */
			   );

/**************************************************************************
 *	              _DX_ECDSA_Sign_Finish function
 **************************************************************************/
/*!
@brief Performs initialization of variables and structures, calls the hash function  
for the last block of data (if necessary) and then calculates digital signature.
Algorithm according ANS X9.62 standard.
	   
@note
Using of HASH functions with HASH size great, than EC modulus size, is not recommended!

@return SaSi_OK on success.
@return a non-zero value on failure as defined sasi_ecpki_error.h.
**/
CIMPORT_C  SaSiError_t _DX_ECDSA_SignFinish_MTK(
			   SaSi_ECDSA_SignUserContext_t   *pSignUserContext,       /*!< [in]  A pointer to the user buffer for signing database. */
			   SaSi_RND_Context_t             *pRndContext,            /*!< [in/out] A pointer to the random generation function context. */
			   uint8_t                        *pSignOut,               /*!< [out] A pointer to a buffer for output of signature. */
			   uint32_t                       *pSignOutSize,           /*!< [in/out] A pointer to the size of a user passed buffer for
												 signature (in), be not less than 2*orderSizeInBytes. */
			   uint32_t                        isEphemerKeyInternal,   /*!< [in] A parameter defining whether the ephemeral key is 
											     internal or external (1 or 0). */
			   uint32_t                       *pEphemerKeyData         /*!< [in] A pointer to external ephemeral key data. 
										   If it is given (case isEphemerKeyInternal=0), then the buffer 
										   must containing the ephemeral private key of size equal to 
										   EC generator order size, where LS-word is left most and MS-word 
										   is right most one. */
			   );

/**************************************************************************
 *	              SaSi_ECDSA_Sign_Finish function
 **************************************************************************/
/*!
@brief The macro definition for calling the ::_DX_ECDSA_SignFinish_MTK function with internal generation of ephemeral keys.
	   
@note
Using of HASH functions with HASH size great, than EC modulus size, is not recommended!

The macro calls the function with the following arguments as constant: 
isEphemerKeyInternal = 1 and pEphemerKeyData = NULL.
*/
#define SaSi_ECDSA_SignFinish(pSignUserContext, pRndContext, pSignatureOut, pSignatureOutSize) \
_DX_ECDSA_SignFinish_MTK((pSignUserContext), (pRndContext), (pSignatureOut), (pSignatureOutSize), 1, NULL)

/**************************************************************************
 *	              SaSi_ECDSA_VerifyInit_MTK  function
 **************************************************************************/
/*!
@brief Prepares a context that is used by the Update and Finish functions
but does not perform elliptic curve cryptographic processing

The function:
- Receives and decrypts user data (working context). 
- Checks input parameters of  ECDSA Verifying primitive.
- Calls hash init function.
- Initializes variables and structures for calling next functions.
- Encrypts and releases working context.
			
@note
Using of HASH functions with HASH size great, than EC modulus size, is not recommended!

@return SaSi_OK on success.
@return a non-zero value on failure as defined sasi_ecpki_error.h.
*/
CIMPORT_C SaSiError_t SaSi_ECDSA_VerifyInit_MTK(
					   SaSi_ECDSA_VerifyUserContext_t  *pVerifyUserContext,    /*!< [in/out] A pointer to the user buffer for verifying database. */
					   SaSi_ECPKI_UserPublKey_t        *pSignerPublKey,        /*!< [in]  A pointer to a Signer public key structure. */    
					   SaSi_ECPKI_HASH_OpMode_t         hashMode               /*!< [in]  The enumerator variable defines the hash function to be used. */
					   );


/**************************************************************************
 *	              SaSi_ECDSA_VerifyUpdate_MTK function
 **************************************************************************/
/*!
@brief Performs a hash  operation on data allocated by the user 
before finally verifying its signature.
  
In case user divides signing data by block, he must call the Update function 
continuously a number of times until processing of the entire data block is complete.
	   
@note
Using of HASH functions with HASH size greater, than EC modulus size, is not recommended.

@return SaSi_OK on success.
@return a non-zero value on failure as defined sasi_ecpki_error.h.
*/
CIMPORT_C SaSiError_t SaSi_ECDSA_VerifyUpdate_MTK(
					     SaSi_ECDSA_VerifyUserContext_t *pVerifyUserContext, /*!< [in/out] The pointer to the user buffer for verifying database. */
					     uint8_t                        *pMessageDataIn,     /*!< [in]  The message data for calculating Hash. */ 
					     uint32_t                        dataInSize          /*!< [in]  The size of the message data block, in bytes. 
													     The data size, passed on each call of the function, besides the last call, 
													     must be a multiple of the HASH block size according to used HASH mode. */
					     );


/**************************************************************************
 *	              SaSi_ECDSA_VerifyFinish_MTK function
 **************************************************************************/

/*! 
@brief Performs initialization of variables and structures, 
calls the hash function for the last block of data (if necessary),  
than calls HostEcdsaVerify function for verifying signature according to 
ANS X9.62 standard. 

@note
Using of HASH functions with HASH size greater, than EC modulus size, is not recommended!	   

@return SaSi_OK on success.
@return a non-zero value on failure as defined sasi_ecpki_error.h.
**/
CIMPORT_C SaSiError_t SaSi_ECDSA_VerifyFinish_MTK(
					     SaSi_ECDSA_VerifyUserContext_t  *pVerifyUserContext,    /*!< [in]  A pointer to the user buffer for verifying the database. */
					     uint8_t                         *pSignatureIn,          /*!< [in]  A pointer to a buffer for the signature to be compared. */
					     uint32_t                         SignatureSizeBytes /*!< [in]  The size of a user passed signature (must be 2*orderSizeInBytes). */
					     );





#ifdef __cplusplus
}
#endif

#endif /* #ifndef SaSi_ECPKI_LOCAL_H */

