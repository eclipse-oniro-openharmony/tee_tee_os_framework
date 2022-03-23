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

#include "cc_pal_mem.h"
#include "cc_rnd.h"
#include "cc_ecpki_types.h"
#include "cc_ecpki_error.h"
#include "cc_ecpki_local.h"
#include "pki.h"
#include "ec_wrst.h"
#include "cc_general_defs.h"
#include "cc_fips_defs.h"


/***************  CC_EcpkiKeyPairGenerate function  **************/
/**
 @brief Generates a pair of private and public keys in little endian ordinary form according to [ANS X9.31].

    The function performs the following:
      1. Checks the validity of all of the function inputs. If one of the received
         parameters is not valid, it returns an error.
      2. Cleans buffers and generates random private key.
      3. Calls the low level function PkaEcWrstScalarMult to generate EC public key.
      4. Outputs the user public and private key structures in little endian form.
      5. Cleans temporary buffers.
      6. Exits.

 @param [in/out] pRndContext - The pointer to random context (state).
 @param [in] pDomain  - The pointer to current EC domain.
 @param [in/out] pRndContext - The pointer to random context (state).
 @param [out] pUserPrivKey - The pointer to the private key structure.
 @param [out] pUserPublKey - The pointer to the public key structure.
 @param [in] pTempBuf - Temporary buffers of size, defined by CCEcpkiKgTempData_t.
 @param [in] pFipsCtx - Pointer to temporary buffer used in case FIPS certification if required

 @return <b>CCError_t</b>: <br>
                       CC_OK<br>
                        CC_ECPKI_RND_CONTEXT_PTR_ERROR
                        CC_ECPKI_DOMAIN_PTR_ERROR<br>
                        CC_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR<br>
                        CC_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR<br>
                        CC_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR<br>
*/
CEXPORT_C CCError_t CC_EcpkiKeyPairGenerate(
                                           CCRndContext_t         *pRndContext,  /*in/out*/
                                           const CCEcpkiDomain_t  *pDomain,      /*in*/
                                           CCEcpkiUserPrivKey_t   *pUserPrivKey, /*out*/
                                           CCEcpkiUserPublKey_t   *pUserPublKey, /*out*/
                                           CCEcpkiKgTempData_t   *pTempBuff,    /*in*/
                                           CCEcpkiKgFipsContext_t *pFipsCtx)    /*in*/
{
        CCError_t err = CC_OK;
        CCEcpkiPrivKey_t *pPrivKey;
        uint32_t  orderSizeInWords;

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();


        /* ......... checking the validity of arguments .......... */
        /* ------------------------------------------------------- */

        if (pRndContext == NULL)
                return CC_ECPKI_RND_CONTEXT_PTR_ERROR;

        if (pDomain == NULL)
                return CC_ECPKI_DOMAIN_PTR_ERROR;

        if (pUserPrivKey == NULL)
                return CC_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR;

        if (pUserPublKey == NULL)
                return CC_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR;

        if (pTempBuff == NULL)
                return CC_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR;


        /* .........  clear all input structures  ............*/

        CC_PalMemSetZero( pUserPrivKey, sizeof(CCEcpkiUserPrivKey_t) );
        CC_PalMemSetZero( pUserPublKey, sizeof(CCEcpkiUserPublKey_t) );

        /* the pointer to the key database */
        pPrivKey = (CCEcpkiPrivKey_t *)&pUserPrivKey->PrivKeyDbBuff;

        orderSizeInWords = (pDomain->ordSizeInBits+CC_BITS_IN_32BIT_WORD-1)/CC_BITS_IN_32BIT_WORD;
        /*  set EC order as max. vect. */
        CC_PalMemCopy(pTempBuff, pDomain->ecR, sizeof(uint32_t)*orderSizeInWords);
        /* LR TBD! set right LE bytes order for pTempBuff, when BE PC is used */

        /* generate random private key vector in range: 1 < privKey < EcOrder *
         * Note: we exclude privKey = 1, allowed by FIPS 186-4, because the   *
        *  negligible low probability of its random generation                */
        pPrivKey->PrivKey[orderSizeInWords - 1] = 0;
        err = CC_RndGenerateVectorInRange(
                                            pRndContext, (uint32_t)pDomain->ordSizeInBits, (uint8_t*)pTempBuff/*MaxVect*/,
                                            (uint8_t*)pPrivKey->PrivKey/*RndVect*/);
        if (err) {
                goto End;
        }

        err = EcWrstGenKeyPair(pDomain, pUserPrivKey, pUserPublKey, pTempBuff);
        if (err) {
                goto End;
        }
        err = FIPS_ECC_VALIDATE(pRndContext, pUserPrivKey, pUserPublKey, pFipsCtx);
        End:
        if (err) {
                CC_PalMemSetZero(pUserPrivKey, sizeof(CCEcpkiUserPrivKey_t));
                CC_PalMemSetZero(pUserPublKey, sizeof(CCEcpkiUserPublKey_t));
        }
        if (pFipsCtx != NULL) {
                CC_PalMemSetZero(pFipsCtx, sizeof(CCEcpkiKgFipsContext_t));
        }

        CC_PalMemSetZero(pTempBuff, sizeof(CCEcpkiKgTempData_t));
        return err;
}/* END OF CC_EcpkiKeyPairGenerate */

/**********************************************************************/



