/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef PKA_ECC_EXPORT_H
#define PKA_ECC_EXPORT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * All the includes that are needed for code using this module to
 * compile correctly should be #included here.
 */
#include "ssi_pal_types.h"
#include "sasi_rnd.h"
#include "sasi_ecpki_types.h"

/* ****************   Definitions    ********************* */

/* Temporary buffers used for the functions called from ECDSA */
typedef struct {
    // ! Debug : set to 10, may be less?
    uint32_t tempBuff[SaSi_PKA_ECDSA_SIGN_BUFF_MAX_LENGTH_IN_WORDS];
} ecdsa_sign_db_t;

/* Temporary buffers used for the  functions called from ECDSA */
typedef struct {
    uint32_t tempBuff[SaSi_PKA_ECDSA_VERIFY_BUFF_MAX_LENGTH_IN_WORDS];
} ecdsa_verify_db_t;

/* ***************************************************************************************
 *            PkaEcdsaVerify function    /ECVP_DSA in IEEE-1363              *
 * ************************************************************************************* */
/*
 * This function performs verification of ECDSA signature using PKA.
 *
 * 1. Compute  h = d^-1,  h1 = f*h mod r,  h2 = c*h mod r.
 * 2. Compute  P(Xp,Yp) =  h1*G  + h2*W; c1 = Px mod r
 * 3. Compare  If  c1 != c,  then output "Invalid", else - "valid".
 *
 * @author reuvenl (8/7/2014)
 *
 *
 * @return SaSiError_t - SaSi_OK or error
 *         LLF_ECDSA_VERIFY_CALC_SIGNATURE_IS_INVALID
 */
SaSiError_t PkaEcdsaVerify(void);

/* *********************************************************************** */
/*
 * This function performs verification of ECDSA signature by
 * calling SEP to perform it using PKA.
 * SEP implementation will call PkaEcdsaVerify().
 *
 *
 * @return SaSiError_t - SaSi_OK or error
 *         LLF_ECDSA_VERIFY_CALC_SIGNATURE_IS_INVALID
 */
SaSiError_t HostSepEcdsaVerify(void);

/* *********************************************************************** */
/*
 * The function checks input parameters, sets data into SRAM and calls
 * EcdsaVerifyCall() function
 *
 * @author reuvenl (8/7/2014)
 *
 * @param signPublKey   - A pointer to the Signer Public Key
 * @param messageRepresent - A pointer to the message representative
 * @param messRepresSizeWords  - Size of message representative in words
 * @param signC  - A pointer to the signature c value.
 * @param signD  - A pointer to the signature d value.
 *
 * @return SaSiError_t - SaSi_OK,
 *             LLF_ECDSA_VERIFY_CALC_SIGNATURE_IS_INVALID
 */
SaSiError_t HostEcdsaVerify(struct SaSi_ECPKI_PublKey_t *signPublKey, /* in */
                            uint32_t *messageRepresent,        /* in */
                            uint32_t messRepresSizeWords,      /* in */
                            uint32_t *signC,                   /* in */
                            uint32_t *signD /* in */);

/* Macro for calling ECDSA Verify functions according to HOST/SEP mode */
#define ECDSA_VERIFY_CALL() PkaEcdsaVerify()

/* ************************************************************************************** */
/*
 * The function checks input parameters, sets data into SRAM and calls
 * HOST or SEP specific Signature function (aacording to make file of
 * HOST or SEP).
 *
 * @author reuvenl (8/24/2014)
 *
 * @param pSignPublKey - The pointer to signer public key structure.
 * @param pMessRepres - The pointer to the message representative.
 * @param messRepresSizeWords- The size of the message representative
 * @param isEphemerKeyInternal -
 * @param pEphemerKeyData
 * @param pSignC - The pointer to C-part of the signature.
 * @param pSignD - The pointer to D-part of the signature.
 *
 * @return SaSiError_t
 */
SaSiError_t HostEcdsaSign(SaSi_ECPKI_PrivKey_t *pSignPrivKey, /* in */
                          uint32_t *pMessRepres,              /* in */
                          uint32_t *pEphemerKeyData,          /* in */
                          uint32_t *pSignC,                   /* out */
                          uint32_t *pSignD,                   /* out */
                          uint32_t *pTempBuff /* in */);

/* Macro for calling ECDSA Sign functions according to HOST/SEP mode */
#define ECDSA_SIGN_CALL() PkaEcdsaSign()

/* ************************************************************************************** */
/*
 * EC scalar multiplication p = k*p, with SCA-protection features.
 *
 *  The function performs:
 *  - PKA init,
 *  - setting input data into PKA registers,
 *  - calls pkaSmul function and then output result data from PKA.
 *
 * @author reuvenl (03/19/2015)
 *
 * @param [in] domain - pointer to EC domain.
 * @param [out] bxr,byr - pointers to coordinates of result EC point.
 *          The size of each of buffers must be not less, than
 *          EC modulus size (in words).
 * @param [in] k - pointer to the scalar.
 * @param [in] bxp,byp  - pointers to coordinates of input EC point.
 *
 */
SaSiError_t host_smul(const SaSi_ECPKI_Domain_t *domain, uint32_t *bxr, uint32_t *byr, const uint32_t *k,
                      uint32_t kSizeBit, uint32_t *bxp, uint32_t *byp);

/* ************************************************************************************** */
/*
 * EC scalar multiplication p = k*p, without SCA-protection features.
 *
 *  The function is more fast, than SCA protected function and performs:
 *  - PKA init,
 *  - setting input data into PKA registers,
 *  - calls pka_smul_aff function and then output of result data from PKA.
 *
 * @author reuvenl (03/19/2015)
 *
 * @param [in] domain - pointer to EC domain.
 * @param [in] bxp,byp  - pointers to coordinates of input EC point.
 * @param [in] k - pointer to the scalar.
 * @param [in] kSizeBit - size of scalar in bits.
 * @param [out] bxr,byr - pointers to coordinates of result EC point.
 *          The size of each of buffers must be not less, than
 *          EC modulus size (in words).
 * @param [in] tmpBuff - pointer to temp buffer of size
 *               not less than (2*ecOrderSizeInBits+1) in bytes.
 *
 */
SaSiError_t host_smul_aff(const SaSi_ECPKI_Domain_t *domain, uint32_t *bxp, uint32_t *byp, const uint32_t *k,
                          uint32_t kSizeBit, uint32_t *bxr, uint32_t *byr, uint32_t *tmpBuff);

/* ************************************************************************************** */
/*
 * The function truncates the message to given count of LS bits.
 *
 * @author reuvenl (8/19/2014)
 *
 * @param pMessOut - A pointer to truncated message output. Output format:
 *                   bytes, LS byte is left most one.
 * @param pMessIn  - A pointer to input message. Input format: bytes
 * @param outSizeBits - Exact size of truncated message in bits.
 *
 * @return no return value.
 */
void HostEcdsaTruncateMess(uint32_t *pMessOut, uint8_t *pMessIn, uint32_t outSizeBits);

/* ************************************************************************************** */
/*
 * The function performs decompression of public key, i.e. extracts the Y-coordinate
 *      from compressed key according ANS X9.62-2005.
 *
 * @author reuvenl (22/09/2014)
 *
 * @param [in/out] - pPublKey - A pointer to the public key structure.
 * @param [in] pointCtl - The EC point control byte = (compression mode | Y-MSbit).
 * @return  - On success SaSi_OK is returned, on failure an error code.
 *
 */
SaSiError_t PKA_PointUncompress(struct SaSi_ECPKI_PublKey_t *pPublKey, uint8_t pointCtl);

/* ****************************************************************************************
 *               LLF_ECPKI_InitPubKey function
 * ************************************************************************************** */
/*
 *      The function performs uncompression (extracts Y-coordinate), checks
 *      and inits the public key (ANS X9.62-2005).
 *
 * @author reuvenl (22/09/2014)
 *
 * @param [in/out] - pPublKey - The pointer to the public key structure.
 * @param [in] pointCtl - The EC point control byte = (compression mode | Y-MSbit).
 * @param [in] checkMode - An enum. value indicates a level of checkin the
 *             public key (check size only, partly or full check).
 * @return  - On success SaSi_OK is returned, on failure an error code.
 *
 */
SaSiError_t LLF_ECPKI_InitPubKey(struct SaSi_ECPKI_PublKey_t *pPublKey, uint8_t pointCtl);

/*
 @brief ECC scalar multiplication function, with/without SCA protection
        (according to project configuration file: outPoint = scalsr * inPoint.

    Mote: All buffers are given as 32-bit words arrays, where LSWord is a leftmost one.
          Sizes of buffers of in/out points coordinates are equal to EC modulus
          size.

 @param [in] pDomain  - The pointer to current EC domain.
 @param [in] scalar - The pointer to the scalsr buffer.
 @param [in] scalSizeInBits - The size of the scalsr in 32-bit words.
 @param [in] inPointX - The pointer to the input point X coordinate.
 @param [in] inPointY - The pointer to the point Y coordinate.
 @param [out] outPointX - The pointer to the point X coordinate.
 @param [out] outPointY - The pointer to the point Y coordinate.
 @param [in]  tmpBuff - the pointer to the temp buffer allowed be NULL
                        in SCA protected configuration:
                        DX_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT = 1).

 @return <b>SaSiError_t</b>: <br>
                       SaSi_OK<br>
                       SaSi_ECPKI_GEN_KEY_ILLEGAL_D0MAIN_ID_ERROR<br>
                       SaSi_ECPKI_GEN_KEY_INVALID_PRIVATE_KEY_PTR_ERROR<br>
                       SaSi_ECPKI_GEN_KEY_INVALID_PUBLIC_KEY_PTR_ERROR<br>
                       SaSi_ECPKI_GEN_KEY_INVALID_TEMP_DATA_PTR_ERROR<br>
                       SaSi_ECPKI_BUILD_SCA_RESIST_ILLEGAL_MODE_ERROR<br>
*/
SaSiError_t LLF_ECPKI_ScalarMult(const SaSi_ECPKI_Domain_t *pDomain, /* in */
                                 const uint32_t *scalar,             /* in */
                                 uint32_t scalSizeInWords,           /* in */
                                 uint32_t *inPointX,                 /* out */
                                 uint32_t *inPointY,                 /* out */
                                 uint32_t *outPointX,                /* out */
                                 uint32_t *outPointY,                /* out */
                                 uint32_t *tmpBuff);                 /* in */

/* ****************************************************************************************
 *               LLF_ECPKI_CheckPublKeyCall function
 * ************************************************************************************** */
/*
  @brief  The function checks that the public key is valid point belonging to EC group.

        Assuming: partly check (sizes, point is on curve) of the public key
                  was done previously.

   @param[out] pPubKey      - A pointer to the public key structure.
   @param[in]  pTempBuff    - A pointer to temp buffer of size not less 2*modulusSize.

   @return  SaSi_OK,
        Error from called function
*/
SaSiError_t LLF_ECPKI_FullCheckPublKey(struct SaSi_ECPKI_PublKey_t *pPublKey, /* in */
                                       uint32_t *pTempBuff);           /* in */

/*
 * The sets data into SRAM and calls specific Signature function
 * (aacording to make file of HOST or SEP).
 *
 * @author reuvenl (3/29/2015)
 *
 * Note: All data in buffers given with LE order of bytes and words.
 *
 * @param pRndContext - The pointer to the random generation function context.
 *                      The context must be allocated, initialized and
 *                      instantiated according to SaSi_RND module requirements.
 * @param pSignPrivKey - The pointer to signer privatekey structure.
 * @param pMessRepres - The pointer to the message representative buffer of size
 *                = EC modulus size in words (with leading zeros).
 * @param isEphemerKeyInternal - A parameter defining whether the ephemeral
 *                   key is internal or external (1 or 0).
 * @param pEphemKey - The pointer to private Ephemeral key buff; size
 *                 of the data must be = EC order size in words (with leading
 *                 zeros).
 * @param pSignC - The pointer to C-part of the signature (R-part in some
 *               standards); size of the data must be = EC order size in words
 *               (with leading zeros).
 * @param pSignD - The pointer to D-part of the signature (S-part in some
 *               standards); size of the data must be = EC order size in words
 *               (with leading zeros).
 * @param pTempBuff - The pointer to temp buffer of size, dependig on
 *                    SCA_protection mode defined in project config file: size
 *                    of the buffer must be not less than (2*ModulusSizeInWords
 *                    + SaSi_PKA_ECPKI_SCALAR_MUL_BUFF_MAX_LENGTH_IN_WORDS).
 *
 * @return SaSiError_t
 */
SaSiError_t LLF_ECDSA_SignCalcCall(SaSi_RND_Context_t *pRndContext,    /* in/out */
                                   SaSi_ECPKI_PrivKey_t *pSignPrivKey, /* in */
                                   uint32_t *pMessRepres,              /* in */
                                   uint32_t isEphemerKeyInternal,      /* in */
                                   uint32_t *pEphemKey,                /* in */
                                   uint32_t *pSignC,                   /* out */
                                   uint32_t *pSignD,                   /* out */
                                   uint32_t *pTempBuff /* in */);

/* ****************************************************************************************
 *               LLF_ECPKI_SVDP_DH function
 * ************************************************************************************** */
/*
  @brief  The function checks that the public key is valid point belonging to EC group.

        Assuming: partly check (sizes, point is on curve) of the public key
                  was done previously.

   @param[out] pPubKey      - A pointer to the public key structure.
   @param[out] pPrivKey     - A pointer to the private key structure.
   @param[in]  pSharedSecretValue - A pointer to buffer for Shared Secret Value of size
                             not less than modulusSize in words.
   @param[in]  pTempBuff    - A pointer to temp buffer of defined size.

   @return  SaSi_OK,
        Error from called function
*/
SaSiError_t LLF_ECPKI_SVDP_DH(struct SaSi_ECPKI_PublKey_t *pPublKey,   /* in */
                              SaSi_ECPKI_PrivKey_t *pPrivKey,   /* in */
                              uint8_t *pSharedSecretValue,      /* out */
                              SaSi_ECDH_TempData_t *pTempBuff); /* in */

CEXPORT_C SaSiError_t LLF_ECPKI_GenKeyPair(const SaSi_ECPKI_Domain_t *pDomain,     /* in */
                                           SaSi_ECPKI_UserPrivKey_t *pUserPrivKey, /* out */
                                           SaSi_ECPKI_UserPublKey_t *pUserPublKey, /* out */
                                           SaSi_ECPKI_KG_TempData_t *pTempBuff);   /* in */

#ifdef __cplusplus
}
#endif

#endif
