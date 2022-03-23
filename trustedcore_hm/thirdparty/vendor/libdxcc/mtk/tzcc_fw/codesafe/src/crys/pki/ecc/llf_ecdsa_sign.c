/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

/* .............. SaSi level includes ................. */
#include "ssi_pal_mem.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_abort.h"
#include "sasi_common_math.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_error.h"
#include "sasi_ecpki_local.h"
#include "pka_hw_defs.h"
#include "pka_export.h"
#include "pka.h"
#include "pka_ecc_export.h"
#include "pka_ecc_error.h"
#include "pka_ecc.h"

/* *********************** Defines **************************** */

/* canceling the lint warning:
  Info 740: Unusual pointer cast
  (incompatible indirect types) */


/* canceling the lint warning:
   Info 826: Suspicious pointer-to-pointer conversion
   (area too small) */


/* canceling the lint warning:
Info 716: while(1) */


/* Define common ECC PKA registers allocation */
#include "pka_ecc_glob_regs_def.h"

/* ************* Private functions prototypes  ************** */
void HostDivideVectorBy2(uint32_t *VecBuff_ptr, uint32_t SizeInWords);

/* *********************** Typedefs ************************* */
/* *********************** Global Data ********************** */

// extern const SaSi_ECPKI_Domain_t gEcDomans[];
extern SaSi_PalMutex sasiAsymCryptoMutex;
extern const int8_t regTemps[PKA_MAX_COUNT_OF_PHYS_MEM_REGS];

/*
 * The function sets data into SRAM and calculates ECDSA Signature.
 *
 * @author reuvenl (3/29/2015)
 *
 * Note: All data in is given with LE order of words (LS word is left most).
 *       Algorithm - according ANS X9.62 denoted [1].
 *
 * @param pDomain - The pointer to EC domain structure.
 * @param pSignPrivKey - The pointer to signer private key data of size = EC
 *                     order size in words (with leading zeros).
 * @param pMessRepres - The pointer to the message representative buffer of size
 *                = EC modulus size in words.
 * @param pEphemKey - The pointer to private Ephemeral key buff; size
 *                 of the data must be equal EC order size in words (with
 *                 leading zeros).
 * @param pEphemPublX - The pointer to X-coordinate of Ephemeral publ. key buff;
 *                 size of the data must be equal EC modulus size in words (with
 *                 leading zeros).
 * @param pSignC - The pointer to C-part of the signature (R-part in some
 *               standards); size of the data must be equal EC order size in
 *               words (with leading zeros).
 * @param pSignD - The pointer to D-part of the signature (S-part in some
 *               standards); size of the data must be = EC order size in words
 *               (with leading zeros).
 *
 *
 * @return SaSiError_t
 */
static SaSiError_t PKA_SignCalc(const SaSi_ECPKI_Domain_t *pDomain, /* in/out */
                                uint32_t *pSignPrivKey,             /* in */
                                uint32_t *pMessRepres,              /* in */
                                uint32_t *pEphemKey,                /* in */
                                uint32_t *pEphemPublX,              /* in */
                                uint32_t *pSignC,                   /* out */
                                uint32_t *pSignD)                   /* out */
{
    /* LOCAL DECLARATIONS */

    /* errors identifier */
    SaSiError_t err = SaSi_OK;
    uint32_t status;

    /* EC domain parameters */
    uint32_t ordSizeInWords, modSizeInWords;
    uint32_t pkaReqRegs = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;
    /* define regs (rn=0, rnp=1) */
    uint8_t rC    = regTemps[2]; /* C (zR) - signC */
    uint8_t rM    = regTemps[3]; /* message (zF) */
    uint8_t rEphK = regTemps[4]; /* ephemer.priv.key */
    uint8_t rK    = regTemps[5]; /* priv. key (zD) */
    uint8_t rKinv = regTemps[6];
    uint8_t rD    = regTemps[7]; /* D (zS)- signD */
    uint8_t rT    = regTemps[8];

    /* FUNCTION LOGIC */

    /* set EC modulus and order sizes */
    ordSizeInWords = CALC_FULL_32BIT_WORDS(pDomain->ordSizeInBits);
    modSizeInWords = CALC_FULL_32BIT_WORDS(pDomain->modSizeInBits);

    /*  Init PKA for operations with EC order */
    err = PKA_InitAndMutexLock(pDomain->ordSizeInBits, &pkaReqRegs); // RL Count regs to clean 9!
    if (err != SaSi_OK) {
        return err;
    }

    /* -------------------------------- */
    /*   Set data into PKA registers  */
    /* -------------------------------- */
    /* Note: ignore false positive KW warning about explicit offset:      *
       sizes, given in the EC Domain, must be right                      */
    PKA_CopyDataIntoPkaReg(rn, 1, pDomain->ecR /* src_ptr */, ordSizeInWords);
    PKA_CopyDataIntoPkaReg(rnp, 1, ((PKA_EcDomainLlf_t *)&(pDomain->llfBuff))->ordTag,
                           SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    PKA_CopyDataIntoPkaReg(rC, 1, pEphemPublX, modSizeInWords);
    PKA_CopyDataIntoPkaReg(rM, 1, pMessRepres, ordSizeInWords);
    PKA_CopyDataIntoPkaReg(rEphK, 1, pEphemKey, ordSizeInWords);
    PKA_CopyDataIntoPkaReg(rK, 1, pSignPrivKey, ordSizeInWords);

    /* ---------------------------------------------- */
    /* -----------  Calculate Signature    ---------- */
    /* ---------------------------------------------- */

    /* [1] 7.3. calc. rEphK mod rn and check that it > 0 */
    PKA_DIV(LEN_ID_MAX_BITS, rT /* not used */, rEphK, rn);
    PKA_COMPARE_IM_STATUS(LEN_ID_MAX_BITS, rEphK, 0, status);
    if (status == 1) {
        err = LLF_ECDSA_SIGN_BAD_EPHEMER_KEY_TRY_AGAIN_ERROR;
        goto End;
    }

    /* check rKinv != 0  (ANS X9.62 7.3) */
    PKA_MOD_INV_W_EXP(rKinv, rEphK, rT /* temp */); /* RL to inv_fast */
    PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, rKinv, 0, status);
    if (status == 1) {
        err = LLF_ECDSA_SIGN_BAD_EPHEMER_KEY_TRY_AGAIN_ERROR;
        goto End;
    }
    PKA_MOD_MUL(LEN_ID_N_BITS, rD, rK, rC);
    PKA_REDUCE(LEN_ID_N_BITS, rM, rM);
    PKA_MOD_ADD(LEN_ID_N_PKA_REG_BITS, rD, rD, rM);
    PKA_MOD_MUL(LEN_ID_N_BITS, rD, rD, rKinv);
    /* check rD != 0  (ANS X9.62 7.3) */
    PKA_COMPARE_IM_STATUS(LEN_ID_N_PKA_REG_BITS, rD, 0, status);
    if (status == 1) {
        err = LLF_ECDSA_SIGN_BAD_EPHEMER_KEY_TRY_AGAIN_ERROR;
        goto End;
    }
    /* if status == 0 then copy the signature to the output */
    if (status == 0) {
        PKA_CopyDataFromPkaReg(pSignC, ordSizeInWords, rC);
        PKA_CopyDataFromPkaReg(pSignD, ordSizeInWords, rD);
    }

End:

    PKA_FinishAndMutexUnlock(pkaReqRegs);

    return err;

} /* END OF PKA_SignCalc */

/* *********************** Public Functions ***************** */

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
 *                    of the buffer must be not less than (3*ModulusSizeInWords
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
                                   uint32_t *pTempBuff /* in */)
{
    /* LOCAL DECLARATIONS */

    /* errors identifier */
    SaSiError_t err = SaSi_OK;

    /* EC domain parameters */
    const SaSi_ECPKI_Domain_t *pDomain = &pSignPrivKey->domain;
    uint32_t ordSizeInBits, ordSizeInWords, modSizeInWords;
    /* pointers to result EC point coordinates x, y */
    uint32_t *pEphemPublX, *pEphemPublY, *pEphemKeyBuf, *pMaxVect;
    uint32_t *funcTmpBuff;
    uint32_t countTries = 0;

    /* set EC domain parameters modulus and EC order sizes */
    ordSizeInBits  = pDomain->ordSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);
    modSizeInWords = CALC_FULL_32BIT_WORDS(pDomain->modSizeInBits);

    /* FUNCTION LOGIC */

    pEphemPublX  = pTempBuff; // ?? use pSignC to save mem
    pEphemKeyBuf = pEphemPublX + modSizeInWords;
    pEphemPublY  = pEphemKeyBuf + ordSizeInWords;
    pMaxVect     = pEphemPublY + modSizeInWords;

    while (1) {
        /* ***********  Generate random ephemeral key    **********   *
         * Note: Checking, that private ephemer.key  0 < k < EC order *
         * performed on LLF during scalar multiplication             */

        if (isEphemerKeyInternal) {
            /* Set bytes MaxVect= EcOrder. */
            pMaxVect[ordSizeInWords - 1] = 0; /* zero MSWord of maxVect */
            SaSi_PalMemCopy(pMaxVect, pDomain->ecR, sizeof(uint32_t) * ordSizeInWords);
            /* TBD! set properly LE bytes order for pTempBuff, when BE PC is used */
            pEphemKeyBuf[ordSizeInWords - 1] = 0; /* zero MSWord */
            err = SaSi_RND_GenerateVectorInRange(pRndContext, pDomain->ordSizeInBits, (uint8_t *)pMaxVect /* maxVect */,
                                                 (uint8_t *)pEphemKeyBuf);
            if (err) {
                goto End;
            }
            /* RL TBD! set words Endianness for pEphKeyBuf, when BE PC is used  */
        }
        /* copy external key if provided */
        else {
            if (countTries > 0) {
                /* external ephemer.key must pass from first  *
                 *  try; if it isn't then return error          */
                err = LLF_ECDSA_SIGN_CALC_CANNOT_CREATE_SIGNATURE;
                goto End;
            }
            /* Note: Checking of range of the ephemeral key       *
             *  performed in LLF_ECPKI_ScalarMult                  */
            SaSi_PalMemCopy(pEphemKeyBuf, pEphemKey, sizeof(uint32_t) * ordSizeInWords);
        }

        /* ---------------------------------------------- */
        /* Calculate ephemeral public key               */
        /* ---------------------------------------------- */
        funcTmpBuff = pMaxVect; /* because pMaxVect not needed yet */
        err         = LLF_ECPKI_ScalarMult(pDomain, pEphemKeyBuf /* scalar */, ordSizeInWords,       /* scalar size */
                                   (uint32_t *)&pDomain->ecGx, (uint32_t *)&pDomain->ecGy, /* in point coordinates */
                                   pEphemPublX /* C */, pEphemPublY, /* out point coordinates */
                                   funcTmpBuff);
        if (err) {
            goto End;
        }

        /* ---------------------------------------------- */
        /* -----------  Calculate Signature S  ---------- */
        /* ---------------------------------------------- */

        err = PKA_SignCalc(pDomain, pSignPrivKey->PrivKey, pMessRepres, pEphemKeyBuf, pEphemPublX, pSignC, pSignD);

        /* exit the programm if an error occurs, beside the case of   *
         *  returned error message to try a new Ephemeral Key          */
        if (err && (err != LLF_ECDSA_SIGN_BAD_EPHEMER_KEY_TRY_AGAIN_ERROR || !isEphemerKeyInternal)) {
            goto End;
        }

        /* if error is OK or count of tries > 100, then end the loop */
        if ((err == 0) || (countTries > 100)) {
            goto End;
        } else {
            countTries++;
        }
    } /* End of while() */

/*    End the function  */
End:

    return err;

} /* END OF HostEcdsaSign */

#include "pka_ecc_glob_regs_undef.h"
