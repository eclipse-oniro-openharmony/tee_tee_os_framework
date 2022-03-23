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
#include "sasi_ecpki_types.h"
#include "pka_export.h"
#include "pka.h"
#include "pka_ecc_export.h"
#include "pka_ecc_error.h"
#include "pka_modular_arithmetic.h"
#include "pka_dbg.h"
#include "sasi_common.h"

/* *********************** Defines **************************** */

/* Define common ECC PKA registers allocation */
// rn=0, rnp=1, rt=2, rt1=3, rt2=4, rt3=5, rt4=6, ra_q=7, ra_nm2=8, raaa_z=9;
// rn_4=10, rn_8=11, rn_12=12, ec_a=13;
// r2mul_xpq=14, r2mul_ypq=15, r2mul_zr=16, r2mul_tr=17;

/* *********************** Enums **************************** */
/* *********************** Typedefs ************************* */
/* *********************** Global Data ********************** */

/* *********************** Public Functions ***************** */

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
void HostEcdsaTruncateMess(uint32_t *pMessOut, uint8_t *pMessIn, uint32_t outSizeBits)
{
    uint32_t i, shift;
    uint32_t outSizeBytes = CALC_FULL_BYTES(outSizeBits);

    /* reverse copy only a needded bytes of the message */
    SaSi_COMMON_ReverseMemcpy((uint8_t *)pMessOut, pMessIn, outSizeBytes);

    /* shift right by redundant bits */
    shift = (8 - (outSizeBits & 7UL)) & 7UL;
    if (shift) {
        for (i = 0; i < CALC_FULL_32BIT_WORDS(outSizeBits) - 1; i++) {
            pMessOut[i] = (pMessOut[i] >> shift) | (pMessOut[i + 1] << (32 - shift));
        }
        pMessOut[i] = pMessOut[i] >> shift;
    }
    return;
}

/* ****************************************************************************************
 *               LLF_ECPKI_InitPubKey function
 * ************************************************************************************** */
/*
 *      The function performs uncompression (extracts Y-coordinate) checks
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
SaSiError_t LLF_ECPKI_InitPubKey(struct SaSi_ECPKI_PublKey_t *pPublKey, uint8_t pointCtl)
{
    /* LOCAL DECLARATIONS */

    /* the error identifier */
    SaSiError_t err = SaSi_OK;
    uint32_t modSizeInBits, modSizeInWords;
    SaSi_ECPKI_Domain_t *pDomain;
    uint32_t w;
    int32_t rootExist;
    uint32_t pkaReqRegs = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;

    /* define virt. pointers to pka regs. */
#include "pka_point_compress_regs_def.h"
    /* rN=0, rNp=1 rX=2, rY=3, rEcA=4, rEcB=5 */

    /*  INITIALIZATIONS  */

    /* EC domain parameters */
    pDomain = &pPublKey->domain;

    modSizeInBits  = pDomain->modSizeInBits;
    modSizeInWords = CALC_FULL_32BIT_WORDS(modSizeInBits);

    if (modSizeInWords > SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS)
        return SaSi_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_SIZE_ERROR;

    /*       lock mutex and init PKA  */
    err = PKA_InitAndMutexLock(modSizeInBits, &pkaReqRegs);
    if (err != SaSi_OK) {
        return err;
    }

    /* set modulus P and Barrett tag NP into PKA registers 0,1 */
    PKA_CopyDataIntoPkaReg(rN /* dstReg */, 1, pDomain->ecP, modSizeInWords);

    PKA_CopyDataIntoPkaReg(rNp /* dstReg */, 1, pDomain->llfBuff /* NP */, SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);

    /* set public key coordinates into PKA registers  */
    PKA_CopyDataIntoPkaReg(rX /* dstReg */, 1, pPublKey->x, modSizeInWords);

    /* set EC params */
    PKA_CopyDataIntoPkaReg(rEcA /* dstReg */, 1, pDomain->ecA, modSizeInWords);
    PKA_CopyDataIntoPkaReg(rEcB /* dstReg */, 1, pDomain->ecB, modSizeInWords);

    /* calculate  y^2 for from x */
    PKA_MOD_MUL(LEN_ID_N_BITS, rT /* Res */, rX /* OpA */, rX /* OpB */);
    PKA_MOD_ADD(LEN_ID_N_PKA_REG_BITS, rT /* Res */, rT /* OpA */, rEcA /* OpB */);
    PKA_MOD_MUL(LEN_ID_N_BITS, rT /* Res */, rX /* OpA */, rT /* OpB */);
    PKA_MOD_ADD(LEN_ID_N_PKA_REG_BITS, rY2 /* =rEcA */, rT /* OpA */, rEcB /* OpB */);

    if ((pointCtl & 6) != 2) {
        /* ----------------------------------------------------- */
        /*   Partly check uncompressed key (is it on curve ?)  */
        /* ----------------------------------------------------- */
        /* calculate y^2 directly */
        PKA_CopyDataIntoPkaReg(rY /* dstReg */, 1, pPublKey->y, modSizeInWords);
        PKA_MOD_MUL(LEN_ID_N_BITS, rT, rY, rY);
        PKA_COMPARE_STATUS(LEN_ID_N_PKA_REG_BITS, rY2, rT, w /* stat */);
        if (w != 1) {
            err = SaSi_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_DATA_ERROR;
            goto End;
        }
    } else {
        /* ----------------------------------------------------- */
        /*    Uncompress the Y coordinate if needed            */
        /* ----------------------------------------------------- */
        /* derive modular square root (in/out registers according to  *
         *  included definitions file                                  */
        /* implicit parameterss: rY(rY1)=3(out), rY2(rEcA)=4(in),      *
         * rN=0(in)                                                    */
        rootExist = pka_mod_square_root();

        /* check is the root exists */
        if (rootExist != 1) {
            err = PKA_MOD_SQUARE_ROOT_NOT_EXIST_ERROR;
            goto End;
        }

        /* check Y LS-bit and set Y = -Y if need */
        PKA_READ_WORD_FROM_REG(w, 0, rY);
        if ((w & 1) != (pointCtl & 1)) {
            PKA_SUB(LEN_ID_N_PKA_REG_BITS, rY, rN, rY);
        }

        /* copy Y-coordinate */
        PKA_CopyDataFromPkaReg(pPublKey->y /* dst */, modSizeInWords, rY /* src reg */);
    }

End:

    PKA_FinishAndMutexUnlock(pkaReqRegs);

    /* Un define PKA registers */
#include "pka_point_compress_regs_undef.h"

    return err;
}

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
                                       uint32_t *pTempBuff)            /* in */
{
    /* LOCAL DECLARATIONS */

    /* the error identifier */
    SaSiError_t err;
    uint32_t ordSizeInWords, modSizeInWords, sizeBits;
    uint32_t *outPointX, *outPointY;
    uint32_t *pTmpForFunc;

    /*  INITIALIZATIONS  */

    modSizeInWords = CALC_FULL_32BIT_WORDS(pPublKey->domain.modSizeInBits);
    ordSizeInWords = CALC_FULL_32BIT_WORDS(pPublKey->domain.ordSizeInBits);

    /* scalar mult. resut coordinates  */
    outPointX   = pTempBuff;
    outPointY   = outPointX + modSizeInWords;
    pTmpForFunc = outPointY + modSizeInWords;

    /* FUNCTION LOGIC */

    /* scalar mult publ.key point by EC generator order ecR */
    err = LLF_ECPKI_ScalarMult(&pPublKey->domain, pPublKey->domain.ecR, /* in */
                               ordSizeInWords,                          /* in - publ key X */
                               pPublKey->x,                             /* in - publ key Y */
                               pPublKey->y,                             /* in */
                               outPointX,                               /* out */
                               outPointY,                               /* out */
                               pTmpForFunc);
    if (err)
        goto End;

    /* check that out point is on infinity */
    sizeBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(outPointY, modSizeInWords);
    if (sizeBits > 0) {
        err = SaSi_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_DATA_ERROR;
        goto End;
    }
    /* check condition for X */
    sizeBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(outPointX, modSizeInWords);
    if (sizeBits > 0) {
        err = SaSi_ECPKI_BUILD_KEY_INVALID_PUBL_KEY_DATA_ERROR;
        goto End;
    }

/* .............. end of the function ................................... */
/* ---------------------------------------------------------------------- */
End:

    return err;

} /* END OF LLF_ECPKI_FullCheckPublKey */

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
SaSiError_t LLF_ECPKI_SVDP_DH(struct SaSi_ECPKI_PublKey_t *pPublKey,  /* in */
                              SaSi_ECPKI_PrivKey_t *pPrivKey,  /* in */
                              uint8_t *pSharedSecretValue,     /* out */
                              SaSi_ECDH_TempData_t *pTempBuff) /* in */
{
    /* LOCAL DECLARATIONS */

    /* the error identifier */
    SaSiError_t err;
    uint32_t ordSizeInWords, modSizeInWords;
    uint32_t *outPointX, *outPointY;
    uint32_t *pTmpForFunc;

    /*  INITIALIZATIONS  */

    modSizeInWords = CALC_FULL_32BIT_WORDS(pPublKey->domain.modSizeInBits);
    ordSizeInWords = CALC_FULL_32BIT_WORDS(pPublKey->domain.ordSizeInBits);

    /* scalar mult. resut coordinates  */
    outPointX   = (uint32_t *)pTempBuff;
    outPointY   = outPointX + modSizeInWords;
    pTmpForFunc = outPointY + modSizeInWords;

    /* FUNCTION LOGIC */

    /* scalar mult publ.key point by EC generator order ecR */
    err = LLF_ECPKI_ScalarMult(&pPublKey->domain, pPrivKey->PrivKey, /* in */
                               ordSizeInWords,                       /* in - publ key X */
                               pPublKey->x,                          /* in - publ key Y */
                               pPublKey->y,                          /* in */
                               outPointX,                            /* out */
                               outPointY,                            /* out */
                               pTmpForFunc);                         /* in */
    if (err)
        goto End;

    /* Note: Because output of scalar mult result point in affine         *
     *  form,there no need to check, that coordinates X,Y <= mod-1.       */
    /* Check that out point is not on infinity, i.e. X,Y != 0             */
    if (SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(outPointY, modSizeInWords) == 0 ||
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(outPointX, modSizeInWords) == 0) {
        err = LLF_ECPKI_SVDP_DH_SHARED_VALUE_IS_ON_INFINITY_ERROR;
        goto End;
    } else {
        /* copy X-coordinate of SecrP to output */
        SaSi_COMMON_ReverseMemcpy(pSharedSecretValue, (uint8_t *)outPointX, sizeof(uint32_t) * modSizeInWords);
    }

    /* ........ end of the function ............ */
End:

    /*     clear the ECDH temporary data structure    */
    SaSi_PalMemSetZero(pTempBuff, sizeof(SaSi_ECDH_TempData_t));

    return err;

} /* END OF LLF_ECPKI_FullCheckPublKey */
