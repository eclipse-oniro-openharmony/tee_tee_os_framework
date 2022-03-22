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
#ifndef ARM_DSM
#include "ssi_pal_mutex.h"
#endif
#include "ssi_pal_abort.h"
#include "ssi_hal.h"
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

/* *********************** Defines **************************** */

/* Define common ECC PKA registers allocation */
#include "pka_ecc_glob_regs_def.h"

/* *********************** Enums **************************** */
/* *********************** Typedefs ************************* */
/* *********************** Global Data ********************** */
extern SaSi_PalMutex sasiAsymCryptoMutex;

/* *********************** Public Functions ***************** */

/* ********************************************************** */
/*
 * The function checks input parameters, sets data into SRAM and calls
 * HOST or SEP specific Verify function (aacording to make file of HOST or SEP).
 *
 * @author reuvenl (8/7/2014)
 *
 * @param pSignPublKey - The pointer to signer public key structure.
 * @param pMessRepres - The pointer to the message representative.
 * @param messRepresSizeWords- The size of the message representative
 * @param pSignC - The pointer to C-part of the signature.
 * @param pSignD - The pointer to D-part of the signature.
 *
 * @return SaSiError_t
 */
SaSiError_t HostEcdsaVerify(struct SaSi_ECPKI_PublKey_t *pSignPublKey, /* in */
                            uint32_t *pMessRepres,              /* in */
                            uint32_t messRepresSizeWords,       /* in */
                            uint32_t *pSignC,                   /* in */
                            uint32_t *pSignD /* in */)
{
/* LOCAL DECLARATIONS */

/* define virtual pointers to PKA registers */
/* rR=0 rnR=1 rF=2 rD=3 rh=4 rh1=18 rh2=19
 pG_x=20 pG_y 21 pW_x 22 pW_y=23 pR_x=24 pR_y=25
 rn_t=26 rnp_t=27 rC=28 */
#include "pka_ecdsa_verify_regs_def.h"

    /* errors identifier */
    SaSiError_t err = SaSi_OK;

    /* EC domain parameters */
    const SaSi_ECPKI_Domain_t *domain = &pSignPublKey->domain;
    PKA_EcDomainLlf_t *llfBuff        = (PKA_EcDomainLlf_t *)&pSignPublKey->domain.llfBuff;
    int32_t modSizeInBits, modSizeInWords, ordSizeInBits, ordSizeInWords;
    uint32_t pkaReqRegs = PKA_MAX_COUNT_OF_PHYS_MEM_REGS;

    /* ................ initializtions  ............ */
    /* --------------------------------------------- */

    /* set domain parameters */
    modSizeInBits  = domain->modSizeInBits;
    modSizeInWords = CALC_FULL_32BIT_WORDS(modSizeInBits);
    ordSizeInBits  = domain->ordSizeInBits;
    ordSizeInWords = CALC_FULL_32BIT_WORDS(ordSizeInBits);

    /* FUNCTION LOGIC */

    /*  Init PKA for modular operations with EC modulus or EC order and   *
     *   registers size according to maximal of them                       */
    err = PKA_InitAndMutexLock(SaSi_MAX(ordSizeInBits, modSizeInBits), &pkaReqRegs);
    if (err != SaSi_OK) {
        return err;
    }
    /* set order and modulus mod sizes */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_L0), ordSizeInBits);
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, PKA_L2), modSizeInBits);

    /* --------------------------------------------------- */
    /*            Set input data into PKA registers        */
    /* --------------------------------------------------- */
    /* EC order and its Barrett tag */
    PKA_CopyDataIntoPkaReg(rn /* dest_reg */, 1, domain->ecR /* src_ptr */, ordSizeInWords);
    PKA_CopyDataIntoPkaReg(rnp, 1, llfBuff->ordTag, SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    /* signature C, D */
    PKA_CopyDataIntoPkaReg(rC, 1, pSignC, ordSizeInWords);
    PKA_CopyDataIntoPkaReg(rD, 1, pSignD, ordSizeInWords);
    /* message representative rF */
    PKA_CopyDataIntoPkaReg(rF, 1, pMessRepres, messRepresSizeWords);
    /* Load modulus and its Barrett tag */
    PKA_CopyDataIntoPkaReg(rn_t, 1, domain->ecP, modSizeInWords);
    PKA_CopyDataIntoPkaReg(rnp_t, 1, llfBuff->modTag, SaSi_PKA_BARRETT_MOD_TAG_BUFF_SIZE_IN_WORDS);
    /* set pG */
    PKA_CopyDataIntoPkaReg(pG_x, 1, domain->ecGx, modSizeInWords);
    PKA_CopyDataIntoPkaReg(pG_y, 1, domain->ecGy, modSizeInWords);
    /* set pW */
    PKA_CopyDataIntoPkaReg(pW_x, 1, pSignPublKey->x, modSizeInWords);
    PKA_CopyDataIntoPkaReg(pW_y, 1, pSignPublKey->y, modSizeInWords);
    PKA_CopyDataIntoPkaReg(rec_a, 1, domain->ecA, modSizeInWords);

    /* PKA or SEP calling function */
    err = ECDSA_VERIFY_CALL();

    PKA_FinishAndMutexUnlock(pkaReqRegs);

/* undefine virtual pointers to PKA registers */
#include "pka_ecdsa_verify_regs_undef.h"

    return err;

} /* END OF HostEcdsaVerify */

#include "pka_ecc_glob_regs_undef.h"
