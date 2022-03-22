/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

/* ************ Include Files ************** */

#include "dx_pal_mem.h"
#include "dx_pal_types.h"
#include "crys_common_math.h"
#include "crys_common.h"
#ifndef _INTERNAL_CRYS_NO_RSA_CRT_CONVERT_SUPPORT
#include "crys_rnd.h"
#endif
#include "sw_llf_pki.h"
#ifndef DX_SOFT_KEYGEN
#include "crys_pka_defs.h"
#endif
#include "sw_llf_pki_error.h"
#include "sw_llf_pki_rsa.h"

/* *********************** Defines **************************** */
/* *********************** Enums ****************************** */
/* *********************** Typedefs *************************** */
/* *********************** Global Data ************************ */

/* ******************   Exported functions ******************** */

/*
 * @brief This function initializes the low level key database public structure.
 *        On the Lite platform the Hn vector is initialized
 *
 * @param[in] LLFSpesificParams - spesific parameters required on this LLF implementation.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in.
 */
CRYSError_t SW_LLF_PKI_RSA_InitPubKeyDb(SW_CRYSRSAPubKey_t *PubKey_ptr)
{
    /* LOCAL DECLERATIONS */

    /* error identification */
    CRYSError_t Error;

    /* FUNCTION LOGIC */

    /* .................... initialize local variables ...................... */
    /* ---------------------------------------------------------------------- */

    /* to avoid compilers warnings */
    PubKey_ptr = PubKey_ptr;

    /* initialize the error identifier to success */
    Error = CRYS_OK;

    return Error;

} /* END OF SW_LLF_PKI_RSA_InitPubKeyDb */

/*
 * @brief This function initializes the low level key database private structure.
 *        On the Lite platform the Hn vector is initialized
 *
 *
 * @param[in] LLFSpesificParams - specific parameters required on this LLF implementation.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t SW_LLF_PKI_RSA_InitPrivKeyDb(SW_CRYSRSAPrivKey_t *PrivKey_ptr)
{
    /* LOCAL DECLERATIONS */

    /* error identification */
    CRYSError_t Error;

    /* FUNCTION LOGIC */

    /* .................... initialize local variables ...................... */
    /* ---------------------------------------------------------------------- */

    /* to avoid compilers warnings */
    PrivKey_ptr = PrivKey_ptr;

    /* initialize the error identifier to success */
    Error = CRYS_OK;

    /* ................... calculate the H vectors .......................... */
    /* ---------------------------------------------------------------------- */

    return Error;

} /* END OF SW_LLF_PKI_RSA_InitPrivKeyDb */

/*
 * @brief This function executes the RSA primitive public key exponent engine
 *
 *
 * @param[in] PubKey_ptr - the public key database.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t SW_LLF_PKI_RSA_ExecPubKeyExp(SW_CRYSRSAPubKey_t *PubKey_ptr, SW_CRYS_RSAPrimeData_t *PubData_ptr)
{
    /* LOCAL DECLERATIONS */

    /* error identification */
    CRYSError_t Error;

    /* the window size */
    uint32_t Window;

    /* FUNCTION LOGIC */

    /* ............... initialize local variables ......................... */
    /* -------------------------------------------------------------------- */

    /* initialize the error identifier to the CRYS_OK ( success ) */
    Error = CRYS_OK;

    /* ............... execute the exponent ............................... */
    /* -------------------------------------------------------------------- */

    /* set the window to 1 */
    Window = 1;

    Error = LLF_PKI_UTIL_CalcExponent(PubData_ptr->DataIn, PubKey_ptr->nSizeInBits, PubKey_ptr->e,
                                      PubKey_ptr->eSizeInBits, PubKey_ptr->n, PubKey_ptr->nSizeInBits, Window,
                                      PubData_ptr->LLF.Data.NonCrt.Tempbuff1, PubData_ptr->LLF.Data.NonCrt.Tempbuff2,
                                      PubData_ptr->DataOut);

    return Error;

} /* END OF SW_LLF_PKI_RSA_ExecPubKeyExp */

/*
 * @brief This function executes the RSA primitive private key exponent engine
 *
 *
 * @param[in] PubKey_ptr - the private key database.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t SW_LLF_PKI_RSA_ExecPrivKeyExp(SW_CRYSRSAPrivKey_t *PrivKey_ptr, SW_CRYS_RSAPrimeData_t *PrivData_ptr)
{
    /* LOCAL DECLERATIONS */

    /* error identification */
    CRYSError_t Error;

    /* the window size */
    uint32_t Window;

    /* FUNCTION LOGIC */

    /* ............... initialize local variables ......................... */
    /* -------------------------------------------------------------------- */

    /* initialize the error identifier to the CRYS_OK ( success ) */
    Error = CRYS_OK;

    /* ............... execute the exponent on non CRT mode ............... */
    /* -------------------------------------------------------------------- */

    if (PrivKey_ptr->OperationMode == CRYS_RSA_NoCrt) {
        /* if the size is grater then 1280 - then set the window to 6 else set it to 5 */
        if (PrivKey_ptr->nSizeInBits > 1280)
            Window = 6;
        else
            Window = 5;

        /* check that window is not great than the defined maximal value */
        if (Window > PKI_EXP_SLIDING_WINDOW_MAX_VALUE)
            Window = PKI_EXP_SLIDING_WINDOW_MAX_VALUE;

        Error = LLF_PKI_UTIL_CalcExponent(
            PrivData_ptr->DataIn, PrivKey_ptr->nSizeInBits, PrivKey_ptr->PriveKeyDb.NonCrt.d,
            PrivKey_ptr->PriveKeyDb.NonCrt.dSizeInBits, PrivKey_ptr->n, PrivKey_ptr->nSizeInBits, Window,
            PrivData_ptr->LLF.Data.NonCrt.Tempbuff1, PrivData_ptr->LLF.Data.NonCrt.Tempbuff2, PrivData_ptr->DataOut);

        /* ..................... START : Countermeasures DFA ...................... */
        /* *********************************************************************** */

#ifndef CRYS_NO_SELF_TEST_SUPPORT

        if (PrivKey_ptr->PriveKeyDb.NonCrt.eSizeInBits != 0) {
            /* Execute the inverse operation */
            /* ****************************** */
            Error = LLF_PKI_UTIL_CalcExponent(
                PrivData_ptr->DataOut, PrivKey_ptr->nSizeInBits, PrivKey_ptr->PriveKeyDb.NonCrt.e,
                PrivKey_ptr->PriveKeyDb.NonCrt.eSizeInBits, PrivKey_ptr->n, PrivKey_ptr->nSizeInBits, Window,
                PrivData_ptr->LLF.Data.NonCrt.Tempbuff1, PrivData_ptr->LLF.Data.NonCrt.Tempbuff2,
                PrivData_ptr->LLF.Data.NonCrt.TempBuffer);

            /* if the result is not the same as the original data set the test as failure */
            if (CRYS_COMMON_CmpLsbUnsignedCounters((uint8_t *)&PrivData_ptr->DataIn, (PrivKey_ptr->nSizeInBits / 8),
                                                   (uint8_t *)&PrivData_ptr->LLF.Data.NonCrt.TempBuffer,
                                                   (PrivKey_ptr->nSizeInBits / 8))) {
                DX_PAL_MemSetZero(PrivData_ptr, sizeof(SW_CRYS_RSAPrimeData_t));
                DX_PAL_MemSetZero(PrivKey_ptr, sizeof(SW_CRYS_RSAUserPrivKey_t));

#ifdef CRYS_FIPS_SUPPORT
                DX_GLOBAL_FIPS_MODE = DX_CRYS_FIPS_MODE_ERROR_STATE;
#endif
                return SW_LLF_PKI_COUNTERMEASURES_DFA_FAIL_ERROR;
            }
        } /* end if eSizeInBits!=0 */

#endif /* CRYS_NO_SELF_TEST_SUPPORT */

        /* ..................... END : Countermeasures DFA ..................... */
        /* ********************************************************************** */

    }

    /* ............... execute the exponent on CRT mode ................... */
    /* -------------------------------------------------------------------- */

    else {
#ifndef _INTERNAL_CRYS_NO_RSA_CRT_MODE_SUPPORT
        Error = LLF_PKI_UTIL_CalcExponentCrt(
            PrivData_ptr->DataIn, PrivKey_ptr->nSizeInBits, PrivKey_ptr->n, PrivKey_ptr->nSizeInBits,
            PrivKey_ptr->PriveKeyDb.Crt.P, PrivKey_ptr->PriveKeyDb.Crt.PSizeInBits, PrivKey_ptr->PriveKeyDb.Crt.Q,
            PrivKey_ptr->PriveKeyDb.Crt.QSizeInBits, PrivKey_ptr->PriveKeyDb.Crt.dP,
            PrivKey_ptr->PriveKeyDb.Crt.dPSizeInBits, PrivKey_ptr->PriveKeyDb.Crt.dQ,
            PrivKey_ptr->PriveKeyDb.Crt.dQSizeInBits, PrivKey_ptr->PriveKeyDb.Crt.qInv,
            PrivKey_ptr->PriveKeyDb.Crt.qInvSizeInBits, PrivData_ptr->LLF.Data.Crt.Tempbuff1,
            PrivData_ptr->LLF.Data.Crt.Tempbuff2, PrivData_ptr->DataOut);
#else
        Error = SW_LLF_PKI_RSA_CRT_MODE_NOT_SUPPORTED;
#endif

    } /* end of CRT mode exponent calculation case */

    return Error;

} /* END OF SW_LLF_PKI_RSA_ExecPrivKeyExp */

#ifndef _INTERNAL_CRYS_NO_RSA_KG_SUPPORT
/*
 * @brief This function generates a key pair
 *
 *
 * @param[in] PubKey_ptr - the public key database.
 * @param[in] PrivKey_ptr - the private key database.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
CRYSError_t SW_LLF_PKI_RSA_GenerateKeyPair(SW_CRYSRSAPubKey_t *PubKey_ptr, SW_CRYSRSAPrivKey_t *PrivKey_ptr,
                                           SW_CRYS_RSAKGData_t *KeyGenData_ptr)
{
    /* LOCAL DECLERATIONS */

    /* error identification */
    CRYSError_t Error;

    /* length in words */
    uint32_t eLenInWords;
    uint32_t nLenInWords;

    /* FUNCTION LOGIC */

    /* ................. initialize local variables .................... */
    /* ----------------------------------------------------------------- */

    Error = CRYS_OK;

    /* setting the public exponent size in words */
    eLenInWords = PubKey_ptr->eSizeInBits / 32;

    if (PubKey_ptr->eSizeInBits % 32)

        eLenInWords++;

    /* setting the required modolus size in words */
    nLenInWords = PubKey_ptr->nSizeInBits / 32;

    /* ............. calling the low level function on non CRT mode .... */
    /* ----------------------------------------------------------------- */

    if (PrivKey_ptr->OperationMode == CRYS_RSA_NoCrt) {
        Error =
            SW_LLF_PKI_genKey(PubKey_ptr->e, eLenInWords, PubKey_ptr->n, nLenInWords, PrivKey_ptr->PriveKeyDb.NonCrt.d,
                              KeyGenData_ptr->KGData.p, KeyGenData_ptr->KGData.q, NULL, /* not used in nonCRT */
                              NULL, NULL, KeyGenData_ptr->KGData.TempbuffExp, PLS_FALSE /* means - non CRT mode */);

        PrivKey_ptr->PriveKeyDb.NonCrt.dSizeInBits = CRYS_COMMON_GetBytesCounterEffectiveSizeInBits(
            (uint8_t *)PrivKey_ptr->PriveKeyDb.NonCrt.d, (PubKey_ptr->nSizeInBits / 8));

    } else {
        Error = SW_LLF_PKI_genKey(
            PubKey_ptr->e, eLenInWords, PubKey_ptr->n, nLenInWords, KeyGenData_ptr->KGData.TempbuffExp,
            KeyGenData_ptr->KGData.p, KeyGenData_ptr->KGData.q, PrivKey_ptr->PriveKeyDb.Crt.dP,
            PrivKey_ptr->PriveKeyDb.Crt.dQ, PrivKey_ptr->PriveKeyDb.Crt.qInv,
            &KeyGenData_ptr->KGData.TempbuffExp[SW_CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS], PLS_TRUE);

        if (Error != CRYS_OK) {
            return Error;
        }

        /* load 'P' & 'Q' to the private */
        DX_PAL_MemCopy(PrivKey_ptr->PriveKeyDb.Crt.Q, KeyGenData_ptr->KGData.q, (nLenInWords / 2) * sizeof(uint32_t));
        DX_PAL_MemCopy(PrivKey_ptr->PriveKeyDb.Crt.P, KeyGenData_ptr->KGData.p, (nLenInWords / 2) * sizeof(uint32_t));
    }

    /* load 'n' to the private */
    DX_PAL_MemCopy(PrivKey_ptr->n, PubKey_ptr->n, nLenInWords * sizeof(uint32_t));

    return Error;

} /* END OF SW_LLF_PKI_RSA_GenerateKeyPair */
#endif
