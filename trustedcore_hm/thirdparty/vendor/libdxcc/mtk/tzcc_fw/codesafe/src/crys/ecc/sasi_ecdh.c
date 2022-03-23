/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

/* SaSi level includes  */
#include "ssi_pal_mem.h"
#include "sasi_ecpki_error.h"
#include "sasi_ecpki_local.h"

/* LLF level includes  */
#include "pka_ecc_export.h"
#include "sasi_fips_defs.h"

/* *********************** Defines *********************************** */

/* *********************** Enums ************************************* */

/* *********************** Typedefs ********************************** */

/* *********************** Global Data ******************************* */

/* ************ Private function prototype *************************** */

/* *********************** Public Functions ************************** */

/* **********************************************************************
 *                 SaSi_ECDH_SVDP_DH_MTK function                            *
 * ******************************************************************** */
/*
 @brief    Creates the shared secret value accordingly to the IEEE 1363-2000
                        standard.

               This function performs the following:

                -# Checks input parameters pointers and accordance of domains in public
                   and prinate keys.
                -# Derives the partner public key and calls the LLF_ECPKI_SVDP_DH function,
                   which performs EC SVDP operations. On errors, outputs error messages.
                -# Exits.

        NOTE:    1. The partner public key and user private key must relate to the same EC Domain.
                 2. The public key must be fully validated by the user before using in this primitive.
                 3. The buffer size for SharedSecretValue must be >= ModulusSizeInWords*4 bytes,
                    and the output size of the shared value should be equal to ModulusSize in bytes.



 @param[in]  PartnerPublKey_ptr         A pointer to a partner public key.
 @param[in]  UserPrivKey_ptr            A pointer to a user private key.
 @param[out] SharedSecretValue_ptr      A pointer to an output buffer that will contain
                                        the shared secret value.
 @param[in,out] SharedSecrValSize_ptr   A pointer to the size of user passed buffer (in) and
                                        actual output size (out) of calculated shared secret value.
 @param[in]  TempBuff_ptr               A pointer to a temporary buffer of size, specified in
                                        the SaSi_ECDH_TempData_t structure.
 @return <b>SaSiError_t</b>: <br>
                         SaSi_OK<br>
                         SaSi_ECDH_SVDP_DH_INVALID_USER_PRIV_KEY_PTR_ERROR<br>
                         SaSi_ECDH_SVDP_DH_USER_PRIV_KEY_VALID_TAG_ERROR<br>
                         SaSi_ECDH_SVDP_DH_INVALID_PARTNER_PUBL_KEY_PTR_ERROR<br>
                         SaSi_ECDH_SVDP_DH_PARTNER_PUBL_KEY_VALID_TAG_ERROR<br>
                         SaSi_ECDH_SVDP_DH_INVALID_SHARED_SECRET_VALUE_PTR_ERROR<br>
                         SaSi_ECDH_SVDP_DH_INVALID_SHARED_SECRET_VALUE_SIZE_PTR_ERROR<br>
                         SaSi_ECDH_SVDP_DH_INVALID_SHARED_SECRET_VALUE_SIZE_ERROR<br>
                         SaSi_ECDH_SVDP_DH_INVALID_TEMP_DATA_PTR_ERROR<br>

*/
CEXPORT_C SaSiError_t SaSi_ECDH_SVDP_DH_MTK(SaSi_ECPKI_UserPublKey_t *PartnerPublKey_ptr, /* in */
                                            SaSi_ECPKI_UserPrivKey_t *UserPrivKey_ptr,    /* in */
                                            uint8_t *SharedSecretValue_ptr,               /* out */
                                            uint32_t *SharedSecrValSize_ptr,              /* in/out */
                                            SaSi_ECDH_TempData_t *TempBuff_ptr /* in */)
{
    /* LOCAL INITIALIZATIONS AND DECLERATIONS */

    /* the error identifier */
    SaSiError_t Error = SaSi_OK;

    struct SaSi_ECPKI_PublKey_t *PublKey_ptr;
    SaSi_ECPKI_PrivKey_t *PrivKey_ptr;

    /*  pointer to the current Domain structure */
    SaSi_ECPKI_Domain_t *pDomain, *pPublDomain;
    uint32_t modSizeInBytes;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ...... checking the validity of the user private key pointer .......... */
    if (UserPrivKey_ptr == NULL)
        return SaSi_ECDH_SVDP_DH_INVALID_USER_PRIV_KEY_PTR_ERROR;

    /* ...... checking the valid tag of the user private key pointer ......... */
    if (UserPrivKey_ptr->valid_tag != SaSi_ECPKI_PRIV_KEY_VALIDATION_TAG)
        return SaSi_ECDH_SVDP_DH_USER_PRIV_KEY_VALID_TAG_ERROR;

    /* .... checking the validity of the other partner public key pointer .... */
    if (PartnerPublKey_ptr == NULL)
        return SaSi_ECDH_SVDP_DH_INVALID_PARTNER_PUBL_KEY_PTR_ERROR;

    /* ...... checking the valid tag of the user private key pointer ......... */
    if (PartnerPublKey_ptr->valid_tag != SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG)
        return SaSi_ECDH_SVDP_DH_PARTNER_PUBL_KEY_VALID_TAG_ERROR;

    /* ...... checking the validity of the SharedSecretValue pointer .......... */
    if (SharedSecretValue_ptr == NULL)
        return SaSi_ECDH_SVDP_DH_INVALID_SHARED_SECRET_VALUE_PTR_ERROR;

    /* ...... checking the validity of SharedSecrValSize_ptr pointer ......... */
    if (SharedSecrValSize_ptr == NULL)
        return SaSi_ECDH_SVDP_DH_INVALID_TEMP_DATA_PTR_ERROR;

    /* ...... checking the validity of temp buffers         .................. */
    if (TempBuff_ptr == NULL)
        return SaSi_ECDH_SVDP_DH_INVALID_SHARED_SECRET_VALUE_SIZE_PTR_ERROR;

    /* ..  initializtions  and other checking   .... */
    /* --------------------------------------------- */

    /* derive  public and private keys pointers */
    PublKey_ptr = (struct SaSi_ECPKI_PublKey_t *)&PartnerPublKey_ptr->PublKeyDbBuff;
    PrivKey_ptr = (SaSi_ECPKI_PrivKey_t *)&UserPrivKey_ptr->PrivKeyDbBuff;

    /* the pointers to private and public keys domains */
    pDomain     = &PrivKey_ptr->domain;
    pPublDomain = &PublKey_ptr->domain;

    /* if domains are not identical, return an error */
    if (SaSi_PalMemCmp(pDomain, pPublDomain, sizeof(SaSi_ECPKI_Domain_t))) {
        return SaSi_ECDH_SVDP_DH_NOT_CONCENT_PUBL_AND_PRIV_DOMAIN_ID_ERROR;
    }

    /* modulus size */
    modSizeInBytes = CALC_FULL_BYTES(pDomain->modSizeInBits);

    /*  check the size of the buffer for Shared value  */
    if (*SharedSecrValSize_ptr < modSizeInBytes) {
        *SharedSecrValSize_ptr = modSizeInBytes;
        return SaSi_ECDH_SVDP_DH_INVALID_SHARED_SECRET_VALUE_SIZE_ERROR;
    }

    /* performing DH operations by calling  LLF_ECDH_SVDP_DH() function */
    /* ------------------------------------------------------------------ */
    Error = LLF_ECPKI_SVDP_DH(PublKey_ptr, PrivKey_ptr, SharedSecretValue_ptr, TempBuff_ptr);

    if (Error != SaSi_OK)
        goto End;

    /* Set SharedSecrValSize = ModSizeInWords  for user control */
    *SharedSecrValSize_ptr = modSizeInBytes;

End:
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(SharedSecretValue_ptr, *SharedSecrValSize_ptr);
        *SharedSecrValSize_ptr = 0;
    }
    SaSi_PalMemSetZero(TempBuff_ptr, sizeof(SaSi_ECDH_TempData_t));

    return Error;

} /* END OF SaSi_ECDH_SVDP_DH_MTK */
