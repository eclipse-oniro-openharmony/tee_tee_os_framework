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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_SECURE_BOOT

/* ************ Include Files ************** */
#include "dx_pal_types.h"
#include "crypto_driver_defs.h"
#include "bootimagesverifier_def.h"
#include "secureboot_error.h"
#include "bootimagesverifier_error.h"
#include "util.h"
#include "bootimagesverifier_parser.h"
#include "crypto_driver.h"
#include "nvm.h"
#include "nvm_mng.h"
#include "bootimagesverifier_swcomp.h"
#include "dx_pal_log.h"
#include "secureboot_base_func.h"
#include "dx_pal_dma.h"
#include "dx_pal_mem.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Internal Functions **************************** */

/* *********************** Public Functions **************************** */

DxError_t DxCertValidateSWComps(DxSbFlashReadFunc flashRead_func, void *userContext,
                                DxSbCertParserSwCompsInfo_t *pSwImagesData, uint32_t *pSwImagesAddData,
                                uint32_t *workspace_ptr, uint32_t workspaceSize)
{
    /* error variable */
    DxError_t error = DX_SUCCESS;

    /* internal index */
    uint32_t i = 0;

    /* internal pointer for the certificate buffer */
    uint32_t *pCurrRec        = DX_NULL;
    uint32_t *pCurrRecAddInfo = DX_NULL;

    /* Hash output size */
    uint16_t hashOutputSize = sizeof(HASH_Result_t);

    /* AES key buffer */
    AES_Key_t AESKey;

    /* ------------------
        CODE
    ------------------- */

    if (pSwImagesData->isSwComponentEncrypted) {
        error = NVM_ReadAESKey(AESKey);
        if (error != DX_SUCCESS)
            return error;
    }

    /* Point to the current s/w record HASH data */
    pCurrRec = pSwImagesData->pSwCompsData;

    /* Point to the current add data */
    pCurrRecAddInfo = pSwImagesAddData;

    /* In a loop, read the SW component data, calculate the HASH and compare */
    /* ----------------------------------------------------------------------- */
    for (i = 0; i < pSwImagesData->numOfSwComps; i++) {
        /* calculate the HASH on the current block */
        error = DX_SB_CalcHASHOnSWRecDecryptAndCompare(
            flashRead_func, userContext, /* Flash Read function */

            hashOutputSize,                        /* HASH output size */
            pCurrRec,                              /* pointer to Hash and load address */
            pCurrRecAddInfo,                       /* comp additional info */
            &AESKey,                               /* code encryption key for sw component */
            pSwImagesData->isSwComponentEncrypted, /* Indicator if SW image is encrypted */
            pSwImagesData->nonce,                  /* nonce */
            workspace_ptr, workspaceSize);         /* workspace & workspaceSize to load the SW component into */
        if (error != DX_SUCCESS)
            return error;

        /* Point to the next records */
        pCurrRec        = pCurrRec + SIZE_OF_SW_DATA_COMP_PAIR_BYTES / sizeof(uint32_t);
        pCurrRecAddInfo = pCurrRecAddInfo + SIZE_OF_ADD_DATA_PAIR_BYTES / sizeof(uint32_t);
    }

    return DX_SUCCESS;
}
