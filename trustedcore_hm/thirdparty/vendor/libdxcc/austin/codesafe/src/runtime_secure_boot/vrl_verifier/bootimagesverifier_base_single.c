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
#include "secureboot_error.h"
#include "bootimagesverifier_error.h"
#include "crypto_driver_defs.h"
#include "bootimagesverifier_def.h"
#include "bootimagesverifier_parser.h"
#include "secureboot_base_func.h"
#include "nvm.h"
#include "nvm_mng.h"
#include "util.h"
#include "dx_pal_log.h"
#include "secureboot_defs.h"
#include "bootimagesverifier_swcomp.h"
#include "crys_rsa_types.h"
#include "dx_pal_mem.h"
#include "dx_cclib.h"
#include "sbrt_management_api.h"
// #include <stdio.h>

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */
#ifndef DX_SB_USE_RSA_SW
/* SRAM offset */
extern uint32_t g_SramPkaAddr;
#endif

/* *********************** Private functions  **************************** */

/* *********************** Public functions  **************************** */

DxError_t DX_SBRT_CertChainVerificationInit(DxSbCertInfo_t *certPkgInfo)
{
    if (certPkgInfo == DX_NULL)
        return DX_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    /* clear the external hash */
    DX_PAL_MemSet((uint8_t *)&(certPkgInfo->pubKeyHash), 0x0, sizeof(certPkgInfo->pubKeyHash));
    certPkgInfo->initDataFlag = 0;

    return DX_SUCCESS;
}

DxError_t DX_SBRT_CertVerifySingle(DxSbFlashReadFunc flashReadFunc, void *userContext, uint8_t *certPtr,
                                   uint32_t certSize, DxSbCertInfo_t *certPkgInfo, uint32_t *pWorkspace,
                                   uint32_t workspaceSize)
{
    /* error variable */
    DxError_t error = DX_SUCCESS;
    DxSbCertParserSwCompsInfo_t pSwImagesData;
    uint32_t *pSwImagesAddData;
    DxSbCertTypes_t certType;
    uint32_t lcs;

    /* ------------------
        CODE
    ------------------- */
    /* Get current LCS */
    error = DX_SBRT_GetLcs(&lcs);
    if (error != DX_SUCCESS) {
        DX_PAL_LOG_DEBUG("DX_SBRT_GetLcs  returned 0x%X\n", (unsigned int)error);
        return error;
    }

    /* Only Secured LCS allowed for this function */
    if (lcs != DX_SBRT_SECURE_LCS) {
        DX_PAL_LOG_DEBUG("Wrong LCS\n");
        return DX_BOOT_IMG_VERIFIER_ILLEGAL_LCS_FOR_OPERATION_ERR;
    }

    /* Verify input parameters */
    if (flashReadFunc == DX_NULL) {
        DX_PAL_LOG_DEBUG("flashReadFunc is NULL\n");
        return DX_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    if (certPkgInfo == DX_NULL || pWorkspace == DX_NULL || workspaceSize == 0) {
        DX_PAL_LOG_DEBUG("illegal params \n");
        return DX_BOOT_IMG_VERIFIER_INV_INPUT_PARAM;
    }

    /* Load the certificate from the Flash */
    /* ------------------------------------- */
    error = DxCertParserLoadCertificate(certPtr, &certType, certSize);
    if (error != DX_SUCCESS) {
        DX_PAL_LOG_DEBUG("DxCertParserLoadCertificate  returned 0x%X\n", (unsigned int)error);
        return error;
    }

    /* Parse the certificate, get Hash from OTP, and verify the RSA signature */
    /* ------------------------------------------------------------------------ */
    error = DxCertVerifyCertificate((uint32_t *)certPtr, certPkgInfo, &pSwImagesData, &pSwImagesAddData, pWorkspace,
                                    workspaceSize);
    if (error != DX_SUCCESS) {
        DX_PAL_LOG_DEBUG("DxCertVerifyCertificate returned 0x%X\n", (unsigned int)error);
        return error;
    }

    /* 4. in case of content certificate - verify the SW images */
    if (certType == DX_SB_CONTENT_CERT) {
        error = DxCertValidateSWComps(flashReadFunc, userContext, &pSwImagesData, pSwImagesAddData, pWorkspace,
                                      workspaceSize);
        if (error != DX_SUCCESS) {
            DX_PAL_LOG_DEBUG("DX_SB_CertSwCompDecryptAndVerify failed\n");
            return error;
        }
    }

    return error;

} /* End of DX_SB_CertVerifySingle */

#define DX_MNG_SEC_DEBUG_ENABLER_MAGIC   0x5364656E
#define DX_MNG_SEC_DEBUG_DEVELOPER_MAGIC 0x53646465

DxError_t DX_SBRT_GetCertSize(uint32_t *pCert, uint32_t *pCertSizeWords)
{
    /* error variable */
    DxError_t error = DX_SUCCESS;
    DxSbCertTypes_t CertType;

    /* the VRL header data */
    DxSbCertHeader_t *pcertHeader;

    /* certificate size and version */
    uint32_t sizeOfCert = 0;

    /* number of components, vrl size */
    uint32_t numOfComps = 0;

    /* temporary pointer */
    uint32_t *tempPtr = pCert;
/* ------------------
    CODE
------------------- */

/* In case there is additional data - need to skip it */
#ifdef DX_SB_ADDITIONAL_DATA_SUPPORTED
    /* set the temporary address to after the additional data header */
    tempPtr = pCert + DX_SB_MAX_SIZE_OF_ADDITIONAL_DATA / sizeof(uint32_t);
#endif

    /* Point to the VRL header */
    pcertHeader = (DxSbCertHeader_t *)tempPtr;

    if (pcertHeader->magicNumber == DX_CERT_MAGIC_NUMBER_DEFAULT_VALUE) {
        /* verify the certificate header */
        error = DxCertValidateHeader(pcertHeader, &CertType);
        if (error != DX_SUCCESS) {
            return error;
        }

        if (CertType != DX_SB_KEY_CERT && CertType != DX_SB_CONTENT_CERT) {
            DX_PAL_LOG_DEBUG("Certificate type incorrect %d\n", CertType);
            return DX_BOOT_IMG_VERIFIER_INCORRECT_CERT_TYPE;
        }

        /* Calculate the certificate size according to offset to signature + certificate type */
        /* ------------------------------------------------------------------------------------ */
        if (CertType == DX_SB_CONTENT_CERT) {
            /* Get the number of sw comnponents from the header certSize field */
            numOfComps = (pcertHeader->certSize & CERT_LEN_NUM_OF_COMPS_BIT_MASK) >> CERT_LEN_NUM_OF_COMPS_BIT_LOCATION;
            sizeOfCert =
                numOfComps * (SIZE_OF_ADD_DATA_PAIR_BYTES / sizeof(uint32_t)); /* records parameter * num of records */
        }
        sizeOfCert = sizeOfCert +
                     (uint32_t)(pcertHeader->certSize & CERT_LEN_SIGNATURE_OFFSET_BIT_MASK) /* signature offset */
                     + sizeof(DxSbSignature_t) / sizeof(uint32_t);                          /* signature */
    } else if ((pcertHeader->magicNumber == DX_MNG_SEC_DEBUG_ENABLER_MAGIC) ||
               (pcertHeader->magicNumber == DX_MNG_SEC_DEBUG_DEVELOPER_MAGIC)) {
        sizeOfCert = ((uint32_t)(pcertHeader->certSize & CERT_LEN_SIGNATURE_OFFSET_BIT_MASK) /
                      sizeof(uint32_t))                            /* signature offset */
                     + sizeof(DxSbSignature_t) / sizeof(uint32_t); /* signature */
    } else {
        return DX_BOOT_IMG_VERIFIER_CERT_MAGIC_NUM_INCORRECT;
    }

    *pCertSizeWords = sizeOfCert;

    return DX_SUCCESS;

} /* End of DX_SB_GetCertSize */
