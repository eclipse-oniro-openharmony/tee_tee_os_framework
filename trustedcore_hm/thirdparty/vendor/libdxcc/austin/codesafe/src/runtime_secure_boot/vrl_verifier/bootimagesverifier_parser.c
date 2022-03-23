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

#include "secureboot_error.h"
#include "dx_pal_types.h"
#include "secureboot_defs.h"
#include "rsa.h"
#include "bootimagesverifier_def.h"
#include "bootimagesverifier_error.h"
#include "util.h"
#include "nvm.h"
#include "bootimagesverifier_parser.h"
#include "crypto_driver_defs.h"
#include "crypto_driver.h"
#include "dx_pal_log.h"
#include "secureboot_base_func.h"
#include "dx_pal_mem.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Internal Functions **************************** */

/* *********************** Public Functions **************************** */

DxError_t DxCertValidateHeader(DxSbCertHeader_t *pCertHeader, DxSbCertTypes_t *pCertType)
{
    uint32_t certVersion;

    /* Verify Magic number */
    /* --------------------- */
    if (pCertHeader->magicNumber != DX_CERT_MAGIC_NUMBER_DEFAULT_VALUE) {
        DX_PAL_LOG_DEBUG("magicNumber 0x%X != default magicNumber\n", pCertHeader->magicNumber);
        return DX_BOOT_IMG_VERIFIER_CERT_MAGIC_NUM_INCORRECT;
    }

    /* Verify certificate version */
    /* ---------------------------- */

    certVersion = (DX_SB_CERT_VERSION_MAJOR << CERT_VERSION_MAJOR_BIT_SHIFT) | DX_SB_CERT_VERSION_MINOR;
    if (pCertHeader->certVersion != certVersion) {
        DX_PAL_LOG_DEBUG("Certificate version incorrect\n");
        return DX_BOOT_IMG_VERIFIER_CERT_VERSION_NUM_INCORRECT;
    }

    /* get the cert type */
    /* ------------------- */
    *pCertType = (pCertHeader->certFlags >> CERT_FLAG_TYPE_BIT_LOCATION) & CERT_FLAG_TYPE_BIT_MASK;

    return DX_SUCCESS;
}

DxError_t DxCertParserLoadCertificate(uint8_t *certPtr, DxSbCertTypes_t *pCertType, uint32_t certBufferSize)
{
    /* error variable */
    DxError_t error = DX_SUCCESS;

    /* temp header */
    DxSbCertHeader_t *certHeader;

    /* certificate size and version */
    uint32_t sizeOfCert = 0;

    /* number of sw components signed on in the certificate */
    uint16_t numOfComps = 0;

    uint8_t *certData = certPtr;

    /* ------------------
        CODE
    ------------------- */
#ifdef DX_SB_ADDITIONAL_DATA_SUPPORTED
    certData = certData + DX_SB_MAX_SIZE_OF_ADDITIONAL_DATA;
#endif

    /* Get pointer to certificate header */
    certHeader = (DxSbCertHeader_t *)certData;

    /* verify the certificate header */
    error = DxCertValidateHeader(certHeader, pCertType);
    if (error != DX_SUCCESS) {
        return error;
    }

    if (*pCertType != DX_SB_KEY_CERT && *pCertType != DX_SB_CONTENT_CERT) {
        DX_PAL_LOG_DEBUG("Certificate type incorrect %d\n", *pCertType);
        return DX_BOOT_IMG_VERIFIER_INCORRECT_CERT_TYPE;
    }
    /* Calculate the certificate size according to offset to signature + certificate type */
    /* ------------------------------------------------------------------------------------ */
    if (*pCertType == DX_SB_CONTENT_CERT) {
        /* Get the number of sw comnponents from the header certSize field */
        numOfComps = (certHeader->certSize & CERT_LEN_NUM_OF_COMPS_BIT_MASK) >> CERT_LEN_NUM_OF_COMPS_BIT_LOCATION;
        sizeOfCert =
            numOfComps * (SIZE_OF_ADD_DATA_PAIR_BYTES / sizeof(uint32_t)); /* records parameter * num of records */
    }
    sizeOfCert = sizeOfCert +
                 (uint32_t)(certHeader->certSize & CERT_LEN_SIGNATURE_OFFSET_BIT_MASK) /* signature offset */
                 + sizeof(DxSbSignature_t) / sizeof(uint32_t);                         /* signature */

    /* ---------------------- */
    /* Verify certificate size */
    if (certBufferSize != sizeOfCert * sizeof(uint32_t)) {
        DX_PAL_LOG_DEBUG("certificate buff size too small\n");
        return DX_BOOT_IMG_VERIFIER_WORKSPACE_SIZE_TOO_SMALL;
    }

    return DX_SUCCESS;

} /* End of DxCertParserLoadCertificate */

DxError_t DxCertVerifyCertificate(uint32_t *pCert, DxSbCertInfo_t *certPkgInfo,
                                  DxSbCertParserSwCompsInfo_t *pSwImagesData, uint32_t **pSwImagesAddData,
                                  uint32_t *workspace_ptr, uint32_t workspaceSize)
{
    /* error variable */
    DxError_t error = DX_SUCCESS;

    /* RSA data */
    DxSbCertParserRSAData_t rsaData;

    /* sw version struct */
    DxSbSwVersion_t *pSwVersion = DX_NULL;

    /* HBK id */
    DxSbPubKeyIndexType_t hbkId;

    /* hash size */
    uint32_t hashSize = 0;

    /* temp hash */
    HASH_Result_t savedHash;

    /* otp sw version */
    uint32_t otpVersion = 0;

    /* ------------------
        CODE
    ------------------- */

    /* save the previous hash (it will be overwritten in the parser ) */
    if (certPkgInfo->initDataFlag != 0) {
        DX_PAL_MemCopy((uint8_t *)savedHash, (uint8_t *)certPkgInfo->pubKeyHash, sizeof(HASH_Result_t));
    }

    /* Parse the certificate, get pointers to its different sections */
    /* --------------------------------------------------------------- */
    error = DxCertInternalCertParse(pCert, &rsaData, &pSwVersion, certPkgInfo->pubKeyHash, pSwImagesData,
                                    pSwImagesAddData, &hbkId);
    if (error != DX_SUCCESS) {
        DX_PAL_LOG_DEBUG("DxCertInternalCertParse failed\n");
        return error;
    }

    /* 1. Verify that the SW version is valid */
    /* -------------------------------------- */
    error =
        DX_SB_VerifyNvCounter(pSwVersion, certPkgInfo->initDataFlag, certPkgInfo->activeMinSwVersionId, &otpVersion);
    if (error != DX_SUCCESS) {
        DX_PAL_LOG_DEBUG("DX_SB_VerifyNvCounter failed\n");
        return error;
    }

    hashSize = sizeof(HASH_Result_t) / sizeof(uint32_t);

    /* 2. Compute HASH over the public key and exponent from the certificate and compare to given HASH */
    /* ------------------------------------------------------------------------------------------------- */
    /* if not initialize than this is the first certificate in the chain and should be verified versus
       the OTP */
    if (certPkgInfo->initDataFlag == 0) {
        if (hbkId == DX_SB_HASH_BOOT_KEY_0_128B || hbkId == DX_SB_HASH_BOOT_KEY_1_128B) {
            hashSize = hashSize / 2;
        }
        /* Get the public key HASH from the OTP/NVM */
        error = NVM_ReadHASHPubKey(hbkId, savedHash, hashSize);
        if (error != DX_SUCCESS) {
            DX_PAL_LOG_DEBUG("NVM_ReadHASHPubKey returned 0x%X\n", (unsigned int)error);
            return error;
        }
    }
    /* Verify calculated hash only in case of secured LCS (hash key is programmed) */
    /* The RSA struct is ordered to first point to N and than to Np (to calculate the HASH need N & Np) */
    error = DX_SB_CalcPublicKeyHASHAndCompare(rsaData.N_ptr, savedHash, hashSize * sizeof(uint32_t));
    if (error != DX_SUCCESS) {
        DX_PAL_LOG_DEBUG("Primary DX_SB_CalcPublicKeyHASHAndCompare failed\n");
        return error;
    }

    /* 3. Verify RSA signature */
    /* ------------------------- */
    /* Verify the certificate signature */
    error = DX_SB_VerifySignature(pCert, (DxSbNParams_t *)rsaData.N_ptr, (DxSbSignature_t *)rsaData.signature,
                                  rsaData.certSizeInWordsForHash * sizeof(uint32_t), rsaData.rsaAlg, workspace_ptr,
                                  workspaceSize);
    if (error != DX_SUCCESS) {
        DX_PAL_LOG_DEBUG("DX_SB_VerifySignature failed\n");
        return error;
    }

    /* 4. Set the sw version in the OTP (if required)  */
    /* ------------------------------------------------- */
    error = DX_SB_SetNvCounter(pSwVersion, otpVersion);
    if (error != DX_SUCCESS) {
        DX_PAL_LOG_DEBUG("DX_SB_SetNvCounter failed\n");
        return error;
    }

    certPkgInfo->initDataFlag         = 1;
    certPkgInfo->activeMinSwVersionId = pSwVersion->id;
    return DX_SUCCESS;

} /* End of DxCertVerifyCertificate */

DxError_t DxCertInternalCertParse(uint32_t *pCert, DxSbCertParserRSAData_t *pRsaData, DxSbSwVersion_t **pSwVersion,
                                  HASH_Result_t pNextPubKeyHash, DxSbCertParserSwCompsInfo_t *pSwImagesData,
                                  uint32_t **pSwImagesAddData, DxSbPubKeyIndexType_t *pHbkId)
{
    /* the certificate header data */
    DxSbCertHeader_t *certHeader;

    /* offset from certificate start */
    uint32_t offset = 0;

    /* temporary pointer */
    uint32_t *tempPtr = pCert;

    uint8_t certType = 0;
    /* ------------------
        CODE
    ------------------- */

#ifdef DX_SB_ADDITIONAL_DATA_SUPPORTED
    certHeader = (DxSbCertHeader_t *)(tempPtr + DX_SB_MAX_SIZE_OF_ADDITIONAL_DATA / sizeof(uint32_t));
    offset     = DX_SB_MAX_SIZE_OF_ADDITIONAL_DATA / sizeof(uint32_t);
#else
    /* Point to the certificate header */
    certHeader = (DxSbCertHeader_t *)tempPtr;
#endif

    /* Parse the certificate */
    /* ----------------------- */
    certType = (certHeader->certFlags >> CERT_FLAG_TYPE_BIT_LOCATION) & CERT_FLAG_TYPE_BIT_MASK;
    *pHbkId  = certHeader->certFlags & CERT_FLAG_HBK_BIT_MASK;
    /* verify that the hbk is legal */
    if (*pHbkId > DX_SB_HASH_BOOT_KEY_256B && *pHbkId != DX_SB_HASH_BOOT_NOT_USED) {
        return DX_BOOT_IMG_VERIFIER_ILLEGAL_HBK_IDX;
    }
    if (certType == DX_SB_CONTENT_CERT) {
        pSwImagesData->isSwComponentEncrypted = (certHeader->certFlags >> CERT_FLAG_ENCRYPTION_USED_BIT_LOCATION) & 0x1;
        pSwImagesData->numOfSwComps =
            (certHeader->certSize & CERT_LEN_NUM_OF_COMPS_BIT_MASK) >> CERT_LEN_NUM_OF_COMPS_BIT_LOCATION;
    }

    /* 2. Get RSA parameters (N and Np) */
    /* Point to N, located in the certificate after the header */
    offset          = offset + sizeof(DxSbCertHeader_t) / sizeof(uint32_t);
    pRsaData->N_ptr = tempPtr + offset;

    /* Point to Np */
    offset             = offset + SB_RSA_MOD_SIZE_IN_WORDS;
    pRsaData->NDer_ptr = tempPtr + offset;

    /* Get the RSA algorithm */
    pRsaData->rsaAlg =
        (DxSbRsaAlg_t)(certHeader->certFlags & CERT_FLAG_RSA_ALG_BIT_MASK) >> CERT_FLAG_RSA_ALG_BIT_LOCATION;

    /* 3. Get the sw revocation parameters */
    offset      = offset + RSA_HW_PKI_PKA_BARRETT_MOD_TAG_SIZE_IN_WORDS;
    *pSwVersion = (DxSbSwVersion_t *)(tempPtr + offset);

    offset = offset + sizeof(DxSbSwVersion_t) / sizeof(uint32_t);

    /* in case its a key certificate copy the next hash */
    if (certType == DX_SB_KEY_CERT) {
        DX_PAL_MemCopy((uint8_t *)pNextPubKeyHash, (uint8_t *)(tempPtr + offset), sizeof(HASH_Result_t));
    } else {
        /* point to the nonce */
        DX_PAL_MemCopy((uint8_t *)pSwImagesData->nonce, (uint8_t *)(tempPtr + offset), sizeof(DxSbNonce_t));
        offset = offset + sizeof(DxSbNonce_t) / sizeof(uint32_t);
        /* point to the sw images data */
        pSwImagesData->pSwCompsData = tempPtr + offset;
    }

    /* Point to RSA signature , set the certificate size for HASH (offset to signature) */
    offset                           = certHeader->certSize & CERT_LEN_SIGNATURE_OFFSET_BIT_MASK;
    pRsaData->signature              = tempPtr + offset;
    pRsaData->certSizeInWordsForHash = offset;

    if (certType == DX_SB_CONTENT_CERT) {
        /* The offset is set to after the signature - only relevant for content certificate */
        offset = offset + sizeof(DxSbSignature_t) / sizeof(uint32_t); /* signature */
        /* point to the sw images add data */
        *pSwImagesAddData = tempPtr + offset;
    }

    return DX_SUCCESS;

} /* End of DxCertInternalCertParse */

/* ************************************************************************************************* */
