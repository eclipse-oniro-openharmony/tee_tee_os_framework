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

#ifndef _BOOT_IMAGES_VERIFIER_PARSER_H
#define _BOOT_IMAGES_VERIFIER_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "secureboot_defs.h"

/* Definitions used by the functions */
/* ----------------------------------- */

/* Definitions for certificate size in the certificate header */
/* mask to location of Offset to signature bits in the header cert size parameter */
#define CERT_LEN_SIGNATURE_OFFSET_BIT_MASK 0x0000FFFFUL

/* mask to Num of components bits in the header certificate size parameter */
#define CERT_LEN_NUM_OF_COMPS_BIT_MASK 0xFFFF0000UL

/* Bit location of the num of copmponents in the header certificate size parameter */
#define CERT_LEN_NUM_OF_COMPS_BIT_LOCATION 16

/* Definitions for certificate flags in the header */
/* SW revocation support bit location in the flag */
#define CERT_FLAG_TYPE_BIT_LOCATION 17

#define CERT_FLAG_TYPE_BIT_MASK 0x3

/* HASH algorithm mask in the header flag */
#define CERT_FLAG_RSA_ALG_BIT_MASK 0x0000FF00UL

/* HASH algorithm mask in the header flag bit location */
#define CERT_FLAG_RSA_ALG_BIT_LOCATION 8

/* HASH algorithm mask in the header flag */
#define CERT_FLAG_HBK_BIT_MASK 0x000000FFUL

/* HASH algorithm mask in the header flag bit location */
#define CERT_FLAG_HBK_BIT_LOCATION 0

/* SW revocation support bit location in the flag */
#define CERT_FLAG_ENCRYPTION_USED_BIT_LOCATION 16

/* certificate version Major offset */
#define CERT_VERSION_MAJOR_BIT_SHIFT 16

/* Structures used inside the parser code */
/* ---------------------------------------- */

/* Data on s/w components */
typedef struct {
    /* Num of s/w comps */
    uint32_t numOfSwComps;

    /* Indicator if SW image is encrypted */
    uint8_t isSwComponentEncrypted;

    /* nonce */
    DxSbNonce_t nonce;

    /* pointer to start of sw comps data */
    uint32_t *pSwCompsData;

} DxSbCertParserSwCompsInfo_t;

/* RSA data (united to one structure) */
typedef struct {
    /* Pointer to N */
    uint32_t *N_ptr;

    /* Pointer to Np OR H according to algorithm used */
    uint32_t *NDer_ptr;

    /* Pointer to RSA signature */
    uint32_t *signature;

    /* RSA algorithm */
    DxSbRsaAlg_t rsaAlg;

    /* Size of cert for HASH computation (offset to signature) */
    uint32_t certSizeInWordsForHash;

} DxSbCertParserRSAData_t;

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

/*
 * @brief This function is resposible to verify the certificate header
 *
 *
 * @param[in] pCertHeader - the certificate header
 * @param[out] pCertType - return the certificate type
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from BootImagesVerifier_error.h
 */
DxError_t DxCertValidateHeader(DxSbCertHeader_t *pCertHeader, DxSbCertTypes_t *pCertType);

/*
 * @brief This function is resposible for loading the certificate from the flash.
 *        The function will read the certificate header from the flash (using the Flash_read function),
 *        get its size and load the entire certificate accordingly.
 *
 *

 * @param[in] certPtr - pointer to certificate
 * @param[in] pCertType - return the certificate type
  @param[in] certBufferSize - certificate size
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from BootImagesVerifier_error.h
 */
DxError_t DxCertParserLoadCertificate(uint8_t *certPtr, DxSbCertTypes_t *pCertType, uint32_t certBufferSize);

/*
 * @brief This function is responsible to parsing the certificate. The function gets a certificate
 *        pointer parse it and do the following verifications:
 *        1. Verify the public key hash (with the one saved in the OTP/NVM and sent to the function)
 *        2. Verify the SW minimum version
 *        3. Verify RSA signature
 *        4. If all verification passed the function return a pointer to the components HASH section
 *           in the certificate and a pointer to the SW components addtitional data section in the certificate.
 *
 *
 * @param[in] pCert - the certificate loaded to RAM
 * @param[in] certPkgInfo - containing the internal falgs for the chain verification
 * @param[out] pSwImagesData - will contain a pointer to the sw images data in the certificate (if content certificate)
 * @param[out] pSwImagesAddData - will contain a pointer to the sw images additional data in the certificate (if content
 * certificate)
 * @param[in]workspace_ptr - pointer to workspace buffer
 * @param[in]workspaceSize - size of workspace buffer
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from BootImagesVerifier_error.h
 */
DxError_t DxCertVerifyCertificate(uint32_t *pCert, DxSbCertInfo_t *certPkgInfo,
                                  DxSbCertParserSwCompsInfo_t *pSwImagesData, uint32_t **pSwImagesAddData,
                                  uint32_t *workspace_ptr, uint32_t workspaceSize);

/*
 * @brief This function parses the certificate and returns pointers to its different components
 *
 * @param[in] pCert - pointer to the certificate
 * @param[out] pRsaData - a pointer to the rsa data in the certificate
 * @param[out] pSwVersion - a pointer to the sw version in the certificate
 * @param[out] pNextPubKeyHash - a pointer to saved hash of pub key (if exist)
 * @param[out] pSwImagesData - a pointer to the sw images data in the certificate
 * @param[out] pSwImagesAddData - a pointer to the sw images additional data in the certificate
 * @param[out] pHbkId - will contain the hbk id from the certificate flags
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from BootImagesVerifier_error.h
 */
DxError_t DxCertInternalCertParse(uint32_t *pCert, DxSbCertParserRSAData_t *pRsaData, DxSbSwVersion_t **pSwVersion,
                                  HASH_Result_t pNextPubKeyHash, DxSbCertParserSwCompsInfo_t *pSwImagesData,
                                  uint32_t **pSwImagesAddData, DxSbPubKeyIndexType_t *pHbkId);

#ifdef __cplusplus
}
#endif

#endif
