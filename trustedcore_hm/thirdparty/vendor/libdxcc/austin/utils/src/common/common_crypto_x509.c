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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#include "common_crypto_x509.h"
#include "common_crypto_asym.h"
#include "common_rsa_keypair.h"
#include "common_util_log.h"
#include "dx_crypto_boot_defs.h"

#define X509_VER_3       2 /* version 3 certificate */
#define ENDLESS_VALIDITY 0xFFFFFFFE
#define CERT_ISSUER_NAME "DISCRETIX"
#define MAX_OBJ_ID_LEN   10
#define MAX_EXT_VAL_LEN  200
#define MAX_EXT_VAL_LIST 36 // sha256 + 4 bytes
#define CHAR_STR_LEN     6

#define OPEN_SSL_ERROR             0
#define IS_VALID_ENC_FLAG(encFlag) (((encFlag) == 0) || ((encFlag) == 1) || (0xFF == (encFlag)))
#define IS_VALID_HBK(hbkType)                                                                  \
    (((hbkType) == DX_SB_HASH_BOOT_KEY_0_128B) || ((hbkType) == DX_SB_HASH_BOOT_KEY_1_128B) || \
     ((hbkType) == DX_SB_HASH_BOOT_KEY_256B) || ((hbkType) == DX_SB_HASH_BOOT_NOT_USED))

const uint8_t *certType2Str[DX_X509_CERT_TYPE_MAX] = {
    NULL,
    /* DX_X509_CERT_TYPE_KEY      */ (uint8_t *)DX_X509_CERT_KEY_CERT,
    /* DX_X509_CERT_TYPE_CONTENT  */ (uint8_t *)DX_X509_CERT_CNT_CERT,
    /* DX_X509_CERT_TYPE_PRIM_DBG */ (uint8_t *)DX_X509_CERT_DBG1_CERT,
    /* DX_X509_CERT_TYPE_SCND_DBG */ (uint8_t *)DX_X509_CERT_DBG2_CERT
};

/*
 * @brief free X509 certificate
 *
 * @param[in/out] ppCertBuff          - x.509 certificate
 */
/* ****************************************************** */
int32_t DX_Common_x509_free(uint8_t **ppCertBuff)
{
    /* validate inputs */
    if ((ppCertBuff == NULL) || (*ppCertBuff == NULL)) {
        UTIL_LOG_ERR("ilegal input\n");
        return 0;
    }

    UTIL_LOG_INFO("about to X509_free\n");
    /* create the certificate buffer */
    X509_free((X509 *)*ppCertBuff);
    *ppCertBuff = NULL;
    return 0;
}

/*
 * @brief Creates X509 certificate and set its header fields
 *
 * @param[in/out] ppCertBuff     - x.509 certificate
 * @param[in] certType           - certificate type
 */
/* ****************************************************** */
int32_t DX_Common_x509_CreateAndSetHeader(uint8_t **ppCertBuff, DxX509CertType_t certType)
{
    int32_t rc         = 0;
    long endDate       = 0;
    uint32_t serialNum = 0;
    X509 *plCert       = NULL;
    ASN1_TIME *pDummy  = NULL;

    /* validate inputs */
    if ((ppCertBuff == NULL) || (certType >= DX_X509_CERT_TYPE_MAX)) {
        UTIL_LOG_ERR("ilegal input\n");
        return (-1);
    }

    /* create the certificate buffer */
    plCert = (X509 *)X509_new();
    if (plCert == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to X509_new\n");
        return 1;
    }

    /* set certificate version to V3 */
    rc = X509_set_version(plCert, X509_VER_3);
    if (rc == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to X509_set_version\n");
        rc = 1;
        goto END;
    }
    /* set certificate serial number */
    rc = DX_Common_RAND_Bytes(4, (char *)&serialNum);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to set DX_Common_RAND_Bytes\n");
        rc = 1;
        goto END;
    }

    rc = ASN1_INTEGER_set(X509_get_serialNumber(plCert), serialNum);
    if (rc == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to set X509_get_serialNumber\n");
        rc = 1;
        goto END;
    }
    /* set ecrtificate start time to current time, and end date according to input */
    pDummy = X509_gmtime_adj(X509_get_notBefore(plCert), (long)0 /* X509_CURRENT_TIME */);
    if (pDummy == NULL) {
        UTIL_LOG_ERR("failed set X509_get_notBefore\n");
        rc = 1;
        goto END;
    }
    pDummy = X509_gmtime_adj(X509_get_notAfter(plCert), (long)ENDLESS_VALIDITY);
    if (pDummy == NULL) {
        UTIL_LOG_ERR("failed set X509_get_notAfter\n");
        rc = 1;
        goto END;
    }

    /* set subject name */
    rc = X509_NAME_add_entry_by_txt(X509_get_subject_name(plCert), "CN", /* common name */
                                    MBSTRING_ASC, certType2Str[certType], -1, -1, 0);
    if (rc == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to set X509_get_subject_name\n");
        rc = 1;
        goto END;
    }

    /* set issuer name */
    rc = X509_NAME_add_entry_by_txt(X509_get_issuer_name(plCert), "CN", MBSTRING_ASC, CERT_ISSUER_NAME, -1, -1, 0);
    if (rc == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to set X509_get_issuer_name\n");
        rc = 1;
        goto END;
    }

    *ppCertBuff = (uint8_t *)plCert;
    rc          = 0;
    UTIL_LOG_INFO("OK\n");

END:
    if (rc != 0) {
        if (plCert != NULL) {
            X509_free(plCert);
        }
        *ppCertBuff = NULL;
    }
    return rc;
}

/*
 * @brief Add ASN.1 critical integer extension to X.509V3 certificate
 *
 * @param[in/out] pCertBuff          - x.509 certificate
 * @param[in] certType                 - certificate type
 * @param[in] extType                 - extension type
 * @param[in] val                 - Extension value
 */
/* ****************************************************** */
int32_t DX_Common_x509_AddIntegerExtension(uint8_t *pCertBuff, DxX509CertType_t certType, DxX509ExtType_t extType,
                                           int32_t val)

{
    int32_t rc          = 0;
    int32_t nid         = 0;
    X509 *plCert        = (X509 *)pCertBuff;
    X509_EXTENSION *ext = NULL;
    uint8_t objId[MAX_OBJ_ID_LEN];
    uint8_t extValue[MAX_EXT_VAL_LEN];
    int32_t writtenBytes = 0;

    /* validate inputs */
    if (pCertBuff == NULL) {
        UTIL_LOG_ERR("Illegal parameters \n");
        return (-1);
    }

    /* create new object */
    snprintf(objId, MAX_OBJ_ID_LEN, "2.20.%d.%d", certType, extType);
    nid = OBJ_create(objId, "MyAlias", "My Test Alias Extension");
    if (nid == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to OBJ_create\n");
        ERR_print_errors_fp(stderr);
        rc = 1;
        goto END;
    }
    rc = X509V3_EXT_add_alias(nid, NID_netscape_comment);
    if (nid == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to X509V3_EXT_add_alias\n");
        ERR_print_errors_fp(stderr);
        rc = 1;
        goto END;
    }
    /* create the extension value */
    writtenBytes = snprintf(extValue, MAX_EXT_VAL_LEN, "critical,ASN1:INTEGER:0x%X", val);
    /* build the extension */
    ext = X509V3_EXT_conf_nid(NULL, NULL, nid, extValue);
    if (ext == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to X509V3_EXT_conf_nid\n");
        ERR_print_errors_fp(stderr);
        rc = 1;
        goto END;
    }

    /* Add the extension to the certificate */
    rc = X509_add_ext(plCert, ext, -1);
    if (rc == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to X509_add_ext\n");
        ERR_print_errors_fp(stderr);
        rc = 1;
        goto END;
    }
    rc = 0;
    UTIL_LOG_INFO("OK\n");

END:
    X509_EXTENSION_free(ext);
    return rc;
}

/*
 * @brief Add critical DER extension to X.509V3 certificate
 *
 * @param[in/out] pCertBuff          - x.509 certificate
 * @param[in] certType                 - certificate tyoes
 * @param[in] extType                 - extension type
 * @param[in] pVal                 - Extension data
 * @param[in] valLen                 - extension data length
 */
/* ****************************************************** */
int32_t DX_Common_x509_AddStringExtension(uint8_t *pCertBuff, DxX509CertType_t certType, DxX509ExtType_t extType,
                                          uint8_t *pVal, uint32_t valLen)

{
    int32_t rc = 0;
    int32_t nid;
    X509 *plCert        = (X509 *)pCertBuff;
    X509_EXTENSION *ext = NULL;
    uint8_t objId[MAX_OBJ_ID_LEN];
    uint8_t extValue[MAX_EXT_VAL_LEN];
    int32_t writtenBytes = 0;
    int32_t pValIdx      = 0;

    /* validate inputs */
    if ((pCertBuff == NULL) || (pVal == NULL) || (valLen > MAX_EXT_VAL_LIST)) {
        UTIL_LOG_ERR("Illegal parameters \n");
        return (-1);
    }
    /* create new object */
    snprintf(objId, MAX_OBJ_ID_LEN, "2.20.%d.%d", certType, extType);
    nid = OBJ_create(objId, "MyAlias", "My Test Alias Extension");
    if (nid == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to OBJ_create\n");
        ERR_print_errors_fp(stderr);
        rc = 1;
        goto END;
    }

    pValIdx      = 0;
    writtenBytes = snprintf(extValue, MAX_EXT_VAL_LEN, "critical,DER: %02X", pVal[pValIdx++]);
    UTIL_LOG_INFO("writtenBytes %d, extValue %s\n", writtenBytes, extValue);
    while (pValIdx < valLen) {
        writtenBytes += snprintf((extValue + writtenBytes), CHAR_STR_LEN, ":%02X", pVal[pValIdx++]);
        UTIL_LOG_INFO("writtenBytes %d, extValue %s\n", writtenBytes, extValue);
    }

    rc = X509V3_EXT_add_alias(
        nid, NID_netscape_comment); // if NID is unknown openssl ignores it. meaning it is not added to cert.
    if (rc == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to X509V3_EXT_add_alias\n");
        ERR_print_errors_fp(stderr);
        rc = 1;
        goto END;
    }

    ext = X509V3_EXT_conf_nid(NULL, NULL, nid, extValue);
    if (ext == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to X509V3_EXT_conf_nid\n");
        ERR_print_errors_fp(stderr);
        rc = 1;
        goto END;
    }

    /* Add the extension to the certificate */
    rc = X509_add_ext(plCert, ext, -1);
    if (rc == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to X509_add_ext\n");
        ERR_print_errors_fp(stderr);
        rc = 1;
        goto END;
    }
    rc = 0;
    UTIL_LOG_INFO("OK\n");

END:
    X509_EXTENSION_free(ext);
    return rc;
}

/*
 * @brief Add subject public key to the X509 certificate
 *     and sign the certificate
 *
 * @param[in/out] pCertBuff      - x.509 certificate
 * @param[in] pKeyPairFileName   - key pair file name in PEM format
 * @param[in] pKeyPairPwd       - passphrase of key pair
 */
/* ****************************************************** */
int32_t DX_Common_x509_SetKeyAndSign(uint8_t *pCertBuff, uint8_t *pKeyPairFileName, uint8_t *pKeyPairPwd)
{
    int32_t rc       = 0;
    X509 *plCert     = (X509 *)pCertBuff;
    RSA *pRsaKeyPair = NULL;
    uint8_t *pwd     = NULL;
    EVP_PKEY *pKey   = NULL;

    /* validate inputs */
    if ((pCertBuff == NULL) || (pKeyPairFileName == NULL)) {
        UTIL_LOG_ERR("ilegal input\n");
        return (-1);
    }

    /* get certificate Subject's RSA public and private key from key pair file */
    /* parse the passphrase for a given file */
    if (pKeyPairPwd != NULL) {
        rc = DX_Common_GetPassphrase(pKeyPairPwd, &pwd);
        if (rc != DX_COMMON_OK) {
            UTIL_LOG_ERR("Failed to retrieve pwd\n");
            goto END;
        }
    }
    pRsaKeyPair = RSA_new();
    if (pRsaKeyPair == NULL) {
        UTIL_LOG_ERR("Failed RSA_new\n");
        goto END;
    }
    rc = DX_Common_GetKeyPair(&pRsaKeyPair, pKeyPairFileName, pwd);
    if (rc != DX_COMMON_OK) {
        UTIL_LOG_ERR("DX_Common_GetKeyPair Cannot read RSA private key\n");
        rc = 1;
        goto END;
    }
    /* allocate an empty EVP_PKEY structure which
    is used by OpenSSL to store private keys. */
    pKey = EVP_PKEY_new();
    if (pKey == NULL) {
        UTIL_LOG_ERR("failed to EVP_PKEY_new\n");
        rc = 1;
        goto END;
    }
    /* set the referenced key to RSA key */
    rc = EVP_PKEY_assign_RSA(pKey, pRsaKeyPair);
    if (rc == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to EVP_PKEY_assign_RSA\n");
        rc = 1;
        goto END;
    }

    UTIL_LOG_INFO("about to X509_set_pubkey\n");
    /* set the key into certificate */
    rc = X509_set_pubkey(plCert, pKey);
    if (rc == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to X509_set_pubkey\n");
        ERR_print_errors_fp(stderr);
        rc = 1;
        goto END;
    }

    UTIL_LOG_INFO("about to X509_sign\n");
    /* sign the ecrtificate and add signature and signature identifier to certificate */
    rc = X509_sign(plCert, pKey, EVP_sha256());
    if (rc == OPEN_SSL_ERROR) {
        UTIL_LOG_ERR("failed to X509_sign\n");
        rc = 1;
        goto END;
    }
    rc = 0;
    UTIL_LOG_INFO("OK\n");

END:
    if (pRsaKeyPair != NULL) {
        RSA_free(pRsaKeyPair);
    }
    if (pwd != NULL) {
        free(pwd);
    }
    return rc;
}

/*
 * @brief Add subject public key to the X509 certificate
 *     sign the certificate
 *
 * @param[in/out] ppCertBuff      - x.509 certificate
 * @param[in] certType           - certificate type
 * @param[in] pKeyPairFileName   - key pair file name in PEM format
 * @param[in] pKeyPairPwd       - passphrase of key pair
 * @param[out] pOutCertSize     - certificate size in PEM format
 */
/* ****************************************************** */
int32_t DX_Common_x509_ResignAndPem(uint8_t **ppCertBuff, DxX509CertType_t certType, uint8_t *pKeyPairFileName,
                                    uint8_t *pKeyPairPwd, uint32_t *pOutCertSize)
{
    int32_t rc           = 0;
    X509 *plCert         = NULL;
    uint8_t *certDecBuff = NULL;
    uint32_t certDecSize = 0;
    BIO *mbio;
    int32_t bioCertSize = 0;
    uint8_t i           = 0;
    uint8_t *pTmpCertData;
    uint8_t *pPemCertData         = NULL;
    uint32_t certDinOffset        = 0;
    uint32_t certTmpOffset        = 0;
    uint32_t certSignSizeNumBytes = 0;
    uint32_t certSignSize         = 0;
    uint32_t certStartSignOffset  = 0;
#ifdef UTIL_DEBUG
    uint8_t *certFileName[DX_X509_CERT_TYPE_MAX] = { NULL,
                                                     /* DX_X509_CERT_TYPE_KEY      */ "key_cert.pem",
                                                     /* DX_X509_CERT_TYPE_CONTENT  */ "content_cert.pem",
                                                     /* DX_X509_CERT_TYPE_PRIM_DBG */ "prim_dbg_cert.pem",
                                                     /* DX_X509_CERT_TYPE_SCND_DBG */ "scnd_dbg_cert.pem" };
#endif

    /* validate inputs */
    if ((ppCertBuff == NULL) || (pKeyPairFileName == NULL) ||
        ((certType <= DX_X509_CERT_TYPE_MIN) || (certType >= DX_X509_CERT_TYPE_MAX)) || (pOutCertSize == NULL)) {
        UTIL_LOG_ERR("ilegal input\n");
        return (-1);
    }

    plCert = (X509 *)*ppCertBuff;
    /*  set outputs */
    *pOutCertSize = 0;

    /* convert x509 certificate to PEM format */
    UTIL_LOG_INFO("using BIO to perform PEM encoding\n");
    mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio, plCert);
    BIO_flush(mbio);

    bioCertSize = BIO_pending(mbio);
    UTIL_LOG_INFO("bioCertSize %d\n", bioCertSize);
    BIO_get_mem_data(mbio, (uint8_t *)&pTmpCertData);
    certDecSize = ((bioCertSize + 3) * 3) / 4;
    certDecBuff = malloc(certDecSize);
    if (certDecBuff == NULL) {
        UTIL_LOG_ERR("failed to malloc certDecBuff\n");
        rc = 1;
        goto END;
    }

    rc = DX_Common_PEM_Decode(pTmpCertData, bioCertSize, certDecBuff, &certDecSize);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to DX_Common_PEM_Decode\n");
        goto END;
    }
    BIO_free_all(mbio);

    // UTIL_LOG_BYTE_BUFF("certDecBuff", certDecBuff, certDecSize);

    /* find certificate data in start offset for performing signature */
    /* first make sure certificate starts with ASN.1 SEQUENCE tag */
    certTmpOffset = 0;
    if (certDecBuff[certTmpOffset] != 0x30) {
        UTIL_LOG_ERR("failed to DX_Common_PEM_Decode\n");
        goto END;
    }
    certTmpOffset++;
    certDinOffset = 2;
    if (certDecBuff[certTmpOffset] & 0x80) {
        certDinOffset += (certDecBuff[certTmpOffset] & 0x03);
    }
    /* find certificate data size for performing signature */
    certTmpOffset        = certDinOffset + 1;
    certSignSizeNumBytes = 0;
    certSignSize         = 0;
    if (certDecBuff[certTmpOffset] & 0x80) {
        certSignSizeNumBytes = certDecBuff[certTmpOffset] & 0x03;
        i                    = certSignSizeNumBytes;
        while (i--) {
            certSignSize = (certSignSize << 8) | (certDecBuff[++certTmpOffset]);
        }
    } else {
        certSignSize = certDecBuff[certTmpOffset];
    }
    certSignSize += (certSignSizeNumBytes + 2);

    /* find certificate signature offset for performing signature out buffer */
    certStartSignOffset = certDecSize - RSA_MOD_SIZE_IN_BYTES;

    UTIL_LOG_INFO("about to DX_Common_RSA_Sign, certDinOffset %d, certSignSize 0x%x, certStartSignOffset %d\n",
                  certDinOffset, certSignSize, certStartSignOffset);
    rc = DX_Common_RSA_Sign(RSA_USE_PKCS_21_VERSION, &certDecBuff[certDinOffset], certSignSize, pKeyPairFileName,
                            pKeyPairPwd, &certDecBuff[certStartSignOffset]);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to DX_Common_RSA_Sign\n");
        goto END;
    }

    UTIL_LOG_INFO("after SHA256\n");
    // UTIL_LOG_BYTE_BUFF("certDecBuff", certDecBuff, certDecSize);

#ifdef UTIL_DEBUG
    UTIL_LOG_INFO("writing certificate into file %s\n", certFileName[certType]);
    DX_Common_Util_copyBuffToBinFile(certFileName[certType], certDecBuff, certDecSize);
#endif

    pPemCertData = malloc(bioCertSize);
    if (pPemCertData == NULL) {
        UTIL_LOG_ERR("failed to malloc pPemCertData\n");
        rc = 1;
        goto END;
    }
    rc = DX_Common_PEM_Encode(certDecBuff, certDecSize, pPemCertData, &bioCertSize);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to DX_Common_PEM_Encode\n");
        goto END;
    }
    *pOutCertSize = bioCertSize;

    DX_Common_x509_free(ppCertBuff);
    *ppCertBuff = pPemCertData;

    rc = 0;
    UTIL_LOG_INFO("OK\n");

END:
    if (certDecBuff != NULL) {
        free(certDecBuff);
    }
    if (rc != 0) {
        if (pPemCertData != NULL) {
            free(pPemCertData);
        }
        DX_Common_x509_free(ppCertBuff);
    }
    return rc;
}

/*
 * @brief build package for the certificate
 *
 * @param[in] ppCertBuff          - the x509 certificate  in PEM format
 * @param[in] certSize         - certificate size
 * @param[in] certType           - certificate type
 * @param[in] encFlag           - indicates whether images were encrypted
 * @param[in] hbkType           - hbk type to use by target, in the verification
 * @param[in] pAddData        - additional data to add to package
 * @param[in] addDataSize        - length of additional data
 * @param[in] outPkgFile        - package file name to write the package to
 */
/* ****************************************************** */
int32_t DX_Common_x509_BuildCertPkg(uint8_t **ppCertBuff, uint32_t certSize, DxX509CertType_t certType, uint8_t encFlag,
                                    uint8_t hbkType, uint8_t *pAddData, uint32_t addDataSize, uint8_t *outPkgFile)
{
    int32_t rc               = 0;
    FILE *fp                 = NULL;
    uint8_t *pCertPkg        = NULL;
    uint32_t nextBlockOffset = 0;
    uint32_t pkgBytesSize    = 0;

    UTIL_LOG_INFO("started\n");
    /* check inputs */
    if ((outPkgFile == NULL) || (ppCertBuff == NULL) || (*ppCertBuff == NULL) || (certSize == 0) ||
        (certSize >= DX_X509_MAX_CERT_SIZE) ||
        ((certType <= DX_X509_CERT_TYPE_MIN) || (certType >= DX_X509_CERT_TYPE_MAX)) ||
        ((pAddData != NULL) && (addDataSize == 0)) || ((pAddData == NULL) && (addDataSize != 0)) ||
        (!IS_VALID_ENC_FLAG(encFlag & 0xFF)) || (!IS_VALID_HBK(hbkType & 0xFF))) {
        UTIL_LOG_ERR("illegal input\n");
        rc = (-1);
        goto END;
    }

    /* calcultae package size */
    pkgBytesSize = (sizeof(DxX509PkgHeader_t) + addDataSize);

    UTIL_LOG_INFO("openning certificate pkg file for writing\n");
    fp = fopen(outPkgFile, "w");
    if (fp == NULL) {
        UTIL_LOG_ERR("failed to open %s\n", outPkgFile);
        rc = (-1);
        goto END;
    }

    pkgBytesSize += certSize + 1; /* Adding 1 for "\0" */
    UTIL_LOG_INFO("about to allocate memory for pkg:size %d, certSize %d, addDataSize %d\n", pkgBytesSize, certSize,
                  addDataSize);

    /* create the package buffer */
    pCertPkg = (uint8_t *)malloc(pkgBytesSize);
    if (pCertPkg == NULL) {
        UTIL_LOG_ERR("failed to allocate pkg\n");
        rc = (-1);
        goto END;
    }
    nextBlockOffset = sizeof(DxX509PkgHeader_t);
    /* copy additional data to package */
    if (pAddData != NULL) {
        memcpy(&pCertPkg[nextBlockOffset], pAddData, addDataSize);
        nextBlockOffset += addDataSize;
    }
    /* copy certificate PEM  to package */
    memcpy(&pCertPkg[nextBlockOffset], *ppCertBuff, certSize);

    /* setting pkg header */
    UTIL_LOG_INFO("setting pkg header\n");
    ((DxX509PkgHeader_t *)pCertPkg)->pkgToken                       = DX_CERT_PKG_TOKEN;
    ((DxX509PkgHeader_t *)pCertPkg)->pkgVer                         = DX_CERT_PKG_VERSION;
    ((DxX509PkgHeader_t *)pCertPkg)->pkgFlags.pkgFlagsWord          = 0;
    ((DxX509PkgHeader_t *)pCertPkg)->pkgFlags.pkgFlagsBits.certType = certType & 0xFF;
    ((DxX509PkgHeader_t *)pCertPkg)->pkgFlags.pkgFlagsBits.imageEnc = encFlag & 0xFF;
    ((DxX509PkgHeader_t *)pCertPkg)->pkgFlags.pkgFlagsBits.hbkType  = hbkType & 0xFF;
    ((DxX509PkgHeader_t *)pCertPkg)->certInfo.certInfoWord          = 0;
    ((DxX509PkgHeader_t *)pCertPkg)->certInfo.certInfoBits.storeAddr =
        (sizeof(DxX509PkgHeader_t) + addDataSize) & 0xFFFF;
    ((DxX509PkgHeader_t *)pCertPkg)->certInfo.certInfoBits.certSize = certSize;

    /* write out the package in binary format  */
    UTIL_LOG_INFO("writing pkg to file\n");
    rc = DX_Common_Util_copyBuffToBinFile(outPkgFile, pCertPkg, pkgBytesSize);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to DX_Common_Util_copyBuffToBinFile\n");
        rc = 1;
        goto END;
    }
    rc = 0;
    UTIL_LOG_INFO("OK\n");

END:
    if (fp != NULL) {
        fclose(fp);
    }
    if (pCertPkg != NULL) {
        free(pCertPkg);
    }
    return rc;
}
