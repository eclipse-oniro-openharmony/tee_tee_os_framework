/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/cmac.h>
#include "ssi_util_oem_asset_defs.h"
#include "../oem_asset_utils.h"
#include "common_util_files.h"
#include "common_util_log.h"
#include "common_crypto_encode.h"
#include "common_crypto_asym.h"
#include "common_crypto_sym.h"

/* definitions for file parsing and building Koem */
#define OEM_ASSET_KCP_KEY_BUFF_SIZE      16 // Kcp = Krtl XOR (Scp || 0'64)
#define CM_SECRETS_FILE_CONTENT_MAX_SIZE (OEM_ASSET_KRTL_BUFF_SIZE + OEM_ASSET_SCP_BUFF_SIZE)

/*  key derivation as specified in [SP800-108] in section "KDF in Counter Mode */
#define CM_UTIL_MAX_LABEL_LENGTH_IN_BYTES   32
#define CM_UTIL_MAX_CONTEXT_LENGTH_IN_BYTES 32
#define CM_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES  3   /* counter, 0x00, lengt(0x80) */
#define CM_UTIL_DERIVED_KEY_SIZE_IN_BYTES   128 /* 128b */
#define CM_UTIL_MAX_KDF_SIZE_IN_BYTES \
    (CM_UTIL_MAX_LABEL_LENGTH_IN_BYTES + CM_UTIL_MAX_CONTEXT_LENGTH_IN_BYTES + CM_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES)

#define KEY_PLAT_LABEL 0x4B, 0x45, 0x59, 0x20, 0x50, 0x4C, 0x41, 0x54 /* "KEY PLAT" */
#define KEY_PROVISION_LABEL \
    0x50, 0x52, 0x4f, 0x56, 0x49, 0x53, 0x49, 0x4f, 0x4e, 0x20, 0x4B, 0x45, 0x59 /* PROVISION KEY */

static unsigned char cmSecretsFileName[UTIL_MAX_FILE_NAME]               = "cm_secrets.bin";
static unsigned char cmPwdFileName[UTIL_MAX_FILE_NAME]                   = { 0 };
static unsigned char *cmPwdFilePtr                                       = NULL;
static unsigned char cmSecretsBase64AesBuff[SASI_COMMON_CALC_BASE64_ENCODE_SIZE(
    SASI_COMMON_CALC_CBC_ENCODE_SIZE(CM_SECRETS_FILE_CONTENT_MAX_SIZE))] = { 0 };
static unsigned int cmSecretsBase64AesBuffSize                           = 0;
/* in AES output size equals to input size (must be multiple of 16 bytes) adding 16 bytes */
static unsigned char cmSecretsAesBuff[SASI_COMMON_CALC_CBC_ENCODE_SIZE(CM_SECRETS_FILE_CONTENT_MAX_SIZE)] = { 0 };
static unsigned char cmSecretsBuff[OEM_ASSET_CM_SECRETS_BUFF_SIZE] = { 0 }; /* last 8 bytes are 0 */

static unsigned char csrFileName[UTIL_MAX_FILE_NAME]                                       = "csr.bin";
static unsigned char csrBase64Buff[SASI_COMMON_CALC_BASE64_ENCODE_SIZE(sizeof(CsrBuff_t))] = { 0 };
static CsrBuff_t csrBuff                                                                   = { 0 };

static unsigned char pubKey1FileName[UTIL_MAX_FILE_NAME]    = "";
static unsigned char cpKeyBuff[OEM_ASSET_KCP_KEY_BUFF_SIZE] = { 0 };
static unsigned char hbkBuff[OEM_ASSET_MAX_HBK_BUFF_SIZE]   = { 0 };

static unsigned char pltKeyBuff[SASI_UTIL_KPLT_SIZE_IN_BYTES] = { 0 };

static unsigned char oemKeyFileName[UTIL_MAX_FILE_NAME]                                              = "oem_key.bin";
static unsigned char oemKeyBuff[SASI_UTIL_KOEM_SIZE_IN_BYTES]                                        = { 0 };
static EncOemKeyBuff_t oemKeyRsa                                                                     = { 0 };
static unsigned char oemKeyRsaBase64Buff[SASI_COMMON_CALC_BASE64_ENCODE_SIZE(ENC_OEM_KEY_BUFF_SIZE)] = { 0 };

static bool isSecKeyExist = false;

static struct option main_long_options[] = {
    { "csr", required_argument, 0, 'c' },
    { "pubkey1", required_argument, 0, 'q' },
    { "oem-key", required_argument, 0, 'o' },
    { "cm-secrets", required_argument, 0, 's' },
    { "cm-pwd", required_argument, 0, 'w' },
    { "help", no_argument, 0, 'H' },
    { NULL, 0, 0, 0 } /* end of options list */
};

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
void usage(void)
{
    UTIL_LOG_ERR("\nUsage:"
                 "[-c csr file name <csr.bin>] "
                 "[-q optional CM public key key file name - PEM format <pubKey1.pem>]"
                 "[-o @OUTPUT@ oem key file name <oem_key.bin>]"
                 "[-s file name for Scp and Krtl <cm_secrets.bin>]"
                 "[-w optional, pwd of private key file name. If not exist, PEM should be entered manually.\n");

    UTIL_LOG_ERR("Parameters:\n");
    UTIL_LOG_ERR("--csr                  -c:\t csr binary file <csr.bin>\n");
    UTIL_LOG_ERR("--pubkey1              -q:\t optional public key key file name - PEM format <pubKey1.pem>\n");
    UTIL_LOG_ERR("--oem-key              -o:\t @OUTPUT@ oem key file name <oem_key.bin>\n");
    UTIL_LOG_ERR("--cm-secrets           -s:\t file name for Scp and Krtl <cm_secrets.bin>\n");
    UTIL_LOG_ERR(
        "--cm-pwd              -w:\t optional, pwd of private key file name. If not exist, PEM should be entered manually\n");
    UTIL_LOG_ERR("--help                 -H:\t Help\n");
    exit(1);
}

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int parseArguments(const int argc, char *const argv[])
{
    int ch;
    int long_opt_index;
    int rc                         = 0;
    unsigned int csrBase64BuffSize = 0;

    // parse argument from command line, and initalize fields
    while (1) {
        ch = getopt_long(argc, argv, "c:q:o:s:w:H", main_long_options, &long_opt_index);

        if (ch == -1)
            break; // No more parameters
        switch (ch) {
        case 'c': // --csr
            strncpy(csrFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            csrFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("csrFileName %s\n", csrFileName);
            break;
        case 'q': // --pubkey1
            strncpy(pubKey1FileName, optarg, UTIL_MAX_FILE_NAME - 1);
            pubKey1FileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("pubKey1 File Name %s\n", pubKey1FileName);
            isSecKeyExist = true;
            break;
        case 'o': // --oem-key
            strncpy(oemKeyFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            oemKeyFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("oemKeyFileName %s\n", oemKeyFileName);
            break;
        case 's': // --cm-secrets
            strncpy(cmSecretsFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            cmSecretsFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("cmSecretsFileName %s\n", cmSecretsFileName);
            break;
        case 'w': // --cm-pwd
            strncpy(cmPwdFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            cmPwdFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("cmPwdFileName %s\n", cmPwdFileName);
            cmPwdFilePtr = cmPwdFileName;
            break;
        case 'H': // --help
            usage();
            break;
        }
    }

    /* read data from files */
    /* read asset binary file */
    csrBase64BuffSize = sizeof(csrBase64Buff);
    rc                = SaSi_CommonUtilCopyDataFromBinFile(csrFileName, csrBase64Buff, &csrBase64BuffSize);
    if ((rc != 0) || (csrBase64BuffSize != (sizeof(csrBase64Buff)))) {
        UTIL_LOG_ERR("failed parse csr file, rc %d, csr Size %d\n", rc, csrBase64BuffSize);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("csrBase64Buff", csrBase64Buff, csrBase64BuffSize);

    /* read asset binary file */
    cmSecretsBase64AesBuffSize = sizeof(cmSecretsBase64AesBuff);
    rc = SaSi_CommonUtilCopyDataFromBinFile(cmSecretsFileName, cmSecretsBase64AesBuff, &cmSecretsBase64AesBuffSize);
    if ((rc != 0) || (cmSecretsBase64AesBuffSize > sizeof(cmSecretsBase64AesBuff))) {
        UTIL_LOG_ERR("failed parse cm-secrets file, rc %d, cm-secrets size %d\n", rc, cmSecretsBase64AesBuffSize);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("cmSecretsBase64AesBuff", cmSecretsBase64AesBuff, cmSecretsBase64AesBuffSize);

    return 0;
}

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int getCmSecrets(void)
{
    int rc                            = 0;
    unsigned int cmSecretsAesBuffSize = 0;

    UTIL_LOG_BYTE_BUFF("cmSecretsBase64AesBuff", cmSecretsBase64AesBuff, cmSecretsBase64AesBuffSize);
    /* get cm secrets from its file. first decode base64, then decrypt with AES_CBC128 */
    cmSecretsAesBuffSize = SASI_COMMON_CALC_BASE64_MAX_DECODE_SIZE(cmSecretsBase64AesBuffSize);
    rc                   = SaSi_CommonBase64Decode(cmSecretsBase64AesBuff, cmSecretsBase64AesBuffSize, cmSecretsAesBuff,
                                 &cmSecretsAesBuffSize);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonBase64Decode() for cm secrets, rc %d\n", rc);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("cmSecretsAesBuff", cmSecretsAesBuff, (int)sizeof(cmSecretsAesBuff));

    rc = SaSi_CommonAesCbcDecrypt(cmPwdFilePtr, cmSecretsAesBuff, cmSecretsAesBuffSize, cmSecretsBuff);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonAesCbcDecrypt() for cm secrets, rc %d\n", rc);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("cmSecretsBuff", cmSecretsBuff, (int)sizeof(cmSecretsBuff));
    return 0;
}

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int computeHbk(void)
{
    int rc         = 0;
    int sizeOfHash = sizeof(hbkBuff);

    /* update HASH size in case of 2 public keys */
    if (true == isSecKeyExist) {
        sizeOfHash /= 2;
    }

    /* compute  hbkBuff  */
    /* compute  hbkBuff on key0 */
    rc = SaSi_CommonCalcHBKFromBuff(csrBuff.pubKey0, hbkBuff, sizeOfHash);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonCalcHBKFromBuff %d for pubKey0\n", rc);
        return 1;
    }
    /* If there is a second keypair the hbkbuff is combined from truncated_hbk0 + truncated_hbk1 */
    if (true == isSecKeyExist) {
        /* compute  hbkBuff */
        rc = SaSi_CommonCalcHBKFromFile(pubKey1FileName, hbkBuff + sizeOfHash, sizeOfHash);
        if (rc != 0) {
            UTIL_LOG_ERR("failed to SaSi_CommonCalcHBKFromBuff %d for pubKey1\n", rc);
            return 1;
        }
    }

    UTIL_LOG_BYTE_BUFF("hbkBuff", hbkBuff, (int)sizeof(hbkBuff));
    return 0;
}

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int buildKcp(void)
{
    int i = 0;
    int j = 0;

    /* compute provisioning key master KCP = KPRTL XOR (064 || SCP) */
    for (i = 0; i < OEM_ASSET_KCP_KEY_BUFF_SIZE / 2; i++) {
        cpKeyBuff[i] = cmSecretsBuff[OEM_ASSET_PROV_KEY_FILE_KPRTL_OFFSET + i];
    }
    j = 0;
    for (i = OEM_ASSET_KCP_KEY_BUFF_SIZE / 2; i < OEM_ASSET_KCP_KEY_BUFF_SIZE; i++) {
        cpKeyBuff[i] = cmSecretsBuff[OEM_ASSET_PROV_KEY_FILE_KPRTL_OFFSET + i] ^
                       cmSecretsBuff[OEM_ASSET_PROV_KEY_FILE_SCP_OFFSET + j];
        j++;
    }
    return 0;
}

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int getCsr(void)
{
    int rc                   = 0;
    unsigned int csrBuffSize = 0;

    /* first decode base64 */
    csrBuffSize = sizeof(csrBuff);
    rc = SaSi_CommonBase64Decode(csrBase64Buff, sizeof(csrBase64Buff), (unsigned char *)&csrBuff, &csrBuffSize);
    if ((rc != 0) || (csrBuffSize != sizeof(csrBuff))) {
        UTIL_LOG_ERR("failed to SaSi_CommonBase64Decode() for csr, rc %d, csr length %d\n", rc, csrBuffSize);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("csrBuff", (unsigned char *)&csrBuff, sizeof(csrBuff));

    /* verify CSR header */
    if (csrBuff.token != OEM_GEN_CSR_TOKEN) {
        UTIL_LOG_ERR("Ilegal token in csr 0x%x\n", csrBuff.token);
        return 1;
    }
    if (csrBuff.version != OEM_ASSET_VERSION) {
        UTIL_LOG_ERR("Ilegal version in csr 0x%x\n", csrBuff.version);
        return 1;
    }
    if (csrBuff.len != sizeof(csrBuff)) {
        UTIL_LOG_ERR("Ilegal length in csr 0x%x\n", csrBuff.len);
        return 1;
    }

    /* verify CSR signatire */
    rc = SaSi_CommonRsaVerify(RSA_USE_PKCS_21_VERSION,                   /* RSA version */
                              csrBuff.pubKey0,                           /* public key to verify with */
                              (char *)&csrBuff,                          /* data */
                              sizeof(csrBuff) - sizeof(csrBuff.csrSign), /* data size */
                              csrBuff.csrSign);                          /* signature */
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonRsaVerify() for csr, rc %d\n", rc);
        return 1;
    }
    UTIL_LOG_ERR("getCsr: OK\n");
    return 0;
}

static int deriveKey(char *pLabel, int labelSize, char *pContext, int contextSize, char *pKey, int keySize,
                     char *pKeyOut)
{
    int i, dataSize, err = 0;
    uint8_t dataIn[CM_UTIL_MAX_KDF_SIZE_IN_BYTES] = { 0 };

    dataSize = CM_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES + labelSize + contextSize;
    i        = 0;

    /* Generate dataIn buffer for CMAC: 0x01 || Label || 0x00 || context || length */
    dataIn[i++] = 0x01;

    if (labelSize != 0) {
        memcpy(&dataIn[i], pLabel, labelSize);
        i += labelSize;
    }

    dataIn[i++] = 0x00;

    if (contextSize != 0) {
        memcpy(&dataIn[i], pContext, contextSize);
        i += contextSize;
    }

    dataIn[i] = CM_UTIL_DERIVED_KEY_SIZE_IN_BYTES;

    err = SaSi_CommonAesCmacEncrypt(dataIn, dataSize, pKey, keySize, pKeyOut);

    return err;
}

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int main(int argc, char *argv[])
{
    int rc                      = 0;
    int oemKeyRsaBase64BuffSize = 0;

    uint8_t keyPlatLabel[]      = { KEY_PLAT_LABEL };
    uint8_t keyProvisionLabel[] = { KEY_PROVISION_LABEL };

    UTIL_LOG_INFO("cm_gen_oem_key started\n");
    /* parse command line arguments and files content */
    rc = parseArguments(argc, argv);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to parse arguments\n");
        return rc;
    }

    OpenSSL_add_all_algorithms();
    UTIL_LOG_INFO("calling getCsr()\n");
    /* get CSR from its file. first decode base64, then verify it using RSA_PSS verify using pubkye0stored in CSR  */
    rc = getCsr();
    if (rc != 0) {
        UTIL_LOG_ERR("failed to getCsr()\n");
        goto genOemEnd;
    }

    UTIL_LOG_INFO("calling computeHbk()\n");
    /* compute  hbkBuff  */
    rc = computeHbk();
    if (rc != 0) {
        UTIL_LOG_ERR("failed to computeHbk()\n");
        goto genOemEnd;
    }

    UTIL_LOG_INFO("calling getCmSecrets()\n");
    /* get cm secrets  */
    rc = getCmSecrets();
    if (rc != 0) {
        UTIL_LOG_ERR("failed to getCmSecrets()\n");
        goto genOemEnd;
    }

    /* calculate OEM key */
    UTIL_LOG_INFO("Build Kcp\n");
    /* get cm secrets  */
    rc = buildKcp();
    if (rc != 0) {
        UTIL_LOG_ERR("failed to buildKcp()\n");
        goto genOemEnd;
    }
    UTIL_LOG_BYTE_BUFF("cpKeyBuff", cpKeyBuff, OEM_ASSET_KCP_KEY_BUFF_SIZE);

    /* Derives Kplt = KDF (Kcp, "KEY PLAT", Hbk, 128) */
    rc = deriveKey((uint8_t *)keyPlatLabel, sizeof(keyPlatLabel), hbkBuff, sizeof(hbkBuff), cpKeyBuff,
                   OEM_ASSET_KCP_KEY_BUFF_SIZE, pltKeyBuff);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to deriveKey for platform Key: rc %d\n", rc);
        rc = 1;
        goto genOemEnd;
    }
    UTIL_LOG_BYTE_BUFF("pltKeyBuff", pltKeyBuff, (int)sizeof(pltKeyBuff));

    /* Derives Koem = KDF (Kplt, "PROVISION KEY", Hbk, 128) */
    rc = deriveKey((uint8_t *)keyProvisionLabel, sizeof(keyProvisionLabel), hbkBuff, sizeof(hbkBuff), pltKeyBuff,
                   SASI_UTIL_KPLT_SIZE_IN_BYTES, oemKeyBuff);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to deriveKey for oem Key: rc %d\n", rc);
        rc = 1;
        goto genOemEnd;
    }
    UTIL_LOG_BYTE_BUFF("oemKeyBuff", oemKeyBuff, (int)sizeof(oemKeyBuff));

    /* encrypt the key using RSA_OAEP */
    rc = SaSi_CommonRsaEncrypt(RSA_USE_PKCS_21_VERSION, csrBuff.pubKey0, oemKeyBuff, (int)sizeof(oemKeyBuff),
                               oemKeyRsa.oemKeyRsaEnc);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonRsaEncrypt(), rc %d\n", rc);
        goto genOemEnd;
    }
    UTIL_LOG_BYTE_BUFF("oemKeyRsaEnc", oemKeyRsa.oemKeyRsaEnc, (int)sizeof(oemKeyRsa.oemKeyRsaEnc));

    /* Add header to key buffer */
    oemKeyRsa.token   = CM_GEN_OEM_KEY_TOKEN;
    oemKeyRsa.version = OEM_ASSET_VERSION;
    oemKeyRsa.len     = sizeof(EncOemKeyBuff_t);

    /* perform base64-encode */
    oemKeyRsaBase64BuffSize = sizeof(oemKeyRsaBase64Buff);
    rc = SaSi_CommonBase64Encode((char *)&oemKeyRsa, sizeof(oemKeyRsa), oemKeyRsaBase64Buff, &oemKeyRsaBase64BuffSize);
    if ((rc != 0) || (oemKeyRsaBase64BuffSize != sizeof(oemKeyRsaBase64Buff))) {
        UTIL_LOG_ERR("failed to SaSi_CommonBase64Encode(), rc %d\n", rc);
        goto genOemEnd;
    }

    UTIL_LOG_BYTE_BUFF("oemKeyRsaBase64Buff", oemKeyRsaBase64Buff, (int)sizeof(oemKeyRsaBase64Buff));
    /* save buffer into file */
    rc = SaSi_CommonUtilCopyBuffToBinFile(oemKeyFileName, oemKeyRsaBase64Buff, oemKeyRsaBase64BuffSize);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonUtilCopyBuffToBinFile()\n");
        goto genOemEnd;
    }

    rc = 0;
genOemEnd:
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data(); /* cleanup application specific data to avoid memory leaks. */
    return rc;
}
