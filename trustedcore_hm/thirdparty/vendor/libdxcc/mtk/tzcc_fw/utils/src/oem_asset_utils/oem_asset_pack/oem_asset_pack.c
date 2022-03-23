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
#define OEM_ASSET_PROV_KEY_BUFF_SIZE 16
#define OEM_KEY_BASE64_SIZE_IN_BYTES (SASI_COMMON_CALC_BASE64_ENCODE_SIZE(sizeof(EncOemKeyBuff_t)))

static int assetId                   = 0;
static int userData                  = 0;
static unsigned int assetBinBuffSize = 0;

static unsigned char assetBinFileName[UTIL_MAX_FILE_NAME]                     = "asset_bin.bin";
static unsigned char assetBinBuff[SASI_UTIL_OEM_ASSET_DATA_MAX_SIZE_IN_BYTES] = { 0 };

static unsigned char keyPairFileName[UTIL_MAX_FILE_NAME] = "key_pair.pem";
static unsigned char pwdFileName[UTIL_MAX_FILE_NAME]     = { 0 };
static unsigned char *pwdFilePtr                         = NULL;

static unsigned char oemKeyFileName[UTIL_MAX_FILE_NAME]                = "oem_key.bin";
static unsigned char oemKeyRsaBase64Buff[OEM_KEY_BASE64_SIZE_IN_BYTES] = { 0 };
static unsigned char provKeyBuff[OEM_ASSET_PROV_KEY_BUFF_SIZE]         = { 0 };
static unsigned char oemKeyBuff[SASI_UTIL_KOEM_SIZE_IN_BYTES]          = { 0 };

static unsigned char assetPktFileName[UTIL_MAX_FILE_NAME]                    = "asset_pkg.bin";
static unsigned char assetPkg[SASI_UTIL_OEM_ASSET_PACKAGE_MAX_SIZE_IN_BYTES] = { 0 };

static struct option main_long_options[] = {
    { "asset-pkg", required_argument, 0, 'a' },
    { "asset-bin", required_argument, 0, 'b' },
    { "asset-id", required_argument, 0, 'i' },
    { "oem-key", required_argument, 0, 'o' },
    { "key-pair", required_argument, 0, 'p' },
    { "pwd", required_argument, 0, 'w' },
    { "user-data", required_argument, 0, 'u' },
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
                 "[-a @OUTPUT@ asset package file name <asset_pkg.bin>] "
                 "[-b asset data binary file <asset_bin.bin>] "
                 "[-i asset ID  <32 bit word>]"
                 "[-o file name for oem-key <oem_key.bin>]"
                 "[-p key pair file name - PEM format <key_pair.pem>]"
                 "[-w optional, pwd of private key file name. If not exist, PEM should be entered manually"
                 "[-u optional additional user data <32 bit word>]\n");

    UTIL_LOG_ERR("Parameters:\n");
    UTIL_LOG_ERR("--asset-pkg            -a:\t @OUTPUT@ asset package file name <asset_pkg.bin>\n");
    UTIL_LOG_ERR("--asset-bin            -b:\t asset data binary file <asset_bin.bin>\n");
    UTIL_LOG_ERR("--asset-id             -i:\t asset ID  <32 bit word BE format>\n");
    UTIL_LOG_ERR("--oem-key              -o:\t file name for oem-key <oem_key.bin>\n");
    UTIL_LOG_ERR("--key-pair             -p:\t key pair file name - PEM format <key_pair.pem>\n");
    UTIL_LOG_ERR(
        "--pwd                  -w:\t optional, pwd of private key file name. If not exist, PEM should be entered manually\n");
    UTIL_LOG_ERR("--user-data            -u:\t optional additional user data <32 bit word BE format>\n");
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
    int rc                               = 0;
    unsigned int oemKeyRsaBase64BuffSize = 0;

    // parse argument from command line, and initalize fields
    while (1) {
        ch = getopt_long(argc, argv, "a:b:i:o:p:u:w:H", main_long_options, &long_opt_index);

        if (ch == -1)
            break; // No more parameters
        switch (ch) {
        case 'a': // --asset-pkg
            strncpy(assetPktFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            assetPktFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("assetPktFileName %s\n", assetPktFileName);
            break;
        case 'b': // --asset-bin
            strncpy(assetBinFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            assetBinFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("assetBinFileName %s\n", assetBinFileName);
            break;
        case 'i': // --asset-id
            assetId = strtoul(optarg, NULL, 16);
            UTIL_LOG_INFO("assetId 0x%08X\n", assetId);
            break;
        case 'p': // --key-pair
            strncpy(keyPairFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            keyPairFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("keyPairFileName %s\n", keyPairFileName);
            break;
        case 'w': // --pwd
            strncpy(pwdFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            pwdFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("pwdFileName %s\n", pwdFileName);
            pwdFilePtr = pwdFileName;
            break;
        case 'o': // --oem-key
            strncpy(oemKeyFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            oemKeyFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("oemKeyFileName %s\n", oemKeyFileName);
            break;
        case 'u': // --user-data
            userData = strtoul(optarg, NULL, 16);
            UTIL_LOG_INFO("userData 0x%08X\n", userData);
            break;
        case 'H': // --help
            usage();
            break;
        }
    }

    /*  check params are valid. only asset-id is required */
    if (assetId == 0) {
        UTIL_LOG_ERR("invalid asset_id 0x%08X\n", assetId);
        return 1;
    }

    /* read data from files */
    /* read asset binary file */
    assetBinBuffSize = sizeof(assetBinBuff);
    rc               = SaSi_CommonUtilCopyDataFromBinFile(assetBinFileName, assetBinBuff, &assetBinBuffSize);
    if ((rc != 0) || (assetBinBuffSize & OEM_ASSET_MUL_16_BYTES_MASK) || (assetBinBuffSize == 0) ||
        (assetBinBuffSize > SASI_UTIL_OEM_ASSET_DATA_MAX_SIZE_IN_BYTES)) {
        UTIL_LOG_ERR("failed parse asset-bin file, rc %d, assetBinBuffSize %d\n", rc, assetBinBuffSize);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("assetBinBuff", assetBinBuff, assetBinBuffSize);

    /* read oem-key binary file */
    oemKeyRsaBase64BuffSize = sizeof(oemKeyRsaBase64Buff);
    rc = SaSi_CommonUtilCopyDataFromBinFile(oemKeyFileName, oemKeyRsaBase64Buff, &oemKeyRsaBase64BuffSize);
    if ((rc != 0) || (oemKeyRsaBase64BuffSize > sizeof(oemKeyRsaBase64Buff))) {
        UTIL_LOG_ERR("failed parse oem-key file, rc %d, oemKeyRsaBase64BuffSize %d\n", rc, oemKeyRsaBase64BuffSize);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("oemKeyRsaBase64Buff", oemKeyRsaBase64Buff, oemKeyRsaBase64BuffSize);

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
int getOemKey(void)
{
    int rc                    = 0;
    int oemKeyStrSize         = 0;
    EncOemKeyBuff_t oemKeyStr = { 0 };

    /* get oem key from its file. first decode base64, then RSA_OAEP decrypt using key pair */
    oemKeyStrSize = sizeof(EncOemKeyBuff_t);
    rc = SaSi_CommonBase64Decode(oemKeyRsaBase64Buff, sizeof(oemKeyRsaBase64Buff), (char *)&oemKeyStr, &oemKeyStrSize);
    if ((rc != 0) || (oemKeyStrSize != sizeof(EncOemKeyBuff_t))) {
        UTIL_LOG_ERR("failed to SaSi_CommonBase64Decode(), rc %d oemKeyStrSize %d\n", rc, oemKeyStrSize);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("oemKeyStr", (unsigned char *)&oemKeyStr, (int)sizeof(oemKeyStr));
    if (oemKeyStr.token != CM_GEN_OEM_KEY_TOKEN) {
        UTIL_LOG_ERR("Ilegal token in oem key 0x%x\n", oemKeyStr.token);
        return 1;
    }
    if (oemKeyStr.version != OEM_ASSET_VERSION) {
        UTIL_LOG_ERR("Ilegal version in oem key 0x%x\n", oemKeyStr.version);
        return 1;
    }
    if (oemKeyStr.len != sizeof(EncOemKeyBuff_t)) {
        UTIL_LOG_ERR("Ilegal length in oem key 0x%x\n", oemKeyStr.len);
        return 1;
    }
    OpenSSL_add_all_algorithms();
    rc = SaSi_CommonRsaDecrypt(RSA_USE_PKCS_21_VERSION, keyPairFileName, pwdFilePtr, oemKeyStr.oemKeyRsaEnc,
                               RSA_OAEP_KEY_SIZE_IN_BYTES, oemKeyBuff);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data(); /* cleanup application specific data to avoid memory leaks. */
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonRsaDecrypt(), rc %d\n", rc);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("oemKeyBuff", oemKeyBuff, (int)sizeof(oemKeyBuff));

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
int main(int argc, char *argv[])
{
    int rc                                                  = 0;
    int provKeyBuffSize                                     = 0;
    unsigned char dataInBuff[OEM_ASSET_DATA_IN_CMAC_LENGTH] = { 0 };
    int i                                                   = 0;
    unsigned char tempRand                                  = 0;
    unsigned int assetEnDataSize                            = 0;

    /* parse command line arguments and files content */
    rc = parseArguments(argc, argv);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to parse arguments\n");
        return rc;
    }

    /* get oem key */
    rc = getOemKey();
    if (rc != 0) {
        UTIL_LOG_ERR("failed to getOemKey()\n");
        goto packEnd;
    }

    /* Generate provisioning key: KPROV = AES-CMAC (KOEM, 0x01 || 0x50 || 0x00 || asset id || 0x80); */
    i               = 0;
    dataInBuff[i++] = KOEM_DATA_IN_PREFIX_DATA0;
    dataInBuff[i++] = KOEM_DATA_IN_PREFIX_DATA1;
    dataInBuff[i++] = KOEM_DATA_IN_PREFIX_DATA2;
    CONVERT_WORD_TO_BYTE_ARR(assetId, &dataInBuff[i]);
    i += sizeof(int);
    dataInBuff[i] = KOEM_DATA_IN_SUFIX_DATA;

    provKeyBuffSize = ASSET_PKG_AES_CMAC_RESULT_SIZE_IN_BYTES;
    rc = SaSi_CommonAesCmacEncrypt(dataInBuff, sizeof(dataInBuff), oemKeyBuff, SASI_UTIL_KOEM_SIZE_IN_BYTES,
                                   provKeyBuff);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonAesCmacEncrypt() for provKeyBuff rc %d\n", rc);
        goto packEnd;
    }
    UTIL_LOG_BYTE_BUFF("provKeyBuff", provKeyBuff, (int)sizeof(provKeyBuff));

    /* Build Asset package buffer local buffer */
    CONVERT_WORD_TO_BYTE_ARR((unsigned int)OEM_ASSET_PACK_TOKEN, &assetPkg[ASSET_PKG_TOKEN_OFFSET]);
    CONVERT_WORD_TO_BYTE_ARR((unsigned int)OEM_ASSET_VERSION, &assetPkg[ASSET_PKG_VERSION_OFFSET]);
    CONVERT_WORD_TO_BYTE_ARR(userData, &assetPkg[ASSET_PKG_USER_DATA_OFFSET]);

    assetEnDataSize = assetBinBuffSize;
    CONVERT_WORD_TO_BYTE_ARR(assetEnDataSize, &assetPkg[ASSET_PKG_EN_DATA_SIZE_OFFSET]);

    /* generate Nonce */
    if (RAND_bytes(&assetPkg[ASSET_PKG_CCM_NONCE_OFFSET], ASSET_PKG_CCM_NONCE_SIZE) < 0) {
        UTIL_LOG_ERR("failed to rand NONCE\n");
        rc = 1;
        goto packEnd;
    }

    /* Encrypt the Binary asset buffer using AES_CCM */
    rc = SaSi_CommonAesCcmEncrypt(provKeyBuff, &assetPkg[ASSET_PKG_CCM_NONCE_OFFSET], ASSET_PKG_CCM_NONCE_SIZE,
                                  &assetPkg[ASSET_PKG_CCM_ADDITIONAL_DATA_OFFSET], ASSET_PKG_CCM_ADDITIONAL_DATA_SIZE,
                                  assetBinBuff, assetBinBuffSize, &assetPkg[ASSET_PKG_EN_DATA_OFFSET], &assetEnDataSize,
                                  &assetPkg[ASSET_PKG_EN_DATA_OFFSET + assetBinBuffSize], ASSET_PKG_MAC_SIZE);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonAesCcmEncrypt or invalid size max is %d actual is %d\n", assetBinBuffSize,
                     assetEnDataSize);
        goto packEnd;
    }
    UTIL_LOG_BYTE_BUFF("assetPkg", assetPkg, ASSET_PKG_NONE_ASSET_DATA_SIZE + assetEnDataSize);

    /* save buffer into file */
    rc = SaSi_CommonUtilCopyBuffToBinFile(assetPktFileName, assetPkg, ASSET_PKG_NONE_ASSET_DATA_SIZE + assetEnDataSize);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonUtilCopyBuffToBinFile()\n");
        goto packEnd;
    }
    rc = 0;
packEnd:
    return rc;
}
