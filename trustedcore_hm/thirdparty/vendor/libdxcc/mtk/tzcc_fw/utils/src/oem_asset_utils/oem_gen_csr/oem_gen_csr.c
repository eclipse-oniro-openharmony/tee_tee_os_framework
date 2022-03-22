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
#include "common_crypto_asym.h"
#include "common_crypto_encode.h"

static unsigned char csrFileName[UTIL_MAX_FILE_NAME]     = "csr.bin";
static unsigned char keyPairFileName[UTIL_MAX_FILE_NAME] = "key_pair.pem";
static unsigned char pwdFileName[UTIL_MAX_FILE_NAME]     = { 0 };
static unsigned char *pwdFilePtr                         = NULL;

static CsrBuff_t csrBuff                                                                      = { 0 };
static unsigned char csrBase64EncBuff[SASI_COMMON_CALC_BASE64_ENCODE_SIZE(sizeof(CsrBuff_t))] = { 0 };

static struct option main_long_options[] = {
    { "csr", required_argument, 0, 'c' },
    { "key-pair", required_argument, 0, 'p' },
    { "pwd", required_argument, 0, 'w' },
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
                 "[-c @OUTPUT@ csr file name <csr.bin>] "
                 "[-p key-pair file name - PEM format <key_pair.pem>]"
                 "[-w optional, pwd of private key file name. If not exist, PEM should be entered manually.\n");

    UTIL_LOG_ERR("Parameters:\n");
    UTIL_LOG_ERR("--csr                  -c:\t @OUTPUT@ csr file name <csr.bin>\n");
    UTIL_LOG_ERR("--key-pair             -p:\t key-pair file name - PEM format <key_pair.pem>\n");
    UTIL_LOG_ERR(
        "--pwd                  -w:\t optional, pwd of private key file name. If not exist, PEM should be entered manually\n");
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

    // parse argument from command line, and initalize fields
    while (1) {
        ch = getopt_long(argc, argv, "c:p:w:H", main_long_options, &long_opt_index);

        if (ch == -1)
            break; // No more parameters
        switch (ch) {
        case 'c': // --csr
            strncpy(csrFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            csrFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("csrFileName %s\n", csrFileName);
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
        case 'H': // --help
            usage();
            break;
        }
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
int main(int argc, char *argv[])
{
    int rc                   = 0;
    int len                  = 0;
    int csrTotalSize         = 0;
    int csrBase64EncBuffSize = 0;

    /* parse command line arguments and files content */
    rc = parseArguments(argc, argv);
    if (rc != 0) {
        return rc;
    }
    csrBuff.token   = OEM_GEN_CSR_TOKEN;
    csrBuff.version = OEM_ASSET_VERSION;
    csrBuff.len     = sizeof(csrBuff);
    /* handle all crypto operations within OpenSSL_add_all_algorithms() and EVP_cleanup() */
    OpenSSL_add_all_algorithms();
    UTIL_LOG_INFO("calling SaSi_CommonGetNbuffFromKeyPair\n");
    len = RSA_OAEP_KEY_SIZE_IN_BYTES;
    rc  = SaSi_CommonGetNbuffFromKeyPair(keyPairFileName, pwdFilePtr, csrBuff.pubKey0, &len);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonGetNbuffFromKeyPair() for pubkey0, rc %d\n", rc);
        goto genCsrEnd;
    }

    UTIL_LOG_INFO("calling SaSi_CommonRsaSign\n");
    /* first RSA_PSS sign using privKey0 , then  encode base64    */
    rc = SaSi_CommonRsaSign(RSA_USE_PKCS_21_VERSION,                       /* RSA version */
                            (char *)&csrBuff,                              /* data */
                            sizeof(csrBuff) - sizeof(csrBuff.csrSign),     /* data size */
                            keyPairFileName, pwdFilePtr, csrBuff.csrSign); /* signature */
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonRsaSign() for csr, rc %d\n", rc);
        goto genCsrEnd;
    }
    UTIL_LOG_BYTE_BUFF("csrBuff", (unsigned char *)&csrBuff, sizeof(csrBuff));

    csrBase64EncBuffSize = sizeof(csrBase64EncBuff);
    UTIL_LOG_INFO("calling SaSi_CommonBase64Encode() for csr, size %d\n", csrBase64EncBuffSize);
    rc = SaSi_CommonBase64Encode((unsigned char *)&csrBuff, sizeof(csrBuff), csrBase64EncBuff, &csrBase64EncBuffSize);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonBase64Encode() for csr, rc %d\n", rc);
        goto genCsrEnd;
    }
    UTIL_LOG_BYTE_BUFF("csrBase64EncBuff", csrBase64EncBuff, sizeof(csrBase64EncBuff));

    rc = SaSi_CommonUtilCopyBuffToBinFile(csrFileName, csrBase64EncBuff, csrBase64EncBuffSize);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonUtilCopyBuffToBinFile()\n");
        goto genCsrEnd;
    }
    rc = 0;
genCsrEnd:
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data(); /* cleanup application specific data to avoid memory leaks. */
    return rc;
}
