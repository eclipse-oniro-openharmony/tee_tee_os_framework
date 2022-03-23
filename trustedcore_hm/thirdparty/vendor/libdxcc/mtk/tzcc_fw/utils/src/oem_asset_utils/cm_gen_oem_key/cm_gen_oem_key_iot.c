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
#define OEM_ASSET_KCP_KEY_BUFF_SIZE 16
#define CMAC_LABEL_SIZE             4
#define CMAC_ADDITIONAL_DATA_SIZE   3
#define CMAC_DATA_IN_SIZE           (OEM_ASSET_MAX_HBK_BUFF_SIZE + CMAC_LABEL_SIZE + CMAC_ADDITIONAL_DATA_SIZE)

static unsigned char kcpFileName[UTIL_MAX_FILE_NAME] = "kcp.bin";

static unsigned char csrFileName[UTIL_MAX_FILE_NAME]                                       = "csr.bin";
static unsigned char csrBase64Buff[SASI_COMMON_CALC_BASE64_ENCODE_SIZE(sizeof(CsrBuff_t))] = { 0 };
static CsrBuff_t csrBuff                                                                   = { 0 };

static unsigned char cpKeyBuff[OEM_ASSET_KCP_KEY_BUFF_SIZE] = { 0 };
static unsigned char hbkBuff[OEM_ASSET_MAX_HBK_BUFF_SIZE]   = { 0 };

static unsigned char oemKeyFileName[UTIL_MAX_FILE_NAME]                                              = "oem_key.bin";
static unsigned char oemKeyBuff[SASI_UTIL_KOEM_SIZE_IN_BYTES]                                        = { 0 };
static EncOemKeyBuff_t oemKeyRsa                                                                     = { 0 };
static unsigned char oemKeyRsaBase64Buff[SASI_COMMON_CALC_BASE64_ENCODE_SIZE(ENC_OEM_KEY_BUFF_SIZE)] = { 0 };

static struct option main_long_options[] = {
    { "csr", required_argument, 0, 'c' },
    { "oem-key", required_argument, 0, 'o' },
    { "kcp", required_argument, 0, 'r' },
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
                 "[-o @OUTPUT@ oem key file name <oem_key.bin>]"
                 "[-r kcp file name <kcp.bin>]\n");

    UTIL_LOG_ERR("Parameters:\n");
    UTIL_LOG_ERR("--csr                  -c:\t csr binary file <csr.bin>\n");
    UTIL_LOG_ERR("--oem-key              -o:\t @OUTPUT@ oem key file name <oem_key.bin>\n");
    UTIL_LOG_ERR("--kcp                  -r:\t kcp binary file <kcp.bin>\n");
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
    int rc = 0;

    unsigned int kcpBuffSize       = 0;
    unsigned int csrBase64BuffSize = 0;

    // parse argument from command line, and initalize fields
    while (1) {
        ch = getopt_long(argc, argv, "c:o:r:H", main_long_options, &long_opt_index);

        if (ch == -1)
            break; // No more parameters
        switch (ch) {
        case 'c': // --csr
            strncpy(csrFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            csrFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("csrFileName %s\n", csrFileName);
            break;
        case 'o': // --oem-key
            strncpy(oemKeyFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            oemKeyFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("oemKeyFileName %s\n", oemKeyFileName);
            break;
        case 'r': // --kcp
            strncpy(kcpFileName, optarg, UTIL_MAX_FILE_NAME - 1);
            kcpFileName[UTIL_MAX_FILE_NAME - 1] = '\0';
            UTIL_LOG_INFO("kcpFileName %s\n", kcpFileName);
            break;
        case 'H': // --help
            usage();
            break;
        }
    }

    /* read data from files */
    /* read csr binary file */
    csrBase64BuffSize = sizeof(csrBase64Buff);
    rc                = SaSi_CommonUtilCopyDataFromBinFile(csrFileName, csrBase64Buff, &csrBase64BuffSize);
    if ((rc != 0) || (csrBase64BuffSize != (sizeof(csrBase64Buff)))) {
        UTIL_LOG_ERR("failed parse csr file, rc %d, csr Size %d\n", rc, csrBase64BuffSize);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("csrBase64Buff", csrBase64Buff, csrBase64BuffSize);

    /* read kcp binary file */
    kcpBuffSize = sizeof(cpKeyBuff);
    rc          = SaSi_CommonUtilCopyDataFromBinFile(kcpFileName, cpKeyBuff, &kcpBuffSize);
    if ((rc != 0) || (kcpBuffSize > sizeof(cpKeyBuff))) {
        UTIL_LOG_ERR("failed parse kcp file, rc %d, kcp size %d\n", rc, kcpBuffSize);
        return 1;
    }
    UTIL_LOG_BYTE_BUFF("cpKeyBuff", cpKeyBuff, kcpBuffSize);

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

    /* compute  hbkBuff  */
    /* compute  hbkBuff on key0 */
    rc = SaSi_CommonCalcHBKFromBuff(csrBuff.pubKey0, hbkBuff, sizeOfHash);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonCalcHBKFromBuff %d for pubKey0\n", rc);
        return 1;
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
    int rc                                      = 0;
    int oemKeyRsaBase64BuffSize                 = 0;
    unsigned char cmacLabel[CMAC_LABEL_SIZE]    = { 0x4B, 0x4F, 0x45, 0x4D }; // "KOEM"
    unsigned char cmacDataIn[CMAC_DATA_IN_SIZE] = { 0x0 };

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

    /* Derives OEM key  according to NIST SP800-108 sec #5.1  , CMAC    *
     *  Koem = AES-CMAC(key=KCP, data=  0x1 + "KOEM" + 0x0 +PubKeyHash + 0x80) */
    // preparing DataIn
    cmacDataIn[0] = 0x1;
    memcpy(&cmacDataIn[1], cmacLabel, sizeof(cmacLabel));
    cmacDataIn[1 + sizeof(cmacLabel)] = 0x0;
    memcpy(&cmacDataIn[1 + sizeof(cmacLabel) + 1], hbkBuff, sizeof(hbkBuff));
    cmacDataIn[sizeof(cmacDataIn) - 1] = 0x80;

    rc = SaSi_CommonAesCmacEncrypt(cmacDataIn, sizeof(cmacDataIn), cpKeyBuff, sizeof(cpKeyBuff), oemKeyBuff);
    if (rc != 0) {
        UTIL_LOG_ERR("failed to SaSi_CommonAesCmacEncrypt() for oemKeyBuff rc %d\n", rc);
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
