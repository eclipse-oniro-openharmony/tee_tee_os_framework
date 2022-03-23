/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: keymaster definitions
 * Create: 2012-01-17
 */
#ifndef __KM_DEFINES_H
#define __KM_DEFINES_H

#define HMAC_SIZE 32
#define KEY_MAX   16
#define TEE_KEYPAIR_RSA    1 /* *< RSA public and RSA private key. */
#define TEE_KEYPAIR_RSACRT 2 /* *< RSA public and RSA CRT private key. */

#define PARAM_COUNT 4
#define PARAM_ZERO  0
#define PARAM_ONE   1
#define PARAM_TWO   2
#define PARAM_THREE 3

#define PARAM_SIZE_TWO        2
#define TLV_NUM_FIVE          5
#define ATTEST_VERSION        2
#define KEYMASTER_VERSION     3

#define KM_NUM_THREE          3
#define KM_NUM_FOUR           4
#define KM_NUM_FIVE           5
#define KM_NUM_SIXE           6
#define KM_NUM_SEVEN          7

#define KM_NUM_NINE           9
#define KM_NUM_TEN            10
#define KM_NUM_ELEVEN         11
#define KM_NUM_TWELVE         12
#define KM_NUM_FOURTEEN       14
#define KM_NUM_ONE_HUNDRED    100
#define KM_NUM_ONE_THOUSAND   1000
#define RSA_SW_KEY_LEN        1024
#define KEY_BLOB_MAX_SIZE     0x1000

#define SHA256_LENGTH 32

#define IV_LEN       16
#define CERT_COUNT_MAX    5U
#define TEXT_TO_SIGN_SIZE 8
#define CBC_IV_LENGTH     16
#define SHA256_LENGTH     32

#define SIG_MAX_LEN       512
#define CHAIN_MAX_LEN     8192

#define AES_KEY_LEN  32
#define ECC_KEY_LEN  66
#define AES_KEY_SIZE_16    16
#define AES_KEY_SIZE_24    24
#define AES_KEY_SIZE_32    32

#define PARAM_NBR_TWO   2
#define PARAM_NBR_THREE 3

#define PARAM_NUM_TWO   2
#define PARAM_NUM_THREE 3

#define AES_KEY_LEN     32
#define TEE_KEYPAIR_RSA                1 /* RSA public and RSA private key. */
#define TEE_KEYPAIR_RSACRT             2 /* RSA public and RSA CRT private key. */
#define MAX_FILE_NAME_LEN              256U
#define KEYSTORE_PKGN                  "/system/bin/keystore"
#define VOLD_PKGN                      "/system/bin/vold"
#define VOLISNOTD_PKGN                 "/sbin/volisnotd"
#define ATCMDSERVER_PKGN               "/system/bin/atcmdserver"
#define ATCMDSERVER_PKGN_2             "/vendor/bin/atcmdserver"
#define ATCMDSERVER_PKGN_3             "/system/vendor/bin/atcmdserver"
#define KEYSTORE_HIDL_SERVICE_PKGN     "/vendor/bin/hw/android.hardware.keymaster@3.0-service"
#define KEYSTORE_HIDL_SERVICE_4_0_PKGN "/vendor/bin/hw/android.hardware.keymaster@4.0-service"

#define KEYSTORE_HIDL_SERVICE_UID 1000
#define KEYSTORE_UID              1017
#define VOLD_UID                  0
#define VOLISNOTD_UID             0
#define ATCMDSERVER_UID           0
#define ATTEST_UID                0
#define KMTEST_UID                0

#define CALL_FROM_TA            1
#define ACCESS_CHECK_VERIFY     1
#define ACCESS_CHECK_FROM_CA    0
#define ACCESS_CHECK_DELETE_KEY 2
#define ACCESS_CHECK_POLICY_SET 3
#define ACCESS_CHECK_OTHER      (-1)

#define HUDRED_PERCENT   100
#define SESSION_ID_COUNT 2

#define KM_MAX_PACKAGE_NAME_LEN 255

#define swap_32(x) \
    (((uint32_t)(x) << 24) | (((uint32_t)(x)&0xff00) << 8) | (((uint32_t)(x)&0x00ff0000) >> 8) | ((uint32_t)(x) >> 24))

#define be32(val)     swap_32(val)
#define ntoh(n)       be32(n)
#define hton(h)       be32(h)
#define SEC_TO_MILLIS 1000
#define VAR_SHIFT_32  32
/* For TeeUpdate interface , input data size max is 512k */
#define FIXED_CHUNKSIZE_CA 0x80000

#define KM_NUM_TWO         2
#define KM_NUM_THREE       3
#define KM_NUM_FOUR        4
#define KM_NUM_FIVE        5
#define KM_NUM_SIXE        6
#define KM_NUM_SEVEN       7
#define KM_NUM_EIGHT       8
#define KM_NUM_NINE        9
#define KM_NUM_TEN         10
#define KM_NUM_THIRTY_TWO  32
#define KM_NUM_SIXTY_FOUR  64
#define KM_NUM_ONE_HUNDRED 100

#define HMAC_MAX_KEY_SIZE_BITS 1024

#define KM_TLV_LEN_ONEBYTE   0x80
#define KM_TLV_LEN_TWOBYTE   0x81
#define KM_TLV_LEN_THREEBYTE 0x82
#define KM_SPACE_CHAR        0x00

#define KM_TLV_VALUE_LEN128 0x80
#define KM_TLV_VALUE_LEN256 0x100
#define MAX_TRY_GENERATE_KEY_TIME                       10
#define DES_ONE_KEY_LEN                                 8
#define KM_3DES_KEY_SIZE                                32

#define HEAD_FIRST_CHAR    0
#define HEAD_SECOND_CHAR   1
#define VALID_PADDING_CHAR 0xff
#define DIGEST_START_CHAR  0
#define HARDWARE_ERROR     0x00F00414
#define IV_LEN               16
#define IV_LEN_TWELVE        12
#define MAX_TAG_LEN          128
#define MIN_TAG_LEN          96
#define HASH_BITS_TWO        2
#define HASH_BITS_SIZE       16

#define HMAC_SIZE         32
#define KM_MAGIC_NUM         0x48494B4D /* "HIKM" hisi keymaster in hex */

#define GENERATE_HMAC                 0
#define CHECK_ORIGINAL_LOCK_COLOR     1
#define CHECK_ADAPTABLE_LOCK_COLOR    2
#define NO_NEED_CHECK_ADAPTABLE_COLOR 0
#define NEED_CHECK_ADAPTABLE_COLOR    1

#define COLOR_SHMEM_TOTAL_SIZE 0x1ff
#define COLOR_LOCK_STATE_SIZE  0xA
#define COLOR_LOCK_COLOR_SIZE  0xA
#define PUBLIC_KEY_SIZE        0x100
#define OS_VERSION_SIZE        0x4

#define GP_CRT_MODE 1
#define GP_NOCRT_MODE 0
#define EXCLUED_PRODUCT                                 "NEXT"
#define PRODUCT_NAME_LEN                                32
#define FINAL_INPUT                                     0
#define FINAL_SIG                                       1
#define RSA_4096_CTS_HELP                               0x49501627
#define HEAD_NUM                                        2
#define MIN_MSG_LEN                                     8
#define BITS_UP_BYTE_BASE                               7
#define BITS_ONE_BYTE                                   8
#define RSA_PKCS1_PADDING_SIZE                          11
#define BYTES_ONE_WORD                                  4
#define MAX_RSA_CRYPTO_DATA                             4096
#define HEAD_INCLUDE_FF_LEN                             3
#define FUNC_SHIFT                                      2
#define CTX_BUFF_SIZE_IN_WORD                           (sizeof(gcm_state) / 4 + 2)
#define CRYS_AES_KEY_SIZE                               64
#define CRYS_AES_IV_SIZE                                16
#define HASH_BLOCK_SIZE_64                              64
#define HASH_BLOCK_SIZE_128                             128
#define PKCS7_PADDING_SIZE                              16
#define KEY_SIZE_512                                    512
#define AAD_DATA_BLOCK_SIZE                             16
#define BYTES_INT64                                     8
#define VER_YEAR_SHIFT_NUM                              4
#define VER_YEAR_BASE_NUM                               2000
#define PATCH_LEVER_SHIFT                               100
#define BASE_NUM_TWO                                    2
#define RSA_PARAM_NUM                                   8
#define CTX_CLEAN_GCM                                   1
#define CTX_CLEAN_HASH                                  2
#define get_low_32bits(n)                                ((n) & 0x00000000ffffffff)
#define get_high_32bits(n)                              ((n) >> 32)
#define min_oaep_padding_outsize(module_size, hash_len) ((module_size)-2 * (hash_len)-2)
#define four_bytes_align_up(offset)                     (((offset) + 3) / 4 * 4)
#define eight_align_up(offset)                    (((offset) + 7) / 8 * 8)
#define min_module_len_cc(hash_len)                     ((hash_len) + 2)

#define DX_2048_MAX_SIZE_IN_WORDS 66
#define DX_3072_MAX_SIZE_IN_WORDS 98
#define KEY_MAX_SIZE              64
#define KM_MAGIC_NUM              0x48494B4D /* "HIKM" hisi keymaster in hex */
#define HMAC_SIZE                 32
#define AES_BLOCK_SIZE_IN_BYTES   16U
#define PKCS7_PADDING_LEN         16
#define PKCS7_PADDING_LEN_DES     8
#define MAX_RSA_8192_BYTES        1024
#define ATTRIBUTE_COUNT_ONE 1ul
#define HMAC_MAX_KEY_SIZE_BITS 1024
#define DES3_IV_LEN 8
#define DES3_BLOCKS 8

#define MAX_ECDSA_KEYPAIR_SIZE 521
#define MAX_KEY_BUFFER_LEN 4096
#define MAX_INSE_FACTOR_LEN 64U

/* software engine ECC domain id */
#define NIST_P192                                       0
#define NIST_P224                                       1
#define NIST_P256                                       2
#define NIST_P384                                       3
#define NIST_P521                                       4

/* software engine ecc pub key max len */
#define ECC_PUB_LEN 66
#define RSA_CRT_ATTR_CNT 8
#define RSA_NOCRT_ATTR_CNT 3
#define RSA_CRT_ATTR_PRIV_EXP_INDEX 2

#define EC_ATTR_CNT 4
#define BUF_OR_VALUE_MOVEBIT 2
#define IF_ZERO_MOVEBIT 31
#define OBJECT_ATTR_BUFFER 0
#define object_attr_type(attr_id) (((attr_id) << BUF_OR_VALUE_MOVEBIT) >> IF_ZERO_MOVEBIT)

#define ALG_EC    0
#define ALG_RSA   1
#define ALG_COUNT 2

#define STORE_RPMB 0
#define STORE_SFS  1

#define SRC_GOOGLE 0
#define SRC_HUAWEI 1

#define FILE_TYPE_PRVKEY 0
#define FILE_TYPE_CERT   1

#define ATTEST_CHALLENGE_LEN_MAX 128
#define UNIQUE_ID_BUF_LEN        16
#define ATTEST_ROT_BUF_LEN       128
#define AUTH_LIST_BUF_LEN        512
#define ATTEST_EXT_BUF_LEN       2048
#define ATTEST_CERT_BUF_LEN      4096
#define PUBKEY_DER_LEN           1024
#define SECS_PER_30_DAYS         2592000U

#define LENGTH_32L 4
#define LENGTH_64L 8

#define KM_PURPOSE_MAX 5
#define KM_DIGEST_MAX  7
#define KM_PADDING_MAX 6
#define KM_REP_MAX     10
#define KM_REP_BUF_LEN 128

#define AT_SUCCESS            0
#define AT_WB_DECRYPT_ERR     (-1)
#define AT_TLV_BUF_INVALID    (-2)
#define AT_TLV_DECODE_ERR     (-3)
#define AT_HASH_CHECK_ERR     (-4)
#define AT_SFS_READ_ERR       (-5)
#define AT_SFS_WRITE_ERR      (-6)
#define AT_SIGN_HASH_ERR      (-7)
#define AT_SIGN_ERR           (-8)
#define AT_FILE_NAME_ERROR    (-9)
#define AT_COMPARE_FILE_ERROR (-10)
#define AT_FILE_SIZE_ERROR    (-11)
#define AT_CHAIN_OUT_ERR      (-12)
#define AT_X509_VERIFY_ERR    (-13)
#define AT_SIG_VERIFY_ERR     (-14)
#define AT_EVP_DIGEST_ERR     (-15)
#define AT_VINFO_GET_ERR      (-16)
#define AT_BASE64_DECODE_ERR  (-17)
#define AT_MEM_ERR            (-18)
#define AT_KEYBOX_INVALID     (-19)
#endif
