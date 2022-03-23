/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: header file of taload_verify
 * Author: BSP group
 * Create: 2020-01-17
 */
#ifndef __TALOAD_VERIFY_H__
#define __TALOAD_VERIFY_H__

#include "hi_type_dev.h"
#include "tee_drv_taload_ioctl.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define TALOAD_TA_ROOT_HEADER_RESERVED_0       204
#define TALOAD_TA_ROOT_HEADER_RESERVED_1       2296
#define TALOAD_TA_ROOT_HEADER_RESERVED_2       764
#define TALOAD_TA_ROOT_HEADER_SIGNATURE        256
#define TALOAD_TA_ROOT_CERT_IMAGE_TYPE         0x3C789678
#define TALOAD_TA_ROOT_CERT_STRUCT_VER         0x0

#define TALOAD_TA_HEADER_RESERVED_1            136
#define TALOAD_TA_HEADER_RESERVED_2            2300
#define TALOAD_TA_HEADER_SIGNATURE             256
#define TALOAD_TA_CERT_IMAGE_TYPE              0x3C789687
#define TALOAD_TA_CERT_STRUCT_VER              0x0

#define HISI_MAGIC_NUMBER                      "Hisilicon_ADVCA_ImgHead_MagicNum"
#define HISI_IMAGE_HEADER_VERSION              "v3.0.0.0"
#define HISI_REVO_LIST_HEADER_VERSION          "v2.1.0.0"

#define TALOAD_TA_IMG_HEADER_MAGINNUMBER       32
#define TALOAD_TA_IMG_HEADER_HEADERVERSION     8
#define TALOAD_TA_IMG_HEADER_RESERVED_0        44
#define TALOAD_TA_IMG_HEADER_RESERVED_1        124
#define TALOAD_TA_IMG_HEADER_RESERVED_2        7420
#define TALOAD_REVO_LIST_IMG_HEADER_RESERVED   7928

#define TALOAD_TAROOTCERT_IMG_SIZE             0x1000
#define TALOAD_TACERT_IMG_SIZE                 0x1000
#define TALOAD_TA_CODE_OFFSET                  0x2000
#define TALOAD_REVO_LIST_OFFSET                0x2000
#define TALOAD_TA_IMAGE_TYPE                   0x3C786996
#define TALOAD_REVO_LIST_IMAGE_TYPE            0x3C786987

#define TALOAD_TA_THIRD_PARTY_LEN              0x400
#define TALOAD_TA_OWNER_SIGNATURE_OFFSET       0xB00
#define TALOAD_DOBULE_SIGN_OTP_ADDR            0x44
#define TALOAD_DOBULE_SIGN_OTP_DISABLE         0x0A
#define TALOAD_TA_DOBULE_SIGN_DISABLE          0x3C7896E1
#define TALOAD_TA_ENCRYPTED_DISABLE            0x3C7896E1
#define TALOAD_TA_VERIFY_DISABLE               0x3C7896E1
#define TALOAD_REVO_LIST_DOBULE_SIGN_DISABLE   0x3C7896E1

#define TALOAD_RSA2048                         0x0
#define TALOAD_SM2                             0x1
#define TALOAD_TA_OWNER_LEN                    32
#define TALOAD_SM2_ID_LEN                      16
#define TALOAD_WORD_LEN                        32
#define TALOAD_SM2_DATA_LEN                    2

#define TALOAD_SIGNATURE_LEN                   256
#define TALOAD_TA_IMG_HEADER_MAGINNUMBER_LEN   32
#define TALOAD_TA_IMG_HEADER_HEADERVERSION_LEN 8
#define TALOAD_TA_IMG_HEADER_LEN               0x2000
#define TALOAD_TA_REVO_LIST_IMG_HEADER_LEN     0x2000
#define TALOAD_PROTECT_KEY_LEN                 16
#define TALOAD_TA_OWNER_LEN                    32
#define TALOAD_RSA_PUBLIC_KEY_E_LEN            4
#define TALOAD_RSA_PUBLIC_KEY_N_LEN            256
#define TALOAD_PROTECTION_KEY_LEN              16
#define TALOAD_UUID_LEN                        16
#define TALOAD_TA_NOT_SIGNED_TAG               0x3C7896E1
#define TALOAD_TA_NOT_ENCRYPTED_TAG            0x3C7896E1
#define TALOAD_TA_VERSION_CHECK_DISABLE        0x3C7896E1
#define TALOAD_TA_MSID_CHECK_DISABLE           0x3C7896E1
#define TALOAD_TA_UPDATE_TAG                   0x3C7896E1
#define TALOAD_UINT_MAX                        0xFFFFFFFF
#define TALOAD_TA_PAYLOAD_RESERVED_LEN         12
#define TALOAD_TA_PAYLOAD_TAIL_LEN             (sizeof(taload_ta_payload_tail))
#define TALOAD_IMG_MIN_SIZE (TALOAD_TAROOTCERT_IMG_SIZE + TALOAD_TACERT_IMG_SIZE + TALOAD_TA_IMG_HEADER_LEN)
#define TALOAD_TA_IV_LEN                       12

typedef enum {
    TALOAD_TA_KLAD_TYPE_CATA   = 0,
    TALOAD_TA_KLAD_TYPE_HISITA,
    TALOAD_TA_KLAD_TYPE_STBTA,
    TALOAD_TA_KLAD_TYPE_MAX
} taload_ta_klad_type;

typedef enum {
    TALOAD_TA_DECRYPT_AES_CBC  = 0,
    TALOAD_TA_DECRYPT_SM4_CBC,
    TALOAD_TA_DECRYPT_AES_GCM,
    TALOAD_TA_DECRYPT_MAX
} taload_decrypt_alg;

typedef struct {
    hi_u8 *verify_data;
    hi_u32 verify_data_len;
    hi_u8 *signature_data;
    hi_u32 signature_data_len;
    hi_u32 asym_alg;
    taload_rsa_key rsa_key;
} taload_verify;

typedef struct {
    hi_u8 reserved[TALOAD_TA_PAYLOAD_RESERVED_LEN];
    hi_u32 ta_owner_id;
    hi_u8 ta_owner[TALOAD_TA_OWNER_LEN];
    hi_u8 sig_header_cpy[TALOAD_SIGNATURE_LEN];
} taload_ta_payload_tail;

typedef struct {
    const hi_u8 *protect_key;
    hi_u32 decrypt_alg;
    hi_u32 root_key_cfg;
    hi_u32 ta_owner_id;
} decrypt_param;

hi_s32 taload_decrypt(const hi_u8 *buffer, hi_u32 size, const decrypt_param *param);
hi_s32 taload_verify_init(hi_void);
hi_s32 taload_verify_deinit(hi_void);
hi_s32 taload_verify_signature(const taload_verify *taload_verify_info);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /*__TALOAD_VERIFY_H__*/
