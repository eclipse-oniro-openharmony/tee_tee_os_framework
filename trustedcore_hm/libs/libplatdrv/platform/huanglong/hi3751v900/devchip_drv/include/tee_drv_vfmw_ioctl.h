/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: decoder
 * Author: sdk
 * Create: 2020-06-06
 */

#ifndef __TEE_DRV_VFMW_IOCTL_H__
#define __TEE_DRV_VFMW_IOCTL_H__

#include "hi_type_dev.h"
#include "hi_tee_module_id.h"

#define VFMW_IMAGE_MIN_LEN              0x80000
#define VFMW_IMAGE_MAX_LEN              0x200000

#define VFMW_RSA_PUBLIC_KEY_N_LEN       256
#define VFMW_RSA_PUBLIC_KEY_E_LEN       4
#define VFMW_PROTECTION_KEY_LEN         16
#define VFMW_SIGN_MAGIC_NUM_LEN         32
#define VFMW_SIGN_HEAD_VER_LEN          8
#define VFMW_SG_HEADER_RESERVED_0       44
#define VFMW_SG_HEADER_RESERVED_1       124
#define VFMW_SG_HEADER_RESERVED_2       7928

typedef enum {
    VFMW_SG_IOCTL_GET_EXT_PUB_KEY  = 0,
    VFMW_SG_IOCTL_COPY_BIN,
    VFMW_SG_IOCTL_GET_SIGN_INFO,
    VFMW_SG_IOCTL_MAX
} vfmw_ta_ioctl;

typedef struct {
    hi_u8  magic_number[VFMW_SIGN_MAGIC_NUM_LEN];
    hi_u8  header_version[VFMW_SIGN_HEAD_VER_LEN];
    hi_u32 total_len;
    hi_u32 code_offset;
    hi_u32 signed_image_len;
    hi_u32 signature_offset;
    hi_u32 signature_len;
    hi_u8  reserverd_0[VFMW_SG_HEADER_RESERVED_0];
    hi_u32 sec_version;
    hi_u8  reserverd_1[VFMW_SG_HEADER_RESERVED_1];
    hi_u32 crc32;
    hi_u32 image_type;
    hi_u8 revocation_protection_key[VFMW_PROTECTION_KEY_LEN];
    hi_u32 asym_algorithm;  /* 0: RSA2048 1: SM2 */
    hi_u32 sym_algorithm;
    hi_u8  reserverd_2[VFMW_SG_HEADER_RESERVED_2];
} vfmw_sign_head;

typedef struct {
    hi_u8 rsa_key_n[VFMW_RSA_PUBLIC_KEY_N_LEN];
    hi_u8 rsa_key_e[VFMW_RSA_PUBLIC_KEY_E_LEN];
} vfmw_rsa_key;

typedef struct {
    hi_u8 *verify_data;
    hi_u32 verify_data_len;
    hi_u8 *signature_data;
    hi_u32 signature_data_len;
    hi_u32 asym_alg;
    vfmw_rsa_key rsa_key;
} vfmw_verify;

typedef struct {
    hi_bool opt_double_sign_en;
    hi_bool double_sign_en;
    vfmw_rsa_key rsa_key;
} vfmw_sign_third;

typedef struct {
    hi_mem_handle_t mem_fd;
    hi_u32 fw_total_len; /* contain: head - payload - sign */
    vfmw_sign_head *fw_head;
    hi_void *fw_payload;
    vfmw_verify *verify_para;
    vfmw_sign_third third;
} vfmw_sign_info;

#endif /* End of #ifndef __DRV_TALOAD_IOCTL_H__ */
