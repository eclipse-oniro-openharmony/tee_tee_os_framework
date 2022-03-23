/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: header file of taload file
 * Author: BSP group
 * Create: 2020-01-17
 */
#ifndef __TALOAD_AUTH_H__
#define __TALOAD_AUTH_H__

#include "hi_type_dev.h"
#include "taload_verify.h"
#include "taload_debug.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define TALOAD_IMG_HEADER_CHECK(image_header) \
    (((image_header)->total_len <= TALOAD_TA_IMG_HEADER_LEN) || \
    ((image_header)->code_offset != TALOAD_TA_IMG_HEADER_LEN) || \
    ((image_header)->signature_len != TALOAD_SIGNATURE_LEN) || \
    ((image_header)->signed_image_len + (image_header)->code_offset != (image_header)->signature_offset))

typedef struct {
    hi_u32 image_type;
    hi_u32 struct_version;
    hi_u32 asym_alg;
    hi_u32 ta_owner_id;
    hi_u8  ta_owner[TALOAD_TA_OWNER_LEN];
    hi_u32 ta_owner_id_mask;
    hi_u8  reserved_0[TALOAD_TA_ROOT_HEADER_RESERVED_0];
    hi_u8  ta_root_pub_key_n[TALOAD_RSA_PUBLIC_KEY_N_LEN];
    hi_u8  ta_root_pub_key_e[TALOAD_RSA_PUBLIC_KEY_E_LEN];
    hi_u32 ta_root_pub_key_id;
    hi_u8  reserved_1[TALOAD_TA_ROOT_HEADER_RESERVED_1];
    hi_u8  signature[TALOAD_TA_ROOT_HEADER_SIGNATURE];
    hi_u32 ta_double_sign_en;
    hi_u8  reserved_2[TALOAD_TA_ROOT_HEADER_RESERVED_2];
    hi_u8  signature_ext[TALOAD_TA_ROOT_HEADER_SIGNATURE];
} ta_root_cert;

typedef struct {
    hi_u32 image_type;
    hi_u32 struct_version;
    hi_u32 asym_alg;
    hi_u32 ta_owner_id;
    hi_u8  ta_owner[TALOAD_TA_OWNER_LEN];
    hi_u32 segment_id;
    hi_u32 segment_id_mask;
    hi_u32 sec_version;
    hi_u32 reserved_0;
    hi_u8  ta_uuid[TALOAD_UUID_LEN];
    hi_u8  ta_protection_key[TALOAD_PROTECT_KEY_LEN];
    hi_u32 ta_id;
    hi_u32 root_key_cfg;
    hi_u32 ta_encrypted_flag;
    hi_u32 ta_signed_flag;
    hi_u32 ta_version_check_flag;
    hi_u32 auto_add_new_ta_flag;
    hi_u8  reserved_1[TALOAD_TA_HEADER_RESERVED_1];
    hi_u8  ta_pub_key_n[TALOAD_RSA_PUBLIC_KEY_N_LEN];
    hi_u8  ta_pub_key_e[TALOAD_RSA_PUBLIC_KEY_E_LEN];
    hi_u8  reserved_2[TALOAD_TA_HEADER_RESERVED_2];
    hi_u8  signature[TALOAD_TA_HEADER_SIGNATURE];
} ta_cert;

typedef struct {
    /* Magic Number: "Hisilicon_ADVCA_ImgHead_MagicNum" */
    hi_u8  magic_number[TALOAD_TA_IMG_HEADER_MAGINNUMBER];
    hi_u8  header_version[TALOAD_TA_IMG_HEADER_HEADERVERSION];
    hi_u32 total_len;
    hi_u32 code_offset;
    hi_u32 signed_image_len;
    hi_u32 signature_offset;
    hi_u32 signature_len;
    hi_u8  reserverd_0[TALOAD_TA_IMG_HEADER_RESERVED_0];
    hi_u32 sec_version;
    hi_u8  reserverd_1[TALOAD_TA_IMG_HEADER_RESERVED_1];
    hi_u32 crc32;
    /* private data below */
    hi_u32 image_type;
    hi_u32 segment_id;
    hi_u32 segment_id_mask;
    hi_u32 func_version;
    hi_u32 asym_alg;
    hi_u32 sym_alg;
    hi_u8  reserverd_2[TALOAD_TA_IMG_HEADER_RESERVED_2];
} ta_body_head;

typedef struct {
    /* Magic Number: "Hisilicon_ADVCA_ImgHead_MagicNum" */
    hi_u8  magic_number[TALOAD_TA_IMG_HEADER_MAGINNUMBER];
    hi_u8  header_version[TALOAD_TA_IMG_HEADER_HEADERVERSION];
    hi_u32 total_len;
    hi_u32 code_offset;
    hi_u32 signed_image_len;
    hi_u32 signature_offset;
    hi_u32 signature_len;
    hi_u8  reserverd_0[TALOAD_TA_IMG_HEADER_RESERVED_0];
    hi_u32 sec_version;
    hi_u8  reserverd_1[TALOAD_TA_IMG_HEADER_RESERVED_1];
    hi_u32 crc32;
    /* private data below */
    hi_u32 image_type;
    hi_u8 revo_list_protection_key[TALOAD_PROTECT_KEY_LEN];
    hi_u32 asym_alg;
    hi_u32 sym_alg;
    hi_u8  reserverd_2[TALOAD_REVO_LIST_IMG_HEADER_RESERVED];
} ta_revo_list_head;

typedef struct {
    hi_u32 item_len;
    hi_u32 ta_owner_id;
    hi_u8 ta_owner[TALOAD_TA_OWNER_LEN];
    hi_u32 key_type;
    hi_u32 key_len;
    hi_u32 key;
} revo_item;

typedef struct {
    hi_u32 list_len;
    hi_u32 struct_ver;
    hi_u32 item_num;
    revo_item revo_item[0];
} revo_list;

typedef union {
    struct {
        hi_u32 reserved               : 24; /* [23:0] */
        hi_u32 hrf_double_sign_en     : 4;  /* [27:24] */
        hi_u32 tee_double_sign_en     : 4;  /* [31:28] */
    } bits;
    hi_u32 u32;
} double_sign_en;                         /* Offset: 0x44 */

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /*__TALOAD_AUTH_H__*/
