/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: header file of vfmw_verify
 * Create: 2020-01-17
 */

#ifndef __TA_VFMW_VERIFY_H__
#define __TA_VFMW_VERIFY_H__

#include "hi_type_dev.h"
#include "tee_drv_vfmw_ioctl.h"
#include "hi_tee_errcode.h"
#include "hi_tee_drv_mem.h"
#include "hi_tee_mem.h"
#include "hi_tee_chip_task.h"
#include "hi_tee_cipher.h"
#include "hi_tee_drv_syscall_id.h"
#include "tee_internal_api.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "hmdrv.h"
#include "securec.h"

#define ta_vfmw_check_ret(cond, ret) \
    do { \
        if (!(cond)) { \
            tloge("[%s %d] Assert Warning: condition %s not match.\n", __func__, __LINE__, #cond); \
            return ret; \
        } \
    } while (0)

#define ta_vfmw_check_goto(cond, tag) \
    do { \
        if (!(cond)) { \
            tloge("[%s %d] Assert Warning: condition %s not match.\n", __func__, __LINE__, #cond); \
            goto tag; \
        } \
    } while (0)

#define ta_vfmw_prn(fmt, arg...) \
    do { \
        tloge(fmt, ##arg); \
    } while (0)

#define ta_vfmw_check_sec_func(func) \
    do { \
        if((func) != EOK) { \
            tloge("[%s %d] check err\n", __func__, __LINE__); \
        } \
    } while (0)

#define ta_vfmw_check_func(func) \
    do { \
        if((func) != HI_SUCCESS) { \
            tloge("[%s %d] check err\n", __func__, __LINE__); \
        } \
    } while (0)

#define VFMW_SG_CERT_STRUCT_VER              0x0
#define HISI_MAGIC_NUMBER                    "Hisilicon_ADVCA_ImgHead_MagicNum"
#define HISI_IMAGE_HEADER_VERSION            "v3.0.0.0"
#define VFMW_SG_CODE_OFFSET                  0x2000
#define VFMW_SG_IMAGE_TYPE                   0x3C786996
#define VFMW_SG_DOBULE_SIGN_OTP_ADDR         0x44
#define VFMW_SG_DOBULE_SIGN_OTP_DISABLE      0x0A
#define VFMW_SG_RSA2048                         0x0
#define VFMW_SG_SM2                             0x1
#define VFMW_SG_OWNER_LEN                       32
#define VFMW_SG_SM2_ID_LEN                      16
#define VFMW_SG_WORD_LEN                        32
#define VFMW_SG_SM2_DATA_LEN                    2
#define VFMW_SG_SIGNATURE_LEN                   256
#define VFMW_SG_PROTECT_KEY_LEN                 16
#define VFMW_SG_OWNER_LEN                       32
#define VFMW_SG_RSA_PUBLIC_KEY_E_LEN            4
#define VFMW_SG_RSA_PUBLIC_KEY_N_LEN            256
#define VFMW_SG_PAYLOAD_RESERVED_LEN            12
#define VFMW_SG_IV_LEN                          12

#define VFMW_SG_IMG_HEADER_LEN                  0x2000
#define VFMW_SG_PAY_LOAD_LEN                    256
#define VFMW_SG_PAY_LOAD_EXT_LEN                256
#define VFMW_SG_IMAGE_MIN_LEN                   (VFMW_SG_IMG_HEADER_LEN + VFMW_SG_PAY_LOAD_LEN + \
    VFMW_SG_PAY_LOAD_EXT_LEN + VFMW_IMAGE_MIN_LEN)
#define VFMW_SG_IMAGE_MAX_LEN                   0x200000

typedef enum {
    VFMW_SG_KLAD_TYPE_CATA   = 0,
    VFMW_SG_KLAD_TYPE_HISITA,
    VFMW_SG_KLAD_TYPE_STBTA,
    VFMW_SG_KLAD_TYPE_MAX
} vfmw_ta_klad_type;

typedef enum {
    VFMW_SG_DECRYPT_AES_CBC  = 0,
    VFMW_SG_DECRYPT_SM4_CBC,
    VFMW_SG_DECRYPT_AES_GCM,
    VFMW_SG_DECRYPT_MAX
} vfmw_decrypt_alg;

typedef union {
    struct {
        hi_u32 reserved               : 24; /* [23:0] */
        hi_u32 hrf_double_sign_en     : 4;  /* [27:24] */
        hi_u32 tee_double_sign_en     : 4;  /* [31:28] */
    } bits;
    hi_u32 u32;
} vfmw_double_sign_en;

hi_s32 vfmw_verify_signature(vfmw_verify *verify_info);
hi_s32 vfmw_verify_init(hi_void);
hi_void vfmw_verify_deinit(hi_void);
hi_s32 vfmw_verify_decrypt(vfmw_sign_head *fw_head, hi_mem_handle_t mem_fd, hi_mem_size_t addr_offset);

#endif /* __VFMW_SG_VERIFY_H__ */
