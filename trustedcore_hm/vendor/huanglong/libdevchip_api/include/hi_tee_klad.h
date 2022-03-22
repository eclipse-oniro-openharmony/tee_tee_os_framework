/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define API about key ladder driver
 * Author: Linux SDK team
 * Create: 2019-7-25
 */
#ifndef __HI_TEE_KLAD_H__
#define __HI_TEE_KLAD_H__

#include "hi_type_dev.h"
#include "hi_tee_security.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/* ************************** Structure Definition *************************** */
/* \addtogroup      KLAD */
/* @{ */  /** <!-- [KLAD] */

typedef enum {
    HI_TEE_ROOTKEY_NULL  = 0x0,
    HI_TEE_ROOTKEY_CSA2  = 0x1,
    HI_TEE_ROOTKEY_CSA3  = 0x2,
    HI_TEE_ROOTKEY_AES   = 0x3,
    HI_TEE_ROOTKEY_TDES  = 0x4,
    HI_TEE_ROOTKEY_SM4   = 0x5,
    HI_TEE_ROOTKEY_MISC  = 0x6,
    HI_TEE_ROOTKEY_R2R   = 0x7,
    HI_TEE_ROOTKEY_HDCP  = 0x8,
    HI_TEE_ROOTKEY_DCAS  = 0x9,
    HI_TEE_ROOTKEY_DYM   = 0xFF,
} hi_tee_rootkey_type;

/*
 * Keyladder type list
 */
typedef enum {
    HI_TEE_KLAD_COM   = 0x10,
    HI_TEE_KLAD_TA    = 0x11,
    HI_TEE_KLAD_FP    = 0x12,
    HI_TEE_KLAD_NONCE = 0x13,
    HI_TEE_KLAD_CLR   = 0x14,
} hi_tee_klad_type;

#define hi_tee_klad_instance(ca, rk, klad, id) \
    ((((ca) << 24) & 0xFF000000) + (((rk) << 16) & 0xFF0000) + (((klad) << 8) & 0xFF00)+ (id))

#define HI_TEE_CA_ID_BASIC               0x80

/*
 * Clear route keyladder
 */
#define HI_TEE_KLAD_TYPE_CLEARCW     hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_NULL, HI_TEE_KLAD_CLR, 0x01)

/*
 * Dynamic keyladder, it can be customized
 */
#define HI_TEE_KLAD_TYPE_DYNAMIC    hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_DYM, HI_TEE_KLAD_COM, 0x01)

/*
 * OEM TA keyladder
 * 1 stage keyladder
 * Keyladder algorithm use AES, target engine is MCipher and target engine algorithm is AES.
 */
#define HI_TEE_KLAD_TYPE_OEM_TA     hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_R2R, HI_TEE_KLAD_COM, 0x02)

/*
 * HISI TA keyladder
 * 1 stage keyladder
 * Keyladder algorithm use AES, target engine is MCipher and target engine algorithm is AES.
 */
#define HI_TEE_KLAD_TYPE_HISI_TA    hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_R2R, HI_TEE_KLAD_COM, 0x03)

/*
 * CA TA keyladder
 * 1 stage keyladder
 * Keyladder algorithm use AES, target engine is MCipher and target engine algorithm is AES.
 */
#define HI_TEE_KLAD_TYPE_CA_TA      hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_R2R, HI_TEE_KLAD_COM, 0x04)

/*
 * VMCU keyladder
 * 1 stage keyladder
 * Keyladder algorithm use AES, target engine is MCipher and target engine algorithm is AES.
 */
#define HI_TEE_KLAD_TYPE_VMCU       hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_R2R, HI_TEE_KLAD_COM, 0x06)

/*
 * CSA2 keyladder
 * 2 stage keyladder
 * Keyladder algorithm use AES/TDES/SM4, target engine is TSCIPHER and target engine algorithm is CSA2.
 */
#define HI_TEE_KLAD_TYPE_CSA2   hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_CSA2, HI_TEE_KLAD_COM, 0x01)

/*
 * CSA3 keyladder
 * 2 stage keyladder
 * Keyladder algorithm use AES/TDES/SM4, target engine is TSCIPHER and target engine algorithm is CSA3.
 */
#define HI_TEE_KLAD_TYPE_CSA3   hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_CSA3, HI_TEE_KLAD_COM, 0x01)

/*
 * R2R keyladder
 * 2 stage keyladder
 * Keyladder algorithm use AES/TDES/SM4, target engine is MCipher and target engine algorithm is AES/TDES/SM4.
 */
#define HI_TEE_KLAD_TYPE_R2R    hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_R2R, HI_TEE_KLAD_COM, 0x01)

/*
 * SP keyladder
 * 2 stage keyladder
 * Keyladder algorithm use AES/TDES/SM4, target engine is TSCIPHER and target engine algorithm is AES.
 */
#define HI_TEE_KLAD_TYPE_SP     hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_AES, HI_TEE_KLAD_COM, 0x01)

/*
 * MISC keyladder
 * 2 stage keyladder
 * Keyladder algorithm use AES/TDES/SM4, target engine is TSCIPHER and target engine algorithm is CSA2/CSA3/AES/TDES.
 */
#define HI_TEE_KLAD_TYPE_MISC   hi_tee_klad_instance(HI_TEE_CA_ID_BASIC, HI_TEE_ROOTKEY_MISC, HI_TEE_KLAD_COM, 0x01)

/* Define the maximum session key level */
#define HI_TEE_SESSION_KEY_MAX_LEVEL 0x04

/* Define the maximum key length. */
#define HI_TEE_KLAD_MAX_KEY_LEN      32

/* Define the key security attribute. */
typedef enum {
    HI_TEE_KLAD_SEC_ENABLE = 0,
    HI_TEE_KLAD_SEC_DISABLE,
    HI_TEE_KLAD_SEC_MAX
} hi_tee_klad_sec;

/* Define the keyladder algorithm. */
typedef enum {
    HI_TEE_KLAD_ALG_TYPE_DEFAULT   = 0, /* Default value */
    HI_TEE_KLAD_ALG_TYPE_TDES      = 1,
    HI_TEE_KLAD_ALG_TYPE_AES,
    HI_TEE_KLAD_ALG_TYPE_SM4,
    HI_TEE_KLAD_ALG_TYPE_MAX
} hi_tee_klad_alg_type;

/* Define the keyladder level. */
typedef enum {
    HI_TEE_KLAD_LEVEL1 = 0,
    HI_TEE_KLAD_LEVEL2,
    HI_TEE_KLAD_LEVEL3,
    HI_TEE_KLAD_LEVEL4,
    HI_TEE_KLAD_LEVEL5,
    HI_TEE_KLAD_LEVEL6,
    HI_TEE_KLAD_LEVEL_MAX
} hi_tee_klad_level;

/* Define the structure of keyladder configuration. */
typedef struct {
    hi_u32 owner_id;          /* Keyladder owner ID. Different keyladder have different ID. */
    hi_u32 klad_type;         /* Keyladder type. */
} hi_tee_klad_config;

/* Define the structure of content key configurations. */
typedef struct {
    hi_bool decrypt_support;         /* The content key can be used for decrypting. */
    hi_bool encrypt_support;         /* The content key can be used for encrypting. */
    hi_tee_crypto_alg engine;        /* The content key can be used for which algorithm of the crypto engine. */
} hi_tee_klad_key_config;

/* Define the structure of content key security configurations. */
typedef struct {
    hi_tee_klad_sec key_sec;
    hi_bool dest_buf_sec_support;     /* The destination buffer of target engine can be secure. */
    hi_bool dest_buf_non_sec_support; /* The destination buffer of target engine can be non-secure. */
    hi_bool src_buf_sec_support;      /* The source buffer of target engine can be secure. */
    hi_bool src_buf_non_sec_support;  /* The source buffer of target engine can be non-secure. */
} hi_tee_klad_key_secure_config;

/* Structure of keyladder extend attributes. */
typedef struct {
    hi_tee_klad_config klad_cfg;               /* The keyladder configuration. */
    hi_tee_klad_key_config key_cfg;            /* The content key configuration. */
    hi_tee_klad_key_secure_config key_sec_cfg; /* The content key security configuration. */
} hi_tee_klad_attr;

/* Structure of setting session key. */
typedef struct {
    hi_tee_klad_level level;            /* The level of session key. */
    hi_tee_klad_alg_type alg;           /* The algorithm used to decrypt session key. */
    hi_u32 key_size;                    /* The size of session key. */
    hi_u8 key[HI_TEE_KLAD_MAX_KEY_LEN]; /* The session key. */
} hi_tee_klad_session_key;

/* Structure of setting content key. */
typedef struct {
    hi_bool odd;                        /* Odd or Even key flag. */
    hi_tee_klad_alg_type alg;           /* The algorithm of the content key. */
    hi_u32 key_size;                    /* The size of content key. */
    hi_u8 key[HI_TEE_KLAD_MAX_KEY_LEN]; /* The content key. */
} hi_tee_klad_content_key;

/* Structure of sending clear key. */
typedef struct {
    hi_bool odd;                        /* Odd or Even key flag. */
    hi_u32 key_size;                    /* The size of content key. */
    hi_u8 key[HI_TEE_KLAD_MAX_KEY_LEN]; /* The content key. */
} hi_tee_klad_clear_key;

/* Structure of generating keyladder key. */
typedef struct {
    hi_tee_klad_alg_type alg;               /* The algorithm of the content key. */
    hi_u32 key_size;                        /* The size of content key. */
    hi_u8 key[HI_TEE_KLAD_MAX_KEY_LEN];
    hi_u32 gen_key_size;                    /* The size of generated key. */
    hi_u8 gen_key[HI_TEE_KLAD_MAX_KEY_LEN];
} hi_tee_klad_gen_key;

/* Structure of setting Nonce keyladder key. */
typedef struct {
    hi_tee_klad_alg_type alg;             /* The algorithm of the content key. */
    hi_u32 key_size;                      /* The size of content key. */
    hi_u8 key[HI_TEE_KLAD_MAX_KEY_LEN];
    hi_u32 nonce_size;                    /* The size of nonce key. */
    hi_u8 nonce[HI_TEE_KLAD_MAX_KEY_LEN]; /* The size of nonce key. */
} hi_tee_klad_nonce_key;

/* Rootkey slot. */
typedef enum {
    HI_TEE_BOOT_ROOTKEY_SLOT   = 0x0,
    HI_TEE_HISI_ROOTKEY_SLOT   = 0x1,
    HI_TEE_OEM_ROOTKEY_SLOT    = 0x2,
    HI_TEE_CAS_ROOTKEY_SLOT0   = 0x10,
    HI_TEE_CAS_ROOTKEY_SLOT1   = 0x11,
    HI_TEE_CAS_ROOTKEY_SLOT2   = 0x12,
    HI_TEE_CAS_ROOTKEY_SLOT3   = 0x13,
    HI_TEE_CAS_ROOTKEY_SLOT4   = 0x14,
    HI_TEE_CAS_ROOTKEY_SLOT5   = 0x15,
    HI_TEE_CAS_ROOTKEY_SLOT6   = 0x16,
    HI_TEE_CAS_ROOTKEY_SLOT7   = 0x17,
    HI_TEE_ROOTKEY_SLOT_MAX
} hi_tee_rootkey_select;

/* Configure crypto engine type. */
typedef struct {
    hi_bool mcipher_support;  /* Support send key to Mcipher or not. */
    hi_bool tscipher_support; /* Support send key to TScipher(TSR2RCipher and Demux) or not. */
} hi_tee_rootkey_target;

/* Configure crypto engine algorithm. */
typedef struct {
    hi_bool sm4_support;      /* Target engine support SM4 algorithm or not. */
    hi_bool tdes_support;     /* Target engine support TDES algorithm or not. */
    hi_bool aes_support;      /* Target engine support AES algorithm or not. */

    hi_bool csa2_support;     /* Target engine support CSA2 algorithm or not. */
    hi_bool csa3_support;     /* Target engine support CSA3 algorithm or not. */
    hi_bool hmac_sha_support; /* Target engine support HMAC SHA or not. */
    hi_bool hmac_sm3_support; /* Target engine support HMAC SM3 or not. */
} hi_tee_rootkey_target_alg;

/* Configure target engine features. */
typedef struct {
    hi_bool encrypt_support;  /* Target engine support encrypt or not. */
    hi_bool decrypt_support;  /* Target engine support decrypt or not. */
} hi_tee_rootkey_target_feature;

/* Configure keyladder algorithm. */
typedef struct {
    hi_bool sm4_support;      /* Keyladder support SM4 algorithm or not. */
    hi_bool tdes_support;     /* Keyladder support TDES algorithm or not. */
    hi_bool aes_support;      /* Keyladder support AES algorithm or not. */
} hi_tee_rootkey_alg;

/* Configure keyladder stage. */
typedef enum {
    HI_TEE_ROOTKEY_LEVEL1 = 0,  /* Keyladder support 1 stage. */
    HI_TEE_ROOTKEY_LEVEL2,      /* Keyladder support 2 stage. */
    HI_TEE_ROOTKEY_LEVEL3,      /* Keyladder support 3 stage. */
    HI_TEE_ROOTKEY_LEVEL4,      /* Keyladder support 4 stage. */
    HI_TEE_ROOTKEY_LEVEL5,      /* Keyladder support 5 stage. */
    HI_TEE_ROOTKEY_LEVEL_MAX
} hi_tee_rootkey_level;

/* Structure of Rootkey attributes. */
typedef struct {
    hi_tee_rootkey_select rootkey_sel; /* Rootkey slot select. */
    hi_tee_rootkey_target target_support;                 /* Crypto engine select. */
    hi_tee_rootkey_target_alg target_alg_support;         /* Crypto engine algorithm. */
    hi_tee_rootkey_target_feature target_feature_support;
    hi_tee_rootkey_level level;                           /* Keyladder stage. */
    hi_tee_rootkey_alg alg_support;                       /* Keyladder algorithm. */
} hi_tee_rootkey_attr;

/*
\brief Declare keyladder callback function interface
\param[in] err_code     Return error code.
\param[in] args         Receive buffer.
\param[in] size         The length of cArgs.
\param[in] user_data    User private data.
\param[in] user_data_len    User private data length.
*/
typedef hi_s32(*hi_tee_klad_func)(hi_s32 err_code, hi_char *args, hi_u32 size,
                                  hi_void *user_data, hi_u32 user_data_len);

/* Define cb descriptor */
typedef struct {
    hi_tee_klad_func done_callback; /* Keyladder callback function interface */
    hi_void *user_data;         /*  user private data */
    hi_u32  user_data_len;      /*  user private data length */
} hi_tee_klad_done_callback;

/* @} */  /* <!-- ==== Structure Definition end ==== */

/* ****************************** API Declaration **************************** */
/* \addtogroup      KLAD */
/* @{ */  /** <!--[KLAD] */

/*
\brief Initialize the key ladder device.
\param  None
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
*/
hi_s32 hi_tee_klad_init(hi_void);

/*
\brief Terminate and clean the key ladder device.
\param  None
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
*/
hi_s32 hi_tee_klad_deinit(hi_void);

/*
\brief Create handle of key ladder.
\param[out] phKlad  Handle of key ladder.
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_create(hi_handle *klad);

/*
\brief Destroy key ladder handle.
\param[in] klad  Handle of key ladder.
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_destroy(hi_handle klad);

/*
\brief Attach key ladder to the target.
\param[in] klad    Handle of key ladder.
\param[in] target  Handle of target, it is Keyslot handle that created by CIPHER/TSCIPHER driver.
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_attach(hi_handle klad, hi_handle target);

/*
\brief Detach a key ladder from a target.
\param[in] klad    Handle of key ladder.
\param[in] target  Handle of target, it is Keyslot handle that created by CIPHER/TSCIPHER driver.
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_detach(hi_handle klad, hi_handle target);

/*
\brief Set the attributes of a key ladder.
\param[in] klad    Handle of key ladder.
\param[in] attr  Pointer to the attributes of a key ladder.
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  the parameter is invalid.
*/
hi_s32 hi_tee_klad_set_attr(hi_handle klad, const hi_tee_klad_attr *attr);

/*
\brief Get the attributes of a key ladder
\param[in] klad    Handle of key ladder
\param[out] attr Pointer to the attributes of a key ladder
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_get_attr(hi_handle klad, hi_tee_klad_attr *attr);

/*
\brief Set the rootkey attributes of a key ladder.
\attention \n
This API is used for create a dynamic custom keyladder. keyladder type must be HI_TEE_KLAD_TYPE_DYNAMIC.
\param[in] klad    Handle of key ladder.
\param[in] root_key_attr  Pointer to the rootkey attributes of a key ladder.
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_set_root_key_attr(hi_handle klad, const hi_tee_rootkey_attr *root_key_attr);

/*
\brief Get the rootkey attributes of a key ladder
\param[in] klad    Handle of key ladder
\param[out] root_key_attr Pointer to the rootkey attributes of a key ladder
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_get_root_key_attr(hi_handle klad, hi_tee_rootkey_attr *root_key_attr);

/*
\brief Set session key of a keyladder
\param[in] klad    Handle of key ladder
\param[in] key   Pointer to the session key
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_set_session_key(hi_handle klad, const hi_tee_klad_session_key *key);

/*
\brief Set content key of a keyladder
\param[in] klad    Handle of key ladder
\param[in] key   Pointer to the content key
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_set_content_key(hi_handle klad, const hi_tee_klad_content_key *key);

/*
\brief Set clear route key of a keyladder
\param[in] klad    Handle of key ladder
\param[in] key   Pointer to the clear key
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_set_clear_key(hi_handle klad, const hi_tee_klad_clear_key *key);

/*
\brief Generate nonce key from keyladder
\param[in] klad    Handle of key ladder
\param[in] key   Pointer to the nonce key
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_generate_nonce(hi_handle klad, hi_tee_klad_nonce_key *key);

/*
\brief Set content key of a keyladder
\param[in] klad    Handle of key ladder
\param[in] key   Pointer to the content key
\param[in] call_back   Callback function for receiving final result.
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_async_set_content_key(hi_handle klad, const hi_tee_klad_content_key *key,
                                         const hi_tee_klad_done_callback *call_back);

/* @} */  /* <!-- ==== API declaration end ==== */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_TEE_KLAD_H__ */

