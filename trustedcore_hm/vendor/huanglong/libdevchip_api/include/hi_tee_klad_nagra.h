/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define API about key ladder driver
 * Author: Linux SDK team
 * Create: 2019-7-04
 */
#ifndef __HI_TEE_KLAD_NAGRA_H__
#define __HI_TEE_KLAD_NAGRA_H__

#include "hi_tee_klad.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/*************************** Structure Definition ****************************/
/** \addtogroup      KLAD */
/** @{ */  /** <!-- [KLAD] */
#define HI_CA_ID_NAGRA               0x81

/*
Level: 3
Algorithm: TDES
Target Engine: Demux - CSA2
*/
#define HI_TEE_KLAD_NAGRA_TYPE_CSA2   HI_TEE_KLAD_INSTANCE(HI_CA_ID_NAGRA, HI_TEE_ROOTKEY_CSA2, HI_TEE_KLAD_COM, 0x01)

/*
Level: 3
Algorithm: TDES
Target Engine: Demux - CSA3
*/
#define HI_TEE_KLAD_NAGRA_TYPE_CSA3   HI_TEE_KLAD_INSTANCE(HI_CA_ID_NAGRA, HI_TEE_ROOTKEY_CSA3, HI_TEE_KLAD_COM, 0x02)

/*
Level: 3
Algorithm: TDES
Target Engine: Demux - AES; Payload cipher - AES; Multicipher - fixed
*/
#define HI_TEE_KLAD_NAGRA_TYPE_AES    HI_TEE_KLAD_INSTANCE(HI_CA_ID_NAGRA, HI_TEE_ROOTKEY_AES, HI_TEE_KLAD_COM, 0x03)

/*
Level: 3
Algorithm: TDES
Target Engine: Demux - TDES; Multicipher - fixed
*/
#define HI_TEE_KLAD_NAGRA_TYPE_TDES   HI_TEE_KLAD_INSTANCE(HI_CA_ID_NAGRA, HI_TEE_ROOTKEY_TDES, HI_TEE_KLAD_COM, 0x04)

/*
Level: 4
Algorithm: TDES
Target Engine: Multicipher - fixed; encrypted register - NA
*/
#define HI_TEE_KLAD_NAGRA_TYPE_FPK    HI_TEE_KLAD_INSTANCE(HI_CA_ID_NAGRA, HI_TEE_ROOTKEY_NULL, HI_TEE_KLAD_FP, 0x01)


/** Define the operation of flash protection keyladder. */
typedef enum {
    HI_TEE_KLAD_FP_OPT_ENCRYPT      = 0,  /**< Encrypt operation. */
    HI_TEE_KLAD_FP_OPT_DECRYPT,           /**< Decrypt operation. */
    HI_TEE_KLAD_FP_OPT_ROUTE,             /**< Send key to ctypto engine. */
    HI_TEE_KLAD_FP_OPT_MAX
} hi_tee_klad_fp_operation;

/** Structure of setting FP keyladder key. */
typedef struct {
    hi_tee_klad_fp_operation operation;   /**< The operation of flash protection keyladder. */
    hi_tee_klad_alg_type alg;             /**< The algorithm of the flash protection key,
                                               effective when enOperation set xxx_OPT_ROUTE. */
    hi_u32 key_size;                      /**< The size of flash protection key,
                                               effective when enOperation set xxx_OPT_ROUTE. */
    hi_u8 key[HI_TEE_KLAD_MAX_KEY_LEN];   /**< The size of flash protection key,
                                               effective when enOperation set xxx_OPT_ROUTE. */
    hi_u32 enc_key_size;
    hi_u8 enc_key[HI_TEE_KLAD_MAX_KEY_LEN];
} hi_tee_klad_fp_key;

/**
\brief Set flash protection key to keyladder
\param[in] klad    Handle of key ladder
\param[in] key     Pointer to the flash protection  key
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_nagra_set_fp_key(hi_handle klad, hi_tee_klad_fp_key *key);

/** @} */  /** <!-- ==== API declaration end ==== */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_TEE_KLAD_NAGRA_H__ */

