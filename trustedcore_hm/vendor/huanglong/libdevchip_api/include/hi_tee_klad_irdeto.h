/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define API about key ladder driver
 * Author: Linux SDK team
 * Create: 2019-7-04
 */
#ifndef __HI_TEE_KLAD_IRDETO_H__
#define __HI_TEE_KLAD_IRDETO_H__

#include "hi_tee_klad.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/*************************** Structure Definition ****************************/
/** \addtogroup      KLAD */
/** @{ */  /** <!-- [KLAD] */
#define HI_CA_ID_IRDETO              0x2

#define HI_TEE_KLAD_IRDETO_TYPE_TA   HI_KLAD_TYPE(HI_CA_ID_IRDETO, 0x04)

/** Define the content key source type. */
/** Flag of TA key ladder */
typedef enum {
    HI_TEE_KLAD_IRDETO_TA_FLAG_HOST_CPU = 0,      /**< last level CW data is ca_din from host cpu config */
    HI_TEE_KLAD_IRDETO_TA_FLAG_TA_KLAD  = 1,      /**< last level CW data is cwsk_cw from ta key ladder */
    HI_TEE_KLAD_IRDETO_TA_FLAG_MAX
} hi_tee_klad_irdeto_ta_flag;

/** Define the structure of TA key */
typedef struct {
    hi_u32 key_size;  /**< The size of TA key. */
    hi_u8 key[HI_TEE_KLAD_MAX_KEY_LEN];
} hi_tee_klad_ta_key; /**< The TA key. */

/** Define the structure of Transform data */
typedef struct {
    hi_u32  data_size;  /**< The size of transformed data. */
    hi_u8*  trans_data; /**< The transformed data. */
} hi_tee_klad_trans_data;

/**
\brief Set TA flag, enFlag set TA_KLAD means keyladder content key come from TA keyaldder.
\param[in] klad    Handle of key ladder, This handle created by a common keyladder.
\param[in] flag    flag of TA key ladder
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_irdeto_set_ta_flag(hi_handle klad, hi_tee_klad_irdeto_ta_flag flag);

/**
\brief Set TA session key
\param[in] klad    Handle of key ladder,This handle created by TA keyladder.
\param[in] key     Pointer to the session key(level 1) of TA key ladder
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_irdeto_set_ta_session_key(hi_handle klad, const hi_tee_klad_ta_key *key);

/**
\brief Set TA transform data
\param[in] klad        Handle of key ladder
\param[in] trans_data  Pointer to the transform data(level 2) of TA key ladder
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_irdeto_set_ta_trans_data(hi_handle klad, const hi_tee_klad_trans_data *trans_data);

/**
\brief Set TA content key
\param[in] klad    Handle of key ladder
\param[in] key     Pointer to the content key(level 3) of TA key ladder
\retval ::HI_SUCCESS  Success
\retval ::HI_FAILURE  Failure
\retval ::HI_ERR_KLAD_INVALID_PARAM  The parameter is invalid.
*/
hi_s32 hi_tee_klad_irdeto_set_ta_content_key(hi_handle klad, const hi_tee_klad_ta_key *key);


/** @} */  /** <!-- ==== API declaration end ==== */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_TEE_KLAD_IRDETO_H__ */

