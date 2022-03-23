/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define API about key slot driver
 * Author: Linux SDK team
 * Create: 2019-6-26
 */

#ifndef __HI_TEE_SLOT_H__
#define __HI_TEE_SLOT_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/* ************************** Structure Definition *************************** */
/* \addtogroup      KEYSLOT  */
/* @{ */  /** <!-- [KEYSLOT] */

/* Define the maximum number of TScipher keyslot. */
#define HI_TEE_KEYSLOT_TSCIPHER_MAX   256

/* Define the maximum number of Mcipher keyslot. */
#define HI_TEE_KEYSLOT_MCIPHER_MAX   15

/* Define the maximum number of HMAC keyslot. */
#define HI_TEE_KEYSLOT_HMAC_MAX   1

/* Define the keyslot type. */
typedef enum {
    HI_TEE_KEYSLOT_TYPE_TSCIPHER = 0x00,
    HI_TEE_KEYSLOT_TYPE_MCIPHER,
    HI_TEE_KEYSLOT_TYPE_HMAC,
    HI_TEE_KEYSLOT_TYPE_MAX
} hi_tee_keyslot_type;

/* Define the keyslot attribute type */
typedef enum {
    HI_TEE_KEYSLOT_ATTR_OPERATION_MODE = 0x00,
    HI_TEE_KEYSLOT_ATTR_TYPE_MAX,
} hi_tee_keyslot_attr_type;

/* Define the keyslot operation mode */
typedef enum {
    HI_TEE_KEYSLOT_OP_MODE_NONSECURE = 0x00,
    HI_TEE_KEYSLOT_OP_MODE_PRIVILEGEDATA_PROTECTION,
    HI_TEE_KEYSLOT_OP_MODE_SMP_PROTECTION,
    HI_TEE_KEYSLOT_OP_MODE_MAX,
} hi_tee_keyslot_operation_mode;

/* Define the keyslot attribute */
typedef union {
    hi_tee_keyslot_operation_mode operation_mode;
} hi_tee_keyslot_attr;

/* @} */  /* <!-- ==== Structure Definition end ==== */

/* ****************************** API declaration **************************** */
/* \addtogroup      KEYSLOT  */
/* @{ */  /** <!-- [KEYSLOT] */

/*
\brief Initializes the keyslot module. CNcomment:初始化keyslot模块 CNend
\attention \n
Before calling any other api in keyslot, you must call this function first.
CNcomment 在调用keyslot其他接口之前，要求先调用本接口 CNend
\param  N/A
\retval HI_SUCCESS  Success
\retval HI_FAILURE  Failure
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_init(hi_void);

/*
\brief Deinitializes the keyslot module. CNcomment:去初始化keyslot模块 CNend
\attention \n
Before calling this api, you should call hi_unf_keyslot_destroy to destroy all the keyslot instance.
CNcomment 在调用keyslot去初始化的接口前，需要调用hi_unf_keyslot_destroy来销毁所有keyslot实例 CNend
\param  N/A
\retval HI_SUCCESS  Success
\retval HI_FAILURE  Failure
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_deinit(hi_void);

/*
\brief Creates a keyslot instance. CNcomment:创建一个keyslot实例 CNend
\param[in] keyslot_type The keyslot type that created the instance. CNcomment:创建实例的类型. CNend
\param[out] key_slot Pointer to the handle of an allocated instance. CNcomment:指针类型，指向分配的实例句柄. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_create(hi_tee_keyslot_type keyslot_type, hi_handle *key_slot);

/*
\brief Destroys a keyslot instance. CNcomment:销毁一个keyslot实例 CNend
\attention \n
N/A
\param[in] key_slot instance handle. CNcomment:实例句柄. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_destroy(hi_handle key_slot);

/*
\brief Set the attributes of the specific instance. CNcomment:设置指定实例的属性 CNend
\attention \n
N/A
\param[in] key_slot instance handle. CNcomment:实例句柄. CNend
\param[in] attr_type instance attributes type. CNcomment:实例属性类型. CNend
\param[in] attr Pointer to the attributes to be set. CNcomment:指针类型，指向要设置的属性. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_set_attr(hi_handle key_slot, hi_tee_keyslot_attr_type attr_type, const hi_tee_keyslot_attr *attr);

/*
\brief Obtains the attributes of the specific instance. CNcomment:获取指定实例的属性 CNend
\attention \n
N/A
\param[in] key_slot instance handle. CNcomment:实例句柄. CNend
\param[in] attr_type instance attributes type. CNcomment:实例属性类型. CNend
\param[out] attr Pointer to the attributes of the specific instance. CNcomment:指针类型，指向指定实例的属性. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_get_attr(hi_handle key_slot, hi_tee_keyslot_attr_type attr_type, const hi_tee_keyslot_attr *attr);


/* @} */  /* <!-- ==== API declaration end ==== */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_TEE_SLOT_H__ */

