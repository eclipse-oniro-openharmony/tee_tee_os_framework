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
\brief Initializes the keyslot module. CNcomment:��ʼ��keyslotģ�� CNend
\attention \n
Before calling any other api in keyslot, you must call this function first.
CNcomment �ڵ���keyslot�����ӿ�֮ǰ��Ҫ���ȵ��ñ��ӿ� CNend
\param  N/A
\retval HI_SUCCESS  Success
\retval HI_FAILURE  Failure
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_init(hi_void);

/*
\brief Deinitializes the keyslot module. CNcomment:ȥ��ʼ��keyslotģ�� CNend
\attention \n
Before calling this api, you should call hi_unf_keyslot_destroy to destroy all the keyslot instance.
CNcomment �ڵ���keyslotȥ��ʼ���Ľӿ�ǰ����Ҫ����hi_unf_keyslot_destroy����������keyslotʵ�� CNend
\param  N/A
\retval HI_SUCCESS  Success
\retval HI_FAILURE  Failure
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_deinit(hi_void);

/*
\brief Creates a keyslot instance. CNcomment:����һ��keyslotʵ�� CNend
\param[in] keyslot_type The keyslot type that created the instance. CNcomment:����ʵ��������. CNend
\param[out] key_slot Pointer to the handle of an allocated instance. CNcomment:ָ�����ͣ�ָ������ʵ�����. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_create(hi_tee_keyslot_type keyslot_type, hi_handle *key_slot);

/*
\brief Destroys a keyslot instance. CNcomment:����һ��keyslotʵ�� CNend
\attention \n
N/A
\param[in] key_slot instance handle. CNcomment:ʵ�����. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_destroy(hi_handle key_slot);

/*
\brief Set the attributes of the specific instance. CNcomment:����ָ��ʵ�������� CNend
\attention \n
N/A
\param[in] key_slot instance handle. CNcomment:ʵ�����. CNend
\param[in] attr_type instance attributes type. CNcomment:ʵ����������. CNend
\param[in] attr Pointer to the attributes to be set. CNcomment:ָ�����ͣ�ָ��Ҫ���õ�����. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_keyslot_set_attr(hi_handle key_slot, hi_tee_keyslot_attr_type attr_type, const hi_tee_keyslot_attr *attr);

/*
\brief Obtains the attributes of the specific instance. CNcomment:��ȡָ��ʵ�������� CNend
\attention \n
N/A
\param[in] key_slot instance handle. CNcomment:ʵ�����. CNend
\param[in] attr_type instance attributes type. CNcomment:ʵ����������. CNend
\param[out] attr Pointer to the attributes of the specific instance. CNcomment:ָ�����ͣ�ָ��ָ��ʵ��������. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
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

