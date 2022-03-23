/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: HiSilicon TSR2RCIPHER TEE API declaration.
 * Author: sdk
 * Create: 2019-08-02
 */

#ifndef __HI_TEE_TSR2RCIPHER_H__
#define __HI_TEE_TSR2RCIPHER_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
extern "C" {
#endif

/*************************** Structure Definition ****************************/
/** \addtogroup      TSR2RCIPHER */
/** @{ */  /** <!-- [TSR2RCIPHER] */

/** Defines the algorithm types of TSR2RCIPHER */
/** CNcomment:����TSR2RCIPHER���㷨���� */
typedef enum {
    HI_TEE_TSR2RCIPHER_ALG_AES_ECB   = 0x10,
    HI_TEE_TSR2RCIPHER_ALG_AES_CBC   = 0x13,
    HI_TEE_TSR2RCIPHER_ALG_AES_IPTV  = 0x16,
    HI_TEE_TSR2RCIPHER_ALG_AES_CTR   = 0x17,
    HI_TEE_TSR2RCIPHER_ALG_SMS4_ECB  = 0x30,
    HI_TEE_TSR2RCIPHER_ALG_SMS4_CBC  = 0x31,
    HI_TEE_TSR2RCIPHER_ALG_SMS4_IPTV = 0x32,
    HI_TEE_TSR2RCIPHER_ALG_MAX
} hi_tee_tsr2rcipher_alg;

/** Defines the mode of TSR2RCIPHER */
/** CNcomment:����TSR2RCIPHER��ģʽ */
typedef enum {
    HI_TEE_TSR2RCIPHER_MODE_PAYLOAD = 0x0, /* payload mode, only encrypt and decrypt the payload */
    HI_TEE_TSR2RCIPHER_MODE_RAW     = 0x1, /* raw mode, encrypt and decrypt all */
    HI_TEE_TSR2RCIPHER_MODE_MAX
} hi_tee_tsr2rcipher_mode;

/** Defines the iv type of TSR2RCIPHER */
/** CNcomment:����TSR2RCIPHER��iv���� */
typedef enum {
    HI_TEE_TSR2RCIPHER_IV_EVEN = 0,
    HI_TEE_TSR2RCIPHER_IV_ODD  = 1,
    HI_TEE_TSR2RCIPHER_IV_MAX,
} hi_tee_tsr2rcipher_iv_type;

/** Defines the capability of TSR2RCIPHER */
/** CNcomment:����TSR2RCIPHER��ҵ���ܽṹ�� */
typedef struct {
    hi_u32 ts_chan_cnt; /* number of channel */
} hi_tee_tsr2rcipher_capability;

/** Defines the structure of the TSR2RCIPHER encrypt/decrypt control information */
/** CNcomment:����TSR2RCIPHER�ӽ�����Ϣ���ƽṹ�� */
typedef struct {
    hi_tee_tsr2rcipher_alg  alg;
    hi_tee_tsr2rcipher_mode mode;
    hi_bool is_crc_check; /* default is false, set to true only when encrypting/decrypting audio and video. */
    hi_bool is_create_keyslot; /* create keyslot or not */
    hi_bool is_odd_key; /* it needs to match the even/odd attr of the key sent by klad */
} hi_tee_tsr2rcipher_attr;

/** @} */  /** <!-- ==== Structure Definition end ==== */

/******************************* API declaration *****************************/
/** \addtogroup      TSR2RCIPHER */
/** @{ */  /** <!-- [TSR2RCIPHER] */

/**
\brief Initializes the TSR2RCIPHER module. CNcomment:��ʼ��TSR2RCIPHERģ�� CNend
\attention \n
Before calling any other api in TSR2RCIPHER, you must call this function first.
CNcomment �ڵ���TSR2RCIPHER�����ӿ�֮ǰ��Ҫ���ȵ��ñ��ӿ� CNend
\param  N/A
\retval HI_SUCCESS  Success
\retval HI_FAILURE  Failure
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_init(hi_void);

/**
\brief Deinitializes the TSR2RCIPHER module. CNcomment:ȥ��ʼ��TSR2RCIPHERģ�� CNend
\attention \n
Before calling this api, you should call hi_tee_tsr2rcipher_destroy to destroy all the TSR2RCIPHER instance.
CNcomment �ڵ���TSR2RCIPHERȥ��ʼ���Ľӿ�ǰ����Ҫ����hi_tee_tsr2rcipher_destroy����������TSR2RCIPHERʵ�� CNend
\param  N/A
\retval HI_SUCCESS  Success
\retval HI_FAILURE  Failure
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_deinit(hi_void);

/**
\brief Obtains the information about the service capabilities of the TSR2RCIPHER module.
CNcomment:��ѯTSR2RCIPHERģ��ҵ������ CNend
\attention \n
N/A
\param[out] cap Pointer to the structure of the TSR2RCIPHER capability.
CNcomment:ָ�����ͣ�ָ��TSR2RCIPHERҵ���ܽṹ��. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_get_capability(hi_tee_tsr2rcipher_capability *cap);

/**
\brief Obtains the default attributes of the TSR2RCIPHER instance. CNcomment:��ȡTSR2RCIPHERʵ��Ĭ������ CNend
\attention \n
It is recommended to call this api to obtain default attributes before creating an instance, then modify the attributes.
CNcomment �����ڴ���TSR2RCIPHERʵ��֮ǰ���ô˽ӿڻ�ȡĬ�����ԣ�Ȼ��ı���Ҫ�޸ĵ����Լ��� CNend
\param[out] attr Pointer to the structure of the TSR2RCIPHER instance attributes.
CNcomment:ָ�����ͣ�ָ��TSR2RCIPHERʵ�����Խṹ��. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_get_default_attr(hi_tee_tsr2rcipher_attr *attr);

/**
\brief Creates a TSR2RCIPHER instance. CNcomment:����һ��TSR2RCIPHERʵ�� CNend
\attention \n
It is recommended to call hi_tee_tsr2rcipher_get_default_attr to obtain default attributes before calling this api.
CNcomment ������ô˽ӿ�ǰ���ȵ���hi_tee_tsr2rcipher_get_default_attr��ȡĬ������ CNend
\param[in] attr Pointer to the attributes that created the instance. CNcomment:ָ�����ͣ�ָ�򴴽�ʵ�����������. CNend
\param[out] handle Pointer to the handle of an allocated instance. CNcomment:ָ�����ͣ�ָ������ʵ�����. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_create(const hi_tee_tsr2rcipher_attr *attr, hi_handle *handle);

/**
\brief Destroys a TSR2RCIPHER instance. CNcomment:����һ��TSR2RCIPHERʵ�� CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:ʵ�����. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_destroy(hi_handle handle);

/**
\brief Obtains the attributes of the specific instance. CNcomment:��ȡָ��ʵ�������� CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:ʵ�����. CNend
\param[out] attr Pointer to the attributes of the specific instance. CNcomment:ָ�����ͣ�ָ��ָ��ʵ��������. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_get_attr(hi_handle handle, hi_tee_tsr2rcipher_attr *attr);

/**
\brief Sets the attributes of the specific instance. CNcomment:����ָ��ʵ�������� CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:ʵ�����. CNend
\param[in] attr Pointer to the attributes to be set. CNcomment:ָ�����ͣ�ָ��Ҫ���õ�����. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_set_attr(hi_handle handle, const hi_tee_tsr2rcipher_attr *attr);

/**
\brief Obtains the keyslot handle by TSR2RCIPHER handle. CNcomment:ͨ��TSR2RCIPHER�����ȡkeyslot��� CNend
\attention \n
Before calling this api, you should configure to create keyslot when calling hi_tee_tsr2rcipher_create.
CNcomment ���ô˽ӿ�ǰ��Ӧ���ڵ���hi_tee_tsr2rcipher_createʱ����Ϊ����keyslot CNend
\param[in] handle TSR2RCIPHER handle. CNcomment:TSR2RCIPHER���. CNend
\param[out] ks_handle Pointer to the keyslot handle. CNcomment:ָ�����ͣ�ָ��keyslot���. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_get_keyslot_handle(hi_handle handle, hi_handle *ks_handle);

/**
\brief Attaches the keyslot to TSR2RCIPHER. CNcomment:��keyslot��TSR2RCIPHER CNend
\attention \n
N/A
\param[in] handle TSR2RCIPHER handle. CNcomment:TSR2RCIPHER���. CNend
\param[in] ks_handle keyslot handle. CNcomment:keyslot���. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_attach_keyslot(hi_handle handle, hi_handle ks_handle);

/**
\brief Detaches the keyslot from TSR2RCIPHER. CNcomment:��TSR2RCIPHER�Ͻ��keyslot CNend
\attention \n
N/A
\param[in] handle TSR2RCIPHER handle. CNcomment:TSR2RCIPHER���. CNend
\param[in] ks_handle keyslot handle. CNcomment:keyslot���. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_detach_keyslot(hi_handle handle, hi_handle ks_handle);

/**
\brief Sets the iv info of the specific instance. CNcomment:����ָ��ʵ���ĳ�ʼ������ CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:ʵ�����. CNend
\param[in] iv_type iv type. CNcomment:��ʼ����������. CNend
\param[in] iv Pointer to the iv value. CNcomment:ָ�����ͣ�ָ���ʼ������ֵ. CNend
\param[in] iv_len iv len. CNcomment:��ʼ����������. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_set_iv(hi_handle handle, hi_tee_tsr2rcipher_iv_type iv_type, const hi_u8 *iv, hi_u32 iv_len);

/**
\brief Encrypt the data by the specific instance. CNcomment:ͨ��ָ��ʵ���������� CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:ʵ�����. CNend
\param[in] src_buf source data buffer address. CNcomment:����Դbuffer��ַ. CNend
\param[in] dst_buf destination buffer address. CNcomment:Ŀ��buffer��ַ. CNend
\param[in] len the length of the data to be encrypted. CNcomment:Ҫ���ܵ����ݳ���. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_encrypt(hi_handle handle, hi_u64 src_buf, hi_u64 dst_buf, hi_u32 len);

/**
\brief Decrypt the data by the specific instance. CNcomment:ͨ��ָ��ʵ���������� CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:ʵ�����. CNend
\param[in] src_buf source data buffer address. CNcomment:����Դbuffer��ַ. CNend
\param[in] dst_buf destination buffer address. CNcomment:Ŀ��buffer��ַ. CNend
\param[in] len the length of the data to be decrypted. CNcomment:Ҫ���ܵ����ݳ���. CNend
\retval HI_SUCCESS  Success CNcomment:�ɹ� CNend
\retval HI_FAILURE  Failure CNcomment:ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_decrypt(hi_handle handle, hi_u64 src_buf, hi_u64 dst_buf, hi_u32 len);

/** @} */  /** <!-- ==== API declaration end ==== */


#ifdef __cplusplus
}
#endif

#endif

