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
/** CNcomment:定义TSR2RCIPHER的算法类型 */
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
/** CNcomment:定义TSR2RCIPHER的模式 */
typedef enum {
    HI_TEE_TSR2RCIPHER_MODE_PAYLOAD = 0x0, /* payload mode, only encrypt and decrypt the payload */
    HI_TEE_TSR2RCIPHER_MODE_RAW     = 0x1, /* raw mode, encrypt and decrypt all */
    HI_TEE_TSR2RCIPHER_MODE_MAX
} hi_tee_tsr2rcipher_mode;

/** Defines the iv type of TSR2RCIPHER */
/** CNcomment:定义TSR2RCIPHER的iv类型 */
typedef enum {
    HI_TEE_TSR2RCIPHER_IV_EVEN = 0,
    HI_TEE_TSR2RCIPHER_IV_ODD  = 1,
    HI_TEE_TSR2RCIPHER_IV_MAX,
} hi_tee_tsr2rcipher_iv_type;

/** Defines the capability of TSR2RCIPHER */
/** CNcomment:定义TSR2RCIPHER的业务功能结构体 */
typedef struct {
    hi_u32 ts_chan_cnt; /* number of channel */
} hi_tee_tsr2rcipher_capability;

/** Defines the structure of the TSR2RCIPHER encrypt/decrypt control information */
/** CNcomment:定义TSR2RCIPHER加解密信息控制结构体 */
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
\brief Initializes the TSR2RCIPHER module. CNcomment:初始化TSR2RCIPHER模块 CNend
\attention \n
Before calling any other api in TSR2RCIPHER, you must call this function first.
CNcomment 在调用TSR2RCIPHER其他接口之前，要求先调用本接口 CNend
\param  N/A
\retval HI_SUCCESS  Success
\retval HI_FAILURE  Failure
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_init(hi_void);

/**
\brief Deinitializes the TSR2RCIPHER module. CNcomment:去初始化TSR2RCIPHER模块 CNend
\attention \n
Before calling this api, you should call hi_tee_tsr2rcipher_destroy to destroy all the TSR2RCIPHER instance.
CNcomment 在调用TSR2RCIPHER去初始化的接口前，需要调用hi_tee_tsr2rcipher_destroy来销毁所有TSR2RCIPHER实例 CNend
\param  N/A
\retval HI_SUCCESS  Success
\retval HI_FAILURE  Failure
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_deinit(hi_void);

/**
\brief Obtains the information about the service capabilities of the TSR2RCIPHER module.
CNcomment:查询TSR2RCIPHER模块业务能力 CNend
\attention \n
N/A
\param[out] cap Pointer to the structure of the TSR2RCIPHER capability.
CNcomment:指针类型，指向TSR2RCIPHER业务功能结构体. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_get_capability(hi_tee_tsr2rcipher_capability *cap);

/**
\brief Obtains the default attributes of the TSR2RCIPHER instance. CNcomment:获取TSR2RCIPHER实例默认属性 CNend
\attention \n
It is recommended to call this api to obtain default attributes before creating an instance, then modify the attributes.
CNcomment 建议在创建TSR2RCIPHER实例之前调用此接口获取默认属性，然后改变需要修改的属性即可 CNend
\param[out] attr Pointer to the structure of the TSR2RCIPHER instance attributes.
CNcomment:指针类型，指向TSR2RCIPHER实例属性结构体. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_get_default_attr(hi_tee_tsr2rcipher_attr *attr);

/**
\brief Creates a TSR2RCIPHER instance. CNcomment:创建一个TSR2RCIPHER实例 CNend
\attention \n
It is recommended to call hi_tee_tsr2rcipher_get_default_attr to obtain default attributes before calling this api.
CNcomment 建议调用此接口前，先调用hi_tee_tsr2rcipher_get_default_attr获取默认属性 CNend
\param[in] attr Pointer to the attributes that created the instance. CNcomment:指针类型，指向创建实例所需的属性. CNend
\param[out] handle Pointer to the handle of an allocated instance. CNcomment:指针类型，指向分配的实例句柄. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_create(const hi_tee_tsr2rcipher_attr *attr, hi_handle *handle);

/**
\brief Destroys a TSR2RCIPHER instance. CNcomment:销毁一个TSR2RCIPHER实例 CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:实例句柄. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_destroy(hi_handle handle);

/**
\brief Obtains the attributes of the specific instance. CNcomment:获取指定实例的属性 CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:实例句柄. CNend
\param[out] attr Pointer to the attributes of the specific instance. CNcomment:指针类型，指向指定实例的属性. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_get_attr(hi_handle handle, hi_tee_tsr2rcipher_attr *attr);

/**
\brief Sets the attributes of the specific instance. CNcomment:设置指定实例的属性 CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:实例句柄. CNend
\param[in] attr Pointer to the attributes to be set. CNcomment:指针类型，指向要设置的属性. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_set_attr(hi_handle handle, const hi_tee_tsr2rcipher_attr *attr);

/**
\brief Obtains the keyslot handle by TSR2RCIPHER handle. CNcomment:通过TSR2RCIPHER句柄获取keyslot句柄 CNend
\attention \n
Before calling this api, you should configure to create keyslot when calling hi_tee_tsr2rcipher_create.
CNcomment 调用此接口前，应该在调用hi_tee_tsr2rcipher_create时配置为创建keyslot CNend
\param[in] handle TSR2RCIPHER handle. CNcomment:TSR2RCIPHER句柄. CNend
\param[out] ks_handle Pointer to the keyslot handle. CNcomment:指针类型，指向keyslot句柄. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_get_keyslot_handle(hi_handle handle, hi_handle *ks_handle);

/**
\brief Attaches the keyslot to TSR2RCIPHER. CNcomment:绑定keyslot到TSR2RCIPHER CNend
\attention \n
N/A
\param[in] handle TSR2RCIPHER handle. CNcomment:TSR2RCIPHER句柄. CNend
\param[in] ks_handle keyslot handle. CNcomment:keyslot句柄. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_attach_keyslot(hi_handle handle, hi_handle ks_handle);

/**
\brief Detaches the keyslot from TSR2RCIPHER. CNcomment:从TSR2RCIPHER上解绑定keyslot CNend
\attention \n
N/A
\param[in] handle TSR2RCIPHER handle. CNcomment:TSR2RCIPHER句柄. CNend
\param[in] ks_handle keyslot handle. CNcomment:keyslot句柄. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_detach_keyslot(hi_handle handle, hi_handle ks_handle);

/**
\brief Sets the iv info of the specific instance. CNcomment:设置指定实例的初始化向量 CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:实例句柄. CNend
\param[in] iv_type iv type. CNcomment:初始化向量类型. CNend
\param[in] iv Pointer to the iv value. CNcomment:指针类型，指向初始化向量值. CNend
\param[in] iv_len iv len. CNcomment:初始化向量长度. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_set_iv(hi_handle handle, hi_tee_tsr2rcipher_iv_type iv_type, const hi_u8 *iv, hi_u32 iv_len);

/**
\brief Encrypt the data by the specific instance. CNcomment:通过指定实例加密数据 CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:实例句柄. CNend
\param[in] src_buf source data buffer address. CNcomment:数据源buffer地址. CNend
\param[in] dst_buf destination buffer address. CNcomment:目的buffer地址. CNend
\param[in] len the length of the data to be encrypted. CNcomment:要加密的数据长度. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_encrypt(hi_handle handle, hi_u64 src_buf, hi_u64 dst_buf, hi_u32 len);

/**
\brief Decrypt the data by the specific instance. CNcomment:通过指定实例解密数据 CNend
\attention \n
N/A
\param[in] handle instance handle. CNcomment:实例句柄. CNend
\param[in] src_buf source data buffer address. CNcomment:数据源buffer地址. CNend
\param[in] dst_buf destination buffer address. CNcomment:目的buffer地址. CNend
\param[in] len the length of the data to be decrypted. CNcomment:要解密的数据长度. CNend
\retval HI_SUCCESS  Success CNcomment:成功 CNend
\retval HI_FAILURE  Failure CNcomment:失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_tsr2rcipher_decrypt(hi_handle handle, hi_u64 src_buf, hi_u64 dst_buf, hi_u32 len);

/** @} */  /** <!-- ==== API declaration end ==== */


#ifdef __cplusplus
}
#endif

#endif

