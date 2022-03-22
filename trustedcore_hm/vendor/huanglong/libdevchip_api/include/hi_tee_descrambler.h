/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee demux descrambler head file
 * Author: sdk
 * Create: 2019-07-13
 */

#ifndef __TEE_DESCRAMBLER_H__
#define __TEE_DESCRAMBLER_H__

#include "hi_type_dev.h"
#include "hi_tee_security.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*************************** Structure Definition ****************************/
/** CA Entropy reduction mode */
/** CNcomment:熵减少模式 */
typedef enum {
    HI_TEE_DMX_CA_ENTROPY_REDUCTION_CLOSE = 0, /* 64bit */
    HI_TEE_DMX_CA_ENTROPY_REDUCTION_OPEN, /* 48bit */

    HI_TEE_DMX_CA_ENTROPY_REDUCTION_MAX
} hi_tee_dmx_ca_entropy;

/* Key secure mode type */
/* CNcomment:Key安全模式类型 */
typedef enum {
    HI_TEE_DMX_DESC_SECURE_MODE_TEE = 0, /* trustedzone security protection */ /* CNcomment:trustedzone安全保护 */
    HI_TEE_DMX_DESC_SECURE_MODE_NONE, /* no security protection */ /* CNcomment:无安全保护 */

    HI_TEE_DMX_DESC_SECURE_MODE_MAX
} hi_tee_dmx_desc_secure_mode;

/* Attribute of the key area. */
/* CNcomment:密钥区属性 */
typedef struct {
    /* Descrambling protocol type of the descrambler */ /* CNcomment:解扰器解扰协议类型 */
    hi_tee_crypto_alg alg_type;
    /* CA Entropy reduction mode,for CSA2.0 */ /* CNcomment:熵减少模式，CSA2.0有效 */
    hi_tee_dmx_ca_entropy ca_entropy;
    /* Secure indication */ /* CNcomment:安全标示 */
    hi_tee_dmx_desc_secure_mode key_secure_mode;
    /* Whether the keysloy will be created, when create descrambler */ /* CNcomment:创建解扰器时是否创建keyslot */
    hi_bool is_create_keyslot;
} hi_tee_dmx_desc_attr;

/** @} */  /** <!-- ==== Structure Definition end ==== */


/******************************* API Declaration *****************************/
/** \addtogroup      Descrambler */
/** @{ */  /** <!--[Descrambler] */

/**
\brief Creates a key area. The key area type and descrambling protocol type can be selected.CNcomment:创建一个密钥区,\n
支持选择高安全CA和解扰协议类型。CNend
\attention \n
When an advanced CA key area is created, the descrambling protocol depends on the hardware and interface settings are\n
ignored.\n
CNcomment:如果是高安全CA，解扰协议已经由硬件决定，接口的设置被忽略。CNend
\param[in] dmx_id   DEMUX ID. CNcomment: DEMUX号。CNend
\param[in] attr  Pointer to the attributes of a key area.CNcomment:密钥区属性指针。CNend
\param[out] handle      Pointer to the handle of a created key area.CNcomment:指针类型，输出申请到的密钥区Handle。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\retval ::HI_ERR_DMX_NOFREE_KEY  There is no available key area.CNcomment:没有空闲的密钥区。CNend
\retval ::HI_ERR_DMX_NOT_SUPPORT  Not support HI_UNF_DMX_DESCRAMBLER_ATTR_S type.CNcomment:不支持的\n
HI_UNF_DMX_DESCRAMBLER_ATTR_S类型。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_create(hi_u32 dmx_id, const hi_tee_dmx_desc_attr *attr, hi_handle *handle);

/**
\brief Destroys an existing key area.CNcomment:销毁创建的密钥区。CNend
\attention \n
If a key area is attached to a channel, the key area needs to be detached from the channel first, but the channel is \n
not disabled.\n
If a key area is detached or destroyed before the attached channel is disabled, an error may occur during data \n
receiving.
CNcomment:如果密钥区绑定在通道上，会先从通道上解绑定密钥区，但是注意不会关闭通道\n
如果没有关闭通道则进行密钥区的解绑定或销毁操作，可能导致数据接收的错误。CNend
\param[in] handle  Handle of the key area to be destroyed.CNcomment:待删除的密钥区Handle。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_destroy(hi_handle handle);

/**
\brief Gets the attributes of a Descrambler.CNcomment:获取密钥配置属性。CNend
\attention \n
NA.\n
CNcomment:无。CNend
\param[in] handle   key handle. CNcomment: key句柄。CNend
\param[out] attr  Pointer to the attributes of a key area.CNcomment:密钥区属性指针。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\retval ::HI_ERR_DMX_NOFREE_KEY  There is no available key area.CNcomment:没有空闲的密钥区。CNend
\retval ::HI_ERR_DMX_NOT_SUPPORT  Not support HI_UNF_DMX_DESCRAMBLER_ATTR_S type.CNcomment:不支持的\n
HI_UNF_DMX_DESCRAMBLER_ATTR_S类型。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_get_attr(hi_handle handle, hi_tee_dmx_desc_attr *attr);

/**
\brief Sets the attributes of a Descrambler.CNcomment:设置密钥配置属性。CNend
\attention \n
NA.\n
CNcomment:无。CNend
\param[in] handle   key handle. CNcomment: key句柄。CNend
\param[out] attr  Pointer to the attributes of a key area.CNcomment:密钥区属性指针。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\retval ::HI_ERR_DMX_NOFREE_KEY  There is no available key area.CNcomment:没有空闲的密钥区。CNend
\retval ::HI_ERR_DMX_NOT_SUPPORT  Not support HI_UNF_DMX_DESCRAMBLER_ATTR_S type.CNcomment:不支持的\n
HI_UNF_DMX_DESCRAMBLER_ATTR_S类型。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_set_attr(hi_handle handle, const hi_tee_dmx_desc_attr *attr);

/**
\brief Set system key,only used for multi2 algs.CNcomment:设置系统密钥，只用于multi2算法类型。CNend
\attention \n
pu8SysKey points to the system key data to be set.The data length is specified by parameter u32SysKeyLen,ususlly the \n
length is 32 Bytes.\n
The system key value can be set before or after setting IV key and clear key,and just need to set it once each \n
taransport stream.
CNcomment:pu8SysKey指向要设置的系统密钥数据。密钥数据的长度由参数u32SysKeyLen指定，通常情况是32字节长度。\n
系统密钥可以在设置IV和明文密钥的之前或者之后设置,而且每条码流只需要设置一次。CNend
\param[in] handle  Handle of the key area to be set.CNcomment:待设置的密钥区句柄。CNend
\param[in] sys_key    Pointer to the system key data to be set.CNcomment:指针类型，指向要设置的系统密钥数据。CNend
\param[in] sys_key  The length of system key.CNcomment:待设置的密钥的长度。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_set_sys_key(hi_handle handle, const hi_u8 *sys_key, hi_u32 sys_key_len);

/**
\brief Set Even IV.For algs do not use IV,do not care.CNcomment:设置偶密钥区的初始化向量。对于不涉及初始化向量的解扰\n
算法可以不关注。CNend
\attention \n
pu8IVKey points to the iv key data to be set.The data consists of 16 bytes: CW1, CW2, ..., and CW16.\n
The key value can be set dynamically, that is, the key value can be set at any time after a key area is created.
CNcomment:pu8IVKey指向要设置的初始化向量数据。奇密钥数据共16byte，byte依次是CW1、CW2、……、CW16\n
支持密钥区的动态设置，可以在密钥区申请后的任意时刻设置。CNend
\param[in] handle  Handle of the key area to be set.CNcomment:待设置的密钥区句柄。CNend
\param[in] even_iv   Pointer to the 16-byte IV key data to be set.CNcomment:指针类型，指向要设置的奇密钥数据，必须是16\n
个字节的数组。CNend
\param[in] even_iv_len   The length of even IV key data to be set.CNcomment:待设置的偶密钥数据的长度。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_set_even_iv(hi_handle handle, const hi_u8 *even_iv, hi_u32 even_iv_len);

/**
\brief Set Odd IV.For algs do not use IV,do not care.CNcomment:设置奇密钥区的初始化向量。对于不涉及初始化向量的解扰\n
算法可以不关注。CNend
\attention \n
pu8IVKey points to the iv key data to be set.The data consists of 16 bytes: CW1, CW2, ..., and CW16.\n
The key value can be set dynamically, that is, the key value can be set at any time after a key area is created.
CNcomment:pu8IVKey指向要设置的初始化向量数据。奇密钥数据共16byte，byte依次是CW1、CW2、……、CW16\n
支持密钥区的动态设置，可以在密钥区申请后的任意时刻设置。CNend
\param[in] handle  Handle of the key area to be set.CNcomment:待设置的密钥区句柄。CNend
\param[in] odd_iv    Pointer to the 16-byte IV key data to be set.CNcomment:指针类型，指向要设置的奇密钥数据，必须是\n
16个字节的数组。CNend
\param[in] odd_iv_len   The length of odd IV key data to be set.CNcomment:待设置的奇密钥数据的长度。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_set_odd_iv(hi_handle handle, const hi_u8 *odd_iv, hi_u32 odd_iv_len);

/**
\brief Attaches a keyslot  to a key area.CNcomment:绑定keyslot到指定的密钥区。CNend
\attention \n
A keyslot can be attached to multiple keys.\n
The key area can obtain the key value from the keyslot module.\n
The same keyslot or different keyslot cannot be attached to the same key area.
CNcomment:一个keyslot可以绑定到多个密钥区上。\n
绑定后的密钥区可以从keyslot模块获取密钥值。\n
不允许重复绑定相同或不同的keyslot到同一个密钥区上。CNend
\param[in] handle    Handle of the key area to be attached.CNcomment:待绑定的密钥区句柄。CNend
\param[in] ks_handle   Keyslot handle.CNcomment:Keyslot句柄。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_ATTACHED_KEY  A keyslot is attached to the key area.CNcomment:密钥区已经绑定了一个keyslot。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_attach_key_slot(hi_handle handle, hi_handle ks_handle);

/**
\brief Detaches the keyslot handle of a key area.CNcomment:解绑定指定密钥区的keyslot句柄。CNend
\attention \n
You can detach the keyslot at any time after the key area is created.\n
Detach can be successfully performed even if the key area is not attach to keyslot.\n
After detach the keyslot, the key area will not be able to get the key value from the keyslot module.
CNcomment:可以在密钥区创建后的任何时刻解绑定keyslot。\n
即使密钥区没有绑定keyslot句柄也可以成功执行解绑定。\n
解绑定keyslot之后密钥区将不能从keyslot模块获取密钥值。CNend
\param[in] handle    Handle of the key area to be attached.CNcomment:待解绑定的密钥区句柄。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_detach_key_slot(hi_handle handle);

/**
\brief Get the keyslot handle of a key area.CNcomment:获取指定密钥区的keyslot句柄。CNend
\attention \n
Used to get the detached keyslot handle from the specified key area.\n
If the key area did not attach to a keyslot, it will return failure.\n
CNcomment:用于从指定的密钥区获取绑定的keyslot句柄。\n
如果密钥区没有绑定keyslot，则会返回失败。CNend
\param[in] handle    Handle of the key area to be attached.CNcomment:指定的密钥区句柄。CNend
\param[out] ks_handle   Pointer to the handle of the keyslot that is attached to a key area (output).CNcomment:\n
指针类型，输出密钥区绑定的keyslot句柄。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_NOATTACH_KEY A keyslot is not attached to the key area.CNcomment:密钥区还没有绑定一个keyslot。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_get_key_slot_handle(hi_handle handle, hi_handle *ks_handle);

/**
\brief Attaches a key area to a specific pid channel.CNcomment:绑定密钥区到指定的pid通道。CNend
\attention \n
A key area can be attached to multiple pid channels that belong to different DEMUXs.\n
The static loading data in the key areas that are attached to all types of channels can be descrambled.\n
The same key area or different key areas cannot be repeatedly attached to the same pid channel.
CNcomment:一个密钥区可以绑定到多个pid通道上，通道可以属于不同的DEMUX\n
可以对所有类型的通道绑定密钥区进行数据的解扰\n
不允许重复绑定相同或不同的密钥区到同一个pid通道上。CNend
\param[in] handle    Handle of the key area to be attached.CNcomment:待绑定的密钥区句柄。CNend
\param[in] pid_chan   Pid channel handle.CNcomment:Pid通道句柄。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_ATTACHED_KEY  A key area is attached to the channel.CNcomment:通道上已经有一个密钥区绑定在上面。\n
CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_attach_pid_chan(hi_handle handle, hi_handle pid_chan);

/**
\brief Detaches a key area from a pid channel.CNcomment:将密钥区从pid通道上解绑定。CNend
\attention \n
The key area used by a pid channel can be detached dynamically. That is, you can call this API to detach a key area \n
at any time after it is attached.\n
The scrambled data, however, may not be descrambled after the key area is detached, which causes data error.\n
The value of a key area retains even after it is detached. If the key area is attached again, its value is still the \n
previously configured value.\n
If you do not want to descramble data, you can detach the corresponding key area or set all key values to 0.
CNcomment:可以动态的解绑定pid通道使用的密钥区，可以在绑定后的任意时刻使用此接口解绑定密钥区\n
但是解绑定后可能导致加扰数据没有被解扰，导致数据错误\n
解绑定密钥区并不能改变密钥区的值，如果重新绑定密钥区，密钥值仍然是上次设置的值\n
如果不想进行解扰，除了解绑定密钥区之外，也可以直接将密钥值全部设置为0来实现。CNend
\param[in] handle    Handle of the key area to be detached.CNcomment:待解绑定的密钥区句柄。CNend
\param[in] pid_chan  Pid channel handle.CNcomment:Pid通道句柄。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_NOATTACH_KEY  No key areas are attached to the channel.CNcomment:通道上没有绑定任何密钥区。CNend
\retval ::HI_ERR_DMX_UNMATCH_KEY  The specified key area is not attached to the specified channel.CNcomment:指定的\n
密钥区没有绑定在指定的通道上。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_detach_pid_chan(hi_handle handle, hi_handle pid_chan);


/**
\brief Obtains the handle of the key area that is attached to a channel.CNcomment:获取通道绑定的密钥区句柄。CNend
\attention \n
If no key area is attached to the channel, the error code HI_ERR_DMX_NOATTACH_KEY is returned when you call this API.
CNcomment:当通道没有绑定密钥区时，调用本接口返回HI_ERR_DMX_NOATTACH_KEY错误码。CNend
\param[in] pid_chan  Handle of the pid channel to be queried.CNcomment:要查询的pid通道句柄。CNend
\param[out] desc_handle  Pointer to the handle of the key area that is attached to a channel (output).CNcomment:\n
指针类型，输出通道绑定的密钥区句柄。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\retval ::HI_ERR_DMX_NOATTACH_KEY  No key areas are attached to the channel.CNcomment:通道上没有绑定任何密钥区。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_get_handle(hi_handle pid_chan, hi_handle *desc_handle);

/**
\brief Obtains the handle of the channel with a specific PID.CNcomment:获取配置某PID的通道句柄。CNend
\attention \n
You must specify the DEMUX ID when calling this API, because the channel PIDs of different DEMUXs can be the same.\n
You cannot query the PID that is equal to or greater than 0x1FFF; otherwise, the error code HI_ERR_DMX_INVALID_PARA
is returned.\n
If no channel with a specific PID is found, an error code is returned.
CNcomment:因不同DEMUX设备的通道允许设置相同的PID，调用本接口需要指定DEMUX ID\n
不允许查询0x1fff及以上的非法PID值，否则返回参数非法错误码\n
如果没有查询到任何通道设置了要查询的PID，将返回错误码。CNend
\param[in] dmx_id    DEMUX ID. CNcomment: DEMUX号。CNend
\param[in] pid      Channel PID.CNcomment:通道PID。CNend
\param[out] chan_num  Point to channel handle number.CNcomment: 指针类型，指向输出通道Handle的个数。CNend
\param[out] chan   An array to store channel handle.CNcomment: 数组类型，用于存储输出通道Handle。CNend
\retval ::HI_SUCCESS Success.CNcomment:成功。CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:API系统调用失败。CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:模块没有初始化。CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:输入参数非法。CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:指针参数为空。CNend
\retval ::HI_ERR_DMX_UNMATCH_CHAN  No matched channel is found.CNcomment:没有查询到匹配通道。CNend
\see \n
 N/A.CNcomment:无。CNend
*/
hi_s32 hi_tee_dmx_desc_get_chan_handle(hi_u32 dmx_id, hi_u32 pid, hi_u32 *chan_num, hi_handle chan[]);


/** @} */  /** <!-- ==== API Declaration End ==== */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __TEE_DESCRAMBLER_H__ */
