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
/** CNcomment:�ؼ���ģʽ */
typedef enum {
    HI_TEE_DMX_CA_ENTROPY_REDUCTION_CLOSE = 0, /* 64bit */
    HI_TEE_DMX_CA_ENTROPY_REDUCTION_OPEN, /* 48bit */

    HI_TEE_DMX_CA_ENTROPY_REDUCTION_MAX
} hi_tee_dmx_ca_entropy;

/* Key secure mode type */
/* CNcomment:Key��ȫģʽ���� */
typedef enum {
    HI_TEE_DMX_DESC_SECURE_MODE_TEE = 0, /* trustedzone security protection */ /* CNcomment:trustedzone��ȫ���� */
    HI_TEE_DMX_DESC_SECURE_MODE_NONE, /* no security protection */ /* CNcomment:�ް�ȫ���� */

    HI_TEE_DMX_DESC_SECURE_MODE_MAX
} hi_tee_dmx_desc_secure_mode;

/* Attribute of the key area. */
/* CNcomment:��Կ������ */
typedef struct {
    /* Descrambling protocol type of the descrambler */ /* CNcomment:����������Э������ */
    hi_tee_crypto_alg alg_type;
    /* CA Entropy reduction mode,for CSA2.0 */ /* CNcomment:�ؼ���ģʽ��CSA2.0��Ч */
    hi_tee_dmx_ca_entropy ca_entropy;
    /* Secure indication */ /* CNcomment:��ȫ��ʾ */
    hi_tee_dmx_desc_secure_mode key_secure_mode;
    /* Whether the keysloy will be created, when create descrambler */ /* CNcomment:����������ʱ�Ƿ񴴽�keyslot */
    hi_bool is_create_keyslot;
} hi_tee_dmx_desc_attr;

/** @} */  /** <!-- ==== Structure Definition end ==== */


/******************************* API Declaration *****************************/
/** \addtogroup      Descrambler */
/** @{ */  /** <!--[Descrambler] */

/**
\brief Creates a key area. The key area type and descrambling protocol type can be selected.CNcomment:����һ����Կ��,\n
֧��ѡ��߰�ȫCA�ͽ���Э�����͡�CNend
\attention \n
When an advanced CA key area is created, the descrambling protocol depends on the hardware and interface settings are\n
ignored.\n
CNcomment:����Ǹ߰�ȫCA������Э���Ѿ���Ӳ���������ӿڵ����ñ����ԡ�CNend
\param[in] dmx_id   DEMUX ID. CNcomment: DEMUX�š�CNend
\param[in] attr  Pointer to the attributes of a key area.CNcomment:��Կ������ָ�롣CNend
\param[out] handle      Pointer to the handle of a created key area.CNcomment:ָ�����ͣ�������뵽����Կ��Handle��CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\retval ::HI_ERR_DMX_NOFREE_KEY  There is no available key area.CNcomment:û�п��е���Կ����CNend
\retval ::HI_ERR_DMX_NOT_SUPPORT  Not support HI_UNF_DMX_DESCRAMBLER_ATTR_S type.CNcomment:��֧�ֵ�\n
HI_UNF_DMX_DESCRAMBLER_ATTR_S���͡�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_create(hi_u32 dmx_id, const hi_tee_dmx_desc_attr *attr, hi_handle *handle);

/**
\brief Destroys an existing key area.CNcomment:���ٴ�������Կ����CNend
\attention \n
If a key area is attached to a channel, the key area needs to be detached from the channel first, but the channel is \n
not disabled.\n
If a key area is detached or destroyed before the attached channel is disabled, an error may occur during data \n
receiving.
CNcomment:�����Կ������ͨ���ϣ����ȴ�ͨ���Ͻ����Կ��������ע�ⲻ��ر�ͨ��\n
���û�йر�ͨ���������Կ���Ľ�󶨻����ٲ��������ܵ������ݽ��յĴ���CNend
\param[in] handle  Handle of the key area to be destroyed.CNcomment:��ɾ������Կ��Handle��CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_destroy(hi_handle handle);

/**
\brief Gets the attributes of a Descrambler.CNcomment:��ȡ��Կ�������ԡ�CNend
\attention \n
NA.\n
CNcomment:�ޡ�CNend
\param[in] handle   key handle. CNcomment: key�����CNend
\param[out] attr  Pointer to the attributes of a key area.CNcomment:��Կ������ָ�롣CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\retval ::HI_ERR_DMX_NOFREE_KEY  There is no available key area.CNcomment:û�п��е���Կ����CNend
\retval ::HI_ERR_DMX_NOT_SUPPORT  Not support HI_UNF_DMX_DESCRAMBLER_ATTR_S type.CNcomment:��֧�ֵ�\n
HI_UNF_DMX_DESCRAMBLER_ATTR_S���͡�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_get_attr(hi_handle handle, hi_tee_dmx_desc_attr *attr);

/**
\brief Sets the attributes of a Descrambler.CNcomment:������Կ�������ԡ�CNend
\attention \n
NA.\n
CNcomment:�ޡ�CNend
\param[in] handle   key handle. CNcomment: key�����CNend
\param[out] attr  Pointer to the attributes of a key area.CNcomment:��Կ������ָ�롣CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\retval ::HI_ERR_DMX_NOFREE_KEY  There is no available key area.CNcomment:û�п��е���Կ����CNend
\retval ::HI_ERR_DMX_NOT_SUPPORT  Not support HI_UNF_DMX_DESCRAMBLER_ATTR_S type.CNcomment:��֧�ֵ�\n
HI_UNF_DMX_DESCRAMBLER_ATTR_S���͡�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_set_attr(hi_handle handle, const hi_tee_dmx_desc_attr *attr);

/**
\brief Set system key,only used for multi2 algs.CNcomment:����ϵͳ��Կ��ֻ����multi2�㷨���͡�CNend
\attention \n
pu8SysKey points to the system key data to be set.The data length is specified by parameter u32SysKeyLen,ususlly the \n
length is 32 Bytes.\n
The system key value can be set before or after setting IV key and clear key,and just need to set it once each \n
taransport stream.
CNcomment:pu8SysKeyָ��Ҫ���õ�ϵͳ��Կ���ݡ���Կ���ݵĳ����ɲ���u32SysKeyLenָ����ͨ�������32�ֽڳ��ȡ�\n
ϵͳ��Կ����������IV��������Կ��֮ǰ����֮������,����ÿ������ֻ��Ҫ����һ�Ρ�CNend
\param[in] handle  Handle of the key area to be set.CNcomment:�����õ���Կ�������CNend
\param[in] sys_key    Pointer to the system key data to be set.CNcomment:ָ�����ͣ�ָ��Ҫ���õ�ϵͳ��Կ���ݡ�CNend
\param[in] sys_key  The length of system key.CNcomment:�����õ���Կ�ĳ��ȡ�CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_set_sys_key(hi_handle handle, const hi_u8 *sys_key, hi_u32 sys_key_len);

/**
\brief Set Even IV.For algs do not use IV,do not care.CNcomment:����ż��Կ���ĳ�ʼ�����������ڲ��漰��ʼ�������Ľ���\n
�㷨���Բ���ע��CNend
\attention \n
pu8IVKey points to the iv key data to be set.The data consists of 16 bytes: CW1, CW2, ..., and CW16.\n
The key value can be set dynamically, that is, the key value can be set at any time after a key area is created.
CNcomment:pu8IVKeyָ��Ҫ���õĳ�ʼ���������ݡ�����Կ���ݹ�16byte��byte������CW1��CW2��������CW16\n
֧����Կ���Ķ�̬���ã���������Կ������������ʱ�����á�CNend
\param[in] handle  Handle of the key area to be set.CNcomment:�����õ���Կ�������CNend
\param[in] even_iv   Pointer to the 16-byte IV key data to be set.CNcomment:ָ�����ͣ�ָ��Ҫ���õ�����Կ���ݣ�������16\n
���ֽڵ����顣CNend
\param[in] even_iv_len   The length of even IV key data to be set.CNcomment:�����õ�ż��Կ���ݵĳ��ȡ�CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_set_even_iv(hi_handle handle, const hi_u8 *even_iv, hi_u32 even_iv_len);

/**
\brief Set Odd IV.For algs do not use IV,do not care.CNcomment:��������Կ���ĳ�ʼ�����������ڲ��漰��ʼ�������Ľ���\n
�㷨���Բ���ע��CNend
\attention \n
pu8IVKey points to the iv key data to be set.The data consists of 16 bytes: CW1, CW2, ..., and CW16.\n
The key value can be set dynamically, that is, the key value can be set at any time after a key area is created.
CNcomment:pu8IVKeyָ��Ҫ���õĳ�ʼ���������ݡ�����Կ���ݹ�16byte��byte������CW1��CW2��������CW16\n
֧����Կ���Ķ�̬���ã���������Կ������������ʱ�����á�CNend
\param[in] handle  Handle of the key area to be set.CNcomment:�����õ���Կ�������CNend
\param[in] odd_iv    Pointer to the 16-byte IV key data to be set.CNcomment:ָ�����ͣ�ָ��Ҫ���õ�����Կ���ݣ�������\n
16���ֽڵ����顣CNend
\param[in] odd_iv_len   The length of odd IV key data to be set.CNcomment:�����õ�����Կ���ݵĳ��ȡ�CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_set_odd_iv(hi_handle handle, const hi_u8 *odd_iv, hi_u32 odd_iv_len);

/**
\brief Attaches a keyslot  to a key area.CNcomment:��keyslot��ָ������Կ����CNend
\attention \n
A keyslot can be attached to multiple keys.\n
The key area can obtain the key value from the keyslot module.\n
The same keyslot or different keyslot cannot be attached to the same key area.
CNcomment:һ��keyslot���԰󶨵������Կ���ϡ�\n
�󶨺����Կ�����Դ�keyslotģ���ȡ��Կֵ��\n
�������ظ�����ͬ��ͬ��keyslot��ͬһ����Կ���ϡ�CNend
\param[in] handle    Handle of the key area to be attached.CNcomment:���󶨵���Կ�������CNend
\param[in] ks_handle   Keyslot handle.CNcomment:Keyslot�����CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_ATTACHED_KEY  A keyslot is attached to the key area.CNcomment:��Կ���Ѿ�����һ��keyslot��CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_attach_key_slot(hi_handle handle, hi_handle ks_handle);

/**
\brief Detaches the keyslot handle of a key area.CNcomment:���ָ����Կ����keyslot�����CNend
\attention \n
You can detach the keyslot at any time after the key area is created.\n
Detach can be successfully performed even if the key area is not attach to keyslot.\n
After detach the keyslot, the key area will not be able to get the key value from the keyslot module.
CNcomment:��������Կ����������κ�ʱ�̽��keyslot��\n
��ʹ��Կ��û�а�keyslot���Ҳ���Գɹ�ִ�н�󶨡�\n
���keyslot֮����Կ�������ܴ�keyslotģ���ȡ��Կֵ��CNend
\param[in] handle    Handle of the key area to be attached.CNcomment:����󶨵���Կ�������CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_detach_key_slot(hi_handle handle);

/**
\brief Get the keyslot handle of a key area.CNcomment:��ȡָ����Կ����keyslot�����CNend
\attention \n
Used to get the detached keyslot handle from the specified key area.\n
If the key area did not attach to a keyslot, it will return failure.\n
CNcomment:���ڴ�ָ������Կ����ȡ�󶨵�keyslot�����\n
�����Կ��û�а�keyslot����᷵��ʧ�ܡ�CNend
\param[in] handle    Handle of the key area to be attached.CNcomment:ָ������Կ�������CNend
\param[out] ks_handle   Pointer to the handle of the keyslot that is attached to a key area (output).CNcomment:\n
ָ�����ͣ������Կ���󶨵�keyslot�����CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_NOATTACH_KEY A keyslot is not attached to the key area.CNcomment:��Կ����û�а�һ��keyslot��CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_get_key_slot_handle(hi_handle handle, hi_handle *ks_handle);

/**
\brief Attaches a key area to a specific pid channel.CNcomment:����Կ����ָ����pidͨ����CNend
\attention \n
A key area can be attached to multiple pid channels that belong to different DEMUXs.\n
The static loading data in the key areas that are attached to all types of channels can be descrambled.\n
The same key area or different key areas cannot be repeatedly attached to the same pid channel.
CNcomment:һ����Կ�����԰󶨵����pidͨ���ϣ�ͨ���������ڲ�ͬ��DEMUX\n
���Զ��������͵�ͨ������Կ���������ݵĽ���\n
�������ظ�����ͬ��ͬ����Կ����ͬһ��pidͨ���ϡ�CNend
\param[in] handle    Handle of the key area to be attached.CNcomment:���󶨵���Կ�������CNend
\param[in] pid_chan   Pid channel handle.CNcomment:Pidͨ�������CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_ATTACHED_KEY  A key area is attached to the channel.CNcomment:ͨ�����Ѿ���һ����Կ���������档\n
CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_attach_pid_chan(hi_handle handle, hi_handle pid_chan);

/**
\brief Detaches a key area from a pid channel.CNcomment:����Կ����pidͨ���Ͻ�󶨡�CNend
\attention \n
The key area used by a pid channel can be detached dynamically. That is, you can call this API to detach a key area \n
at any time after it is attached.\n
The scrambled data, however, may not be descrambled after the key area is detached, which causes data error.\n
The value of a key area retains even after it is detached. If the key area is attached again, its value is still the \n
previously configured value.\n
If you do not want to descramble data, you can detach the corresponding key area or set all key values to 0.
CNcomment:���Զ�̬�Ľ��pidͨ��ʹ�õ���Կ���������ڰ󶨺������ʱ��ʹ�ô˽ӿڽ����Կ��\n
���ǽ�󶨺���ܵ��¼�������û�б����ţ��������ݴ���\n
�����Կ�������ܸı���Կ����ֵ��������°���Կ������Կֵ��Ȼ���ϴ����õ�ֵ\n
���������н��ţ����˽����Կ��֮�⣬Ҳ����ֱ�ӽ���Կֵȫ������Ϊ0��ʵ�֡�CNend
\param[in] handle    Handle of the key area to be detached.CNcomment:����󶨵���Կ�������CNend
\param[in] pid_chan  Pid channel handle.CNcomment:Pidͨ�������CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_NOATTACH_KEY  No key areas are attached to the channel.CNcomment:ͨ����û�а��κ���Կ����CNend
\retval ::HI_ERR_DMX_UNMATCH_KEY  The specified key area is not attached to the specified channel.CNcomment:ָ����\n
��Կ��û�а���ָ����ͨ���ϡ�CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_detach_pid_chan(hi_handle handle, hi_handle pid_chan);


/**
\brief Obtains the handle of the key area that is attached to a channel.CNcomment:��ȡͨ���󶨵���Կ�������CNend
\attention \n
If no key area is attached to the channel, the error code HI_ERR_DMX_NOATTACH_KEY is returned when you call this API.
CNcomment:��ͨ��û�а���Կ��ʱ�����ñ��ӿڷ���HI_ERR_DMX_NOATTACH_KEY�����롣CNend
\param[in] pid_chan  Handle of the pid channel to be queried.CNcomment:Ҫ��ѯ��pidͨ�������CNend
\param[out] desc_handle  Pointer to the handle of the key area that is attached to a channel (output).CNcomment:\n
ָ�����ͣ����ͨ���󶨵���Կ�������CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\retval ::HI_ERR_DMX_NOATTACH_KEY  No key areas are attached to the channel.CNcomment:ͨ����û�а��κ���Կ����CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_get_handle(hi_handle pid_chan, hi_handle *desc_handle);

/**
\brief Obtains the handle of the channel with a specific PID.CNcomment:��ȡ����ĳPID��ͨ�������CNend
\attention \n
You must specify the DEMUX ID when calling this API, because the channel PIDs of different DEMUXs can be the same.\n
You cannot query the PID that is equal to or greater than 0x1FFF; otherwise, the error code HI_ERR_DMX_INVALID_PARA
is returned.\n
If no channel with a specific PID is found, an error code is returned.
CNcomment:��ͬDEMUX�豸��ͨ������������ͬ��PID�����ñ��ӿ���Ҫָ��DEMUX ID\n
�������ѯ0x1fff�����ϵķǷ�PIDֵ�����򷵻ز����Ƿ�������\n
���û�в�ѯ���κ�ͨ��������Ҫ��ѯ��PID�������ش����롣CNend
\param[in] dmx_id    DEMUX ID. CNcomment: DEMUX�š�CNend
\param[in] pid      Channel PID.CNcomment:ͨ��PID��CNend
\param[out] chan_num  Point to channel handle number.CNcomment: ָ�����ͣ�ָ�����ͨ��Handle�ĸ�����CNend
\param[out] chan   An array to store channel handle.CNcomment: �������ͣ����ڴ洢���ͨ��Handle��CNend
\retval ::HI_SUCCESS Success.CNcomment:�ɹ���CNend
\retval ::HI_FAILURE  Calling this API fails.CNcomment:APIϵͳ����ʧ�ܡ�CNend
\retval ::HI_ERR_DMX_NOT_INIT  The DEMUX module is not initialized.CNcomment:ģ��û�г�ʼ����CNend
\retval ::HI_ERR_DMX_INVALID_PARA  The input parameter is invalid. CNcomment:��������Ƿ���CNend
\retval ::HI_ERR_DMX_NULL_PTR  The pointer is null. CNcomment:ָ�����Ϊ�ա�CNend
\retval ::HI_ERR_DMX_UNMATCH_CHAN  No matched channel is found.CNcomment:û�в�ѯ��ƥ��ͨ����CNend
\see \n
 N/A.CNcomment:�ޡ�CNend
*/
hi_s32 hi_tee_dmx_desc_get_chan_handle(hi_u32 dmx_id, hi_u32 pid, hi_u32 *chan_num, hi_handle chan[]);


/** @} */  /** <!-- ==== API Declaration End ==== */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __TEE_DESCRAMBLER_H__ */
