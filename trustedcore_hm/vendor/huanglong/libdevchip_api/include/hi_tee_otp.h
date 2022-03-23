/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: brief Describes the information about the otp module.
 * Author: Hisilicon hisecurity team
 * Create: 2019-07-23
 */

#ifndef __HI_TEE_OTP_H__
#define __HI_TEE_OTP_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* ************************** Structure Definition *************************** */
/* \addtogroup      OTP */
/* @{ */  /* <!-- [OTP] */

#define FIELD_VALUE_LEN 1024
#define FIELD_NAME_LEN  32

/* Rootkey type */
typedef enum {
    HI_TEE_OTP_BOOT_ROOTKEY0       = 0x0,
    HI_TEE_OTP_OEM_ROOTKEY0,
    HI_TEE_OTP_CAS_ROOTKEY0        = 0x10,
    HI_TEE_OTP_CAS_ROOTKEY1,
    HI_TEE_OTP_CAS_ROOTKEY2,
    HI_TEE_OTP_CAS_ROOTKEY3,
    HI_TEE_OTP_CAS_ROOTKEY4,
    HI_TEE_OTP_CAS_ROOTKEY5,
    HI_TEE_OTP_CAS_ROOTKEY6,
    HI_TEE_OTP_CAS_ROOTKEY7,
    HI_TEE_OTP_ROOTKEY_MAX
} hi_tee_otp_rootkey;

/* TA MSID(Trusted Application Market Segment ID) */
typedef enum {
    HI_TEE_OTP_TA_INDEX_1 = 0,
    HI_TEE_OTP_TA_INDEX_2,
    HI_TEE_OTP_TA_INDEX_3,
    HI_TEE_OTP_TA_INDEX_4,
    HI_TEE_OTP_TA_INDEX_5,
    HI_TEE_OTP_TA_INDEX_6,
    HI_TEE_OTP_TA_INDEX_7,
    HI_TEE_OTP_TA_INDEX_8,
    HI_TEE_OTP_TA_INDEX_9,
    HI_TEE_OTP_TA_INDEX_10,
    HI_TEE_OTP_TA_INDEX_11,
    HI_TEE_OTP_TA_INDEX_12,
    HI_TEE_OTP_TA_INDEX_13,
    HI_TEE_OTP_TA_INDEX_MAX
} hi_tee_otp_ta_index;

/* Chip ID selection */
typedef enum {
    HI_TEE_OTP_CHIPID0 = 0,
    HI_TEE_OTP_CHIPID1,
    HI_TEE_OTP_CHIPID2,
    HI_TEE_OTP_CHIPID_MAX,
} hi_tee_otp_chipid_sel;

/* Rootkey slot flag. */
typedef union {
    struct {
        hi_u32    bb_owner_id  : 7 ; /* [6..0] Black box owner ID */
        hi_u32    reserved_0   : 1 ; /* [7] */
        hi_u32    ca_owner_id  : 8 ; /* [15..8] CA owner ID */
        hi_u32    reserved_1   : 2 ; /* [17..16] */
        hi_u32    chip_id_sel  : 2 ; /* [19..18] Chip ID selection, come from hi_tee_otp_chipid_sel */
        hi_u32    reserved_2   : 5 ; /* [24..20] */
        hi_u32    rk_disable   : 1 ; /* [25]  If disabled, this key can not be used any more. */
        hi_u32    reserved_3   : 6 ; /* [31..26] */
    } bits;
    hi_u32 slot_flag;
} hi_tee_otp_rootkey_slot_flag;

/* @} */  /* <!-- ==== Structure Definition end ==== */

/* ****************************** API declaration **************************** */
/* \addtogroup      OTP */
/* @{ */  /* <!-- [OTP] */

#define hi_tee_otp_open(hi_void) hi_tee_otp_init(hi_void)

#define hi_tee_otp_close(hi_void) hi_tee_otp_deinit(hi_void)

/*
\brief Initializes the otp module. CNcomment:初始化OTP模块 CNend
\attention \n
Before calling other functions in this file, you must call this application programming interface (API).
CNcomment 在调用OTP模块其他接口前，要求首先调用本接口 CNend
\param N/A                                          CNcomment:无。 CNend
\retval ::HI_SUCCESS  Success.                      CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE  Failure.                      CNcomment:API系统调用失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_init(hi_void);

/*
\brief Deinitializes the otp module. CNcomment:去初始化OTP设备 CNend
\attention \n
N/A
\param N/A                                          CNcomment:无。 CNend
\retval ::HI_SUCCESS  Success.                      CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE  Failure.                      CNcomment:API系统调用失败 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_deinit(hi_void);

/*
\brief reset the otp device.
\brief CNcomment:复位OTP设备。 CNend
\attention \n
N/A
\param N/A                                          CNcomment:无。 CNend
\retval ::HI_SUCCESS  Call this API successful.     CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.          CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_reset(hi_void);

/*
\brief Get the device ca chip ID.
\brief CNcomment:获取高安芯片ID。 CNend
\attention \n
\param[in] chip_id_sel , Chip ID select.                                CNcomment:芯片ID选择 CNend
\param[in] chip_id point to chip id.                                    CNcomment:指针类型，芯片ID CNend
\param[in/out] len The length of chip ID, current is 8.                 CNcomment:芯片ID长度，8 CNend
\retval ::HI_SUCCESS Success.                                           CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Failure.                                           CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.        CNcomment:OTP未初始化 CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.       CNcomment:输入参数非法 CNend
\retval ::HI_ERR_OTP_SETPARAM_AGAIN The parameter has been set already. CNcomment:重复设置 CNend
\see \n
None CNcomment:无 CNend
*/
hi_s32 hi_tee_otp_get_ca_chip_id(hi_tee_otp_chipid_sel chip_id_sel, hi_u8 *chip_id, hi_u32 *len);

/*
\brief Get the device chip ID.
\brief CNcomment:获取设备芯片标识。 CNend
\attention \n
\param[in] chip_id point to chip id.                                    CNcomment:指针类型，芯片ID CNend
\param[in] len The length of chip ID, current is 8.                     CNcomment:芯片ID长度，8 CNend
\retval ::HI_SUCCESS Success.                                           CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Failure.                                           CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.        CNcomment:OTP未初始化 CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.       CNcomment:输入参数非法 CNend
\retval ::HI_ERR_OTP_SETPARAM_AGAIN The parameter has been set already. CNcomment:重复设置 CNend
\see \n
None CNcomment:无 CNend
*/
hi_s32 hi_tee_otp_get_chip_id(hi_u8 *chip_id, hi_u32 *len);

/*
\brief Read otp value by word.
\brief CNcomment按字读取OTP的值。 CNend
\attention \n
N/A
\param[in] addr:  OTP address.                              CNcomment:OTP 地址。 CNend
\param[out] value:  Buffer to store the otp by word.        CNcomment:存储按字获取OTP值的缓冲区指针。 CNend
\retval ::HI_SUCCESS  Call this API successful.             CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.                  CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_read_word(hi_u32 addr, hi_u32 *value);

/*
\brief Read otp value by byte.
\brief CNcomment按字节读取OTP的值。 CNend
\attention \n
N/A
\param[in] addr:  OTP address.                              CNcomment:OTP 地址。 CNend
\param[out] value:  Buffer to store the otp by word.        CNcomment:存储按字节获取OTP值的缓冲区指针。 CNend
\retval ::HI_SUCCESS  Call this API successful.             CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.                  CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_read_byte(hi_u32 addr, hi_u8 *value);

/*
\brief Write otp value by byte.
\brief CNcomment按字节写OTP的值。 CNend
\attention \n
N/A
\param[in] addr:  OTP address.                          CNcomment:OTP 地址。 CNend
\param[in] value:   value to be write.                  CNcomment:待写入OTP的值。 CNend
\retval ::HI_SUCCESS  Call this API successful.         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.              CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_write_byte(hi_u32 addr, hi_u8 value);

/*
\brief Get  secure OS version
\brief CNcomment 获取安全OS版本号。 CNend
\attention \n
N/A
\param[out] version: antirollback version.              CNcomment:版本号。 CNend
\retval ::HI_SUCCESS  Call this API successful.         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.              CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_sec_version(hi_u32 *version);

/*
\brief Set root key to otp. CNcomment:向芯片内部设置根密钥 CNend
\attention \n
N/A
\param[in] enRootKeySlot:   Slot of rootkey.                            CNcomment:根密钥Slot CNend
\param[in] pu8RootKey: Point to root key value.                         CNcomment:指针类型，根密钥 CNend
\param[in] u32Len: The length of root key.                              CNcomment:根密钥长度 CNend
\retval ::HI_SUCCESS Success                                            CNcomment:HI_SUCCESS 成功 CNend
\retval ::HI_FAILURE This API fails to be called                        CNcomment:HI_FAILURE  API系统调用失败 CNend
\retval ::HI_ERR_CA_NOT_INIT The advanced CA module is not initialized  CNcomment:HI_ERR_CA_NOT_INIT  CA未初始化 CNend
\retval ::HI_ERR_CA_INVALID_PARA The input parameter value is invalid   CNcomment:HI_ERR_CA_INVALID_PARA  输入参数非法 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_set_root_key(hi_tee_otp_rootkey root_key_slot, const hi_u8 *root_key, hi_u32 len);

/*
\brief Get root key lock status.                    CNcomment:获取OTP锁状态信息 CNend
\attention \n
N/A
\param[in] enRootKeySlot: Slot of rootkey.                              CNcomment:根密钥Slot CNend
\param[out] pbLock: Point to root key lock status.                      CNcomment:指针类型，跟密钥是否被锁 CNend
\retval ::HI_SUCCESS Success                                            CNcomment:HI_SUCCESS 成功 CNend
\retval ::HI_FAILURE This API fails to be called                        CNcomment:HI_FAILURE  API系统调用失败 CNend
\retval ::HI_ERR_CA_NOT_INIT The advanced CA module is not initialized  CNcomment:HI_ERR_CA_NOT_INIT  CA未初始化 CNend
\retval ::HI_ERR_CA_INVALID_PARA The input parameter value is invalid   CNcomment:HI_ERR_CA_INVALID_PARA  输入参数非法 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_root_key_lock_stat(hi_tee_otp_rootkey root_key_slot, hi_bool *lock);

/*
\brief Chip ID select. CNcomment:芯片ID选择 CNend
\attention \n
\param[in] enRootKeySlot Slot of root key.                              CNcomment:根密钥的Slot选择，芯片ID CNend
\param[in] pstSlotFlag , Point to the flag of specified rootkey slot.   CNcomment:指定根密钥槽位的标记。CNend
\retval ::HI_SUCCESS Success.                                           CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Failure.                                           CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.        CNcomment:OTP未初始化 CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.       CNcomment:输入参数非法 CNend
\retval ::HI_ERR_OTP_SETPARAM_AGAIN The parameter has been set already. CNcomment:重复设置 CNend
\see \n
None CNcomment:无 CNend
*/
hi_s32 hi_tee_otp_set_root_key_slot_flag(hi_tee_otp_rootkey root_key_slot,
                                         const hi_tee_otp_rootkey_slot_flag *pst_slot_flag);

/*
\brief Chip ID select. CNcomment:芯片ID选择 CNend
\attention \n
\param[in] enRootKeySlot Slot of root key.                              CNcomment:根密钥的Slot选择，芯片ID CNend
\param[in] pstSlotFlag , Point to the flag of specified rootkey slot.   CNcomment:指定根密钥槽位的标记。CNend
\retval ::HI_SUCCESS Success.                                           CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Failure.                                           CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.        CNcomment:OTP未初始化 CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.       CNcomment:输入参数非法 CNend
\retval ::HI_ERR_OTP_SETPARAM_AGAIN The parameter has been set already. CNcomment:重复设置 CNend
\see \n
None CNcomment:无 CNend
*/
hi_s32 hi_tee_otp_get_root_key_slot_flag(hi_tee_otp_rootkey root_key_slot, hi_tee_otp_rootkey_slot_flag *pst_slot_flag);

/*
\brief Set ta certificate version
\brief CNcomment 设置TA证书版本号。 CNend
\attention \n
N/A
\param[in] index:     TA index.                     CNcomment:TA 索引 CNend
\param[in] version:  version.                       CNcomment:版本号  CNend
\retval ::HI_SUCCESS  Call this API successful.     CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.          CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_set_ta_certificate_version(hi_tee_otp_ta_index index, hi_u32 version);

/*
\brief Get ta certificate version
\brief CNcomment 获取TA证书版本号。 CNend
\attention \n
N/A
\param[in] index:  TA index.                        CNcomment:TA 索引 CNend
\param[out] version:  the point of version.         CNcomment:获取版本号指针  CNend
\retval ::HI_SUCCESS  Call this API successful.     CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.          CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_ta_certificate_version(hi_tee_otp_ta_index index, hi_u32 *version);

/*
\brief Set ta secure version
\brief CNcomment 设置TA版本号。 CNend
\attention \n
N/A
\param[in] index:     TA index.                                             CNcomment:TA 索引 CNend
\param[in] version:  version.                                               CNcomment:版本号  CNend
\retval ::HI_SUCCESS  Call this API successful.                             CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.                                  CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_set_ta_secure_version(hi_tee_otp_ta_index index, hi_u32 version);

/*
\brief Get ta secure version
\brief CNcomment 获取TA版本号。 CNend
\attention \n
N/A
\param[in] index:     TA index.                     CNcomment:TA 索引 CNend
\param[out] version:  the point of version.         CNcomment:获取版本号指针  CNend
CNcomment:存放需要读取的数据长度，同时驱动返回真实的读取长度。  CNend
\retval ::HI_SUCCESS  Call this API successful.     CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.          CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_ta_secure_version(hi_tee_otp_ta_index index, hi_u32 *version);

/*
\brief Sets TA ID and TA market segment ID. CNcomment:设置TA ID和TA市场区域码  CNend
\attention \n
None CNcomment:无 CNend
\param[in] enIndex: TA ID and TA market segment ID index.           CNcomment:TA ID和TA市场区域码的索引  CNend
\param[in] u32TAID: TA ID.                                          CNcomment:TA ID CNend
\param[in] u32MSID: TA market Segment ID.                           CNcomment:TA市场区域码 CNend
\retval ::HI_SUCCESS Success.                                       CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Failure.                                       CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.    CNcomment:OTP未初始化 CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.   CNcomment:输入参数非法 CNend
\see \n
None CNcomment:无 CNend
*/
hi_s32 hi_tee_otp_set_taid_and_msid(hi_tee_otp_ta_index index, hi_u32 taid, hi_u32 msid);

/*
\brief Get TA ID and TA market segment ID. CNcomment:获取TA ID和TA市场区域码  CNend
\attention \n
None CNcomment:无 CNend
\param[in] enIndex: TA ID and TA market segment ID index.           CNcomment:TA ID和TA市场区域码的索引  CNend
\param[out] pu32TAID: TA ID.                                        CNcomment:指针类型，TA ID CNend
\param[out] pu32MSID: TA market segment ID.                         CNcomment:指针类型，TA市场区域码 CNend
\retval ::HI_SUCCESS Success.                                       CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Failure.                                       CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.    CNcomment:OTP未初始化 CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.   CNcomment:输入参数非法 CNend
\see \n
None CNcomment:无 CNend
*/
hi_s32 hi_tee_otp_get_taid_and_msid(hi_tee_otp_ta_index index, hi_u32 *taid, hi_u32 *msid);

/*
\brief Get ta index
\brief CNcomment 根据TA ID号获取索引值。 CNend
\attention \n
N/A
\param[in] taid:     TA ID.                         CNcomment:TA ID号 CNend
\param[out] index:    the point of TA index.        CNcomment:获取TA索引的指针  CNend
\retval ::HI_SUCCESS  Call this API successful.     CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.          CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_ta_index(hi_u32 taid, hi_tee_otp_ta_index *index);

/*
\brief Get ta index
\brief CNcomment 获取可用的索引值。 CNend
\attention \n
N/A
\param[out] index:    the point of available TA index.  CNcomment:获取可用TA索引的指针  CNend
\retval ::HI_SUCCESS  Call this API successful.         CNcomment:API系统调用成功。 CNend
\retval ::HI_FAILURE  Call this API fails.              CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_available_ta_index(hi_tee_otp_ta_index *index);

/*
\brief Get DRM private data information from OTP area.
\brief CNcomment 从OTP空间获取DRM私有数据信息。 CNend
\attention \n
This function is only used for hisilicon Playready and Widevine scenes,
if CAS has a separate DRM program, can not use this interface to read and write data.
CNcomment:此函数仅仅是用于海思Playready/Widevine场景，如果CAS有自己独立的DRM方案，不能使用此接口读写数据。 CNend
\param[in] offset: Offset address of read DRM data area.                            CNcomment:读取的DRM数据区的偏移地址 CNend
\param[out] data: the point of buffer used to store the DRM data information.       CNcomment:指向存放读取数据的内存空间。  CNend
\param[in/out] data_len: Store the length of the data that needs to be read,
and at the same time the driver returns the actual read length.
CNcomment:存放需要读取的数据长度，同时驱动返回真实的读取长度。  CNend
\retval :HI_SUCCESS  Call this API successful.                                      CNcomment:API系统调用成功。 CNend
\retval :HI_ERR_OTP_NULL_PTR  Parameter is a null pointer.                          CNcomment:参数为空指针。 CNend
\retval :HI_ERR_OTP_INVALID_PARAM  Parameter is invalid.                            CNcomment:参数不可用。 CNend
\retval :HI_FAILURE  Call this API fails.                                           CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_priv_drm_data(hi_u32 offset, hi_u8 *data, hi_u32 *data_len);

/*
\brief Set DRM private data information to OTP area.
\brief CNcomment 写入DRM私有数据信息到OTP空间。 CNend
\attention \n
1:This function is only used for hisilicon Playready and Widevine scenes,
if CAS has a separate DRM program, can not use this interface to read and write data.
2:Offset must be 16 bytes aligned.
CNcomment:1:此函数仅仅是用于海思Playready/Widevine场景，如果CAS有自己独立的DRM方案，不能使用此接口读写数据。
2:Offset必须16字节对齐。CNend
\param[in] offset: Offset address of read DRM data area.                            CNcomment:读取的DRM数据区的偏移地址 CNend
\param[in] data: the point of buffer used to store the DRM data information.        CNcomment:指向存放待写入数据的内存空间。 CNend
\param[in] data_len: Store the length of the data that needs to be witten.          CNcomment:存放需要写入的数据长度。 CNend
\retval :HI_SUCCESS  Call this API successful.                                      CNcomment:API系统调用成功。 CNend
\retval :HI_ERR_OTP_NULL_PTR  Parameter is a null pointer.                          CNcomment:参数为空指针。 CNend
\retval :HI_ERR_OTP_INVALID_PARAM  Parameter is invalid.                            CNcomment:参数不可用。 CNend
\retval :HI_FAILURE  Call this API fails.                                           CNcomment:API系统调用失败。 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_set_priv_drm_data(hi_u32 offset, const hi_u8 *data, hi_u32 data_len);

/*
\brief Get runtime-check status CNcomment:获取运行时校验状态使能标记  CNend
\attention \n
None CNcomment:无 CNend
\param[out] enable Point to runtime Check status.                   CNcomment:指针类型，运行时校验使能状态 CNend
\retval ::HI_SUCCESS Success.                                       CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Failure.                                       CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.    CNcomment:OTP未初始化 CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.   CNcomment:输入参数非法 CNend
\see \n
None CNcomment:无 CNend
*/
hi_s32 hi_tee_otp_get_runtime_check_stat(hi_bool *enable);

/*
\brief Enable runtime-check. CNcomment:设置运行时校验功能使能 CNend
\attention \n
None CNcomment:无 CNend
\param[in]  None
\retval ::HI_SUCCESS Success.                                       CNcomment:API系统调用成功 CNend
\retval ::HI_FAILURE Failure.                                       CNcomment:API系统调用失败 CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.    CNcomment:OTP未初始化 CNend
\see \n
None CNcomment:无 CNend
*/
hi_s32 hi_tee_otp_enable_runtime_check(hi_void);


/* @} */  /* <!-- ==== API declaration end ==== */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_TEE_OTP_H__ */
