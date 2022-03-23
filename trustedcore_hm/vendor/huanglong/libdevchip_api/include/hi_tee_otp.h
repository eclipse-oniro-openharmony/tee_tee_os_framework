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
\brief Initializes the otp module. CNcomment:��ʼ��OTPģ�� CNend
\attention \n
Before calling other functions in this file, you must call this application programming interface (API).
CNcomment �ڵ���OTPģ�������ӿ�ǰ��Ҫ�����ȵ��ñ��ӿ� CNend
\param N/A                                          CNcomment:�ޡ� CNend
\retval ::HI_SUCCESS  Success.                      CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE  Failure.                      CNcomment:APIϵͳ����ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_init(hi_void);

/*
\brief Deinitializes the otp module. CNcomment:ȥ��ʼ��OTP�豸 CNend
\attention \n
N/A
\param N/A                                          CNcomment:�ޡ� CNend
\retval ::HI_SUCCESS  Success.                      CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE  Failure.                      CNcomment:APIϵͳ����ʧ�� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_deinit(hi_void);

/*
\brief reset the otp device.
\brief CNcomment:��λOTP�豸�� CNend
\attention \n
N/A
\param N/A                                          CNcomment:�ޡ� CNend
\retval ::HI_SUCCESS  Call this API successful.     CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.          CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_reset(hi_void);

/*
\brief Get the device ca chip ID.
\brief CNcomment:��ȡ�߰�оƬID�� CNend
\attention \n
\param[in] chip_id_sel , Chip ID select.                                CNcomment:оƬIDѡ�� CNend
\param[in] chip_id point to chip id.                                    CNcomment:ָ�����ͣ�оƬID CNend
\param[in/out] len The length of chip ID, current is 8.                 CNcomment:оƬID���ȣ�8 CNend
\retval ::HI_SUCCESS Success.                                           CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Failure.                                           CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.        CNcomment:OTPδ��ʼ�� CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.       CNcomment:��������Ƿ� CNend
\retval ::HI_ERR_OTP_SETPARAM_AGAIN The parameter has been set already. CNcomment:�ظ����� CNend
\see \n
None CNcomment:�� CNend
*/
hi_s32 hi_tee_otp_get_ca_chip_id(hi_tee_otp_chipid_sel chip_id_sel, hi_u8 *chip_id, hi_u32 *len);

/*
\brief Get the device chip ID.
\brief CNcomment:��ȡ�豸оƬ��ʶ�� CNend
\attention \n
\param[in] chip_id point to chip id.                                    CNcomment:ָ�����ͣ�оƬID CNend
\param[in] len The length of chip ID, current is 8.                     CNcomment:оƬID���ȣ�8 CNend
\retval ::HI_SUCCESS Success.                                           CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Failure.                                           CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.        CNcomment:OTPδ��ʼ�� CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.       CNcomment:��������Ƿ� CNend
\retval ::HI_ERR_OTP_SETPARAM_AGAIN The parameter has been set already. CNcomment:�ظ����� CNend
\see \n
None CNcomment:�� CNend
*/
hi_s32 hi_tee_otp_get_chip_id(hi_u8 *chip_id, hi_u32 *len);

/*
\brief Read otp value by word.
\brief CNcomment���ֶ�ȡOTP��ֵ�� CNend
\attention \n
N/A
\param[in] addr:  OTP address.                              CNcomment:OTP ��ַ�� CNend
\param[out] value:  Buffer to store the otp by word.        CNcomment:�洢���ֻ�ȡOTPֵ�Ļ�����ָ�롣 CNend
\retval ::HI_SUCCESS  Call this API successful.             CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.                  CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_read_word(hi_u32 addr, hi_u32 *value);

/*
\brief Read otp value by byte.
\brief CNcomment���ֽڶ�ȡOTP��ֵ�� CNend
\attention \n
N/A
\param[in] addr:  OTP address.                              CNcomment:OTP ��ַ�� CNend
\param[out] value:  Buffer to store the otp by word.        CNcomment:�洢���ֽڻ�ȡOTPֵ�Ļ�����ָ�롣 CNend
\retval ::HI_SUCCESS  Call this API successful.             CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.                  CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_read_byte(hi_u32 addr, hi_u8 *value);

/*
\brief Write otp value by byte.
\brief CNcomment���ֽ�дOTP��ֵ�� CNend
\attention \n
N/A
\param[in] addr:  OTP address.                          CNcomment:OTP ��ַ�� CNend
\param[in] value:   value to be write.                  CNcomment:��д��OTP��ֵ�� CNend
\retval ::HI_SUCCESS  Call this API successful.         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_write_byte(hi_u32 addr, hi_u8 value);

/*
\brief Get  secure OS version
\brief CNcomment ��ȡ��ȫOS�汾�š� CNend
\attention \n
N/A
\param[out] version: antirollback version.              CNcomment:�汾�š� CNend
\retval ::HI_SUCCESS  Call this API successful.         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_sec_version(hi_u32 *version);

/*
\brief Set root key to otp. CNcomment:��оƬ�ڲ����ø���Կ CNend
\attention \n
N/A
\param[in] enRootKeySlot:   Slot of rootkey.                            CNcomment:����ԿSlot CNend
\param[in] pu8RootKey: Point to root key value.                         CNcomment:ָ�����ͣ�����Կ CNend
\param[in] u32Len: The length of root key.                              CNcomment:����Կ���� CNend
\retval ::HI_SUCCESS Success                                            CNcomment:HI_SUCCESS �ɹ� CNend
\retval ::HI_FAILURE This API fails to be called                        CNcomment:HI_FAILURE  APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CA_NOT_INIT The advanced CA module is not initialized  CNcomment:HI_ERR_CA_NOT_INIT  CAδ��ʼ�� CNend
\retval ::HI_ERR_CA_INVALID_PARA The input parameter value is invalid   CNcomment:HI_ERR_CA_INVALID_PARA  ��������Ƿ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_set_root_key(hi_tee_otp_rootkey root_key_slot, const hi_u8 *root_key, hi_u32 len);

/*
\brief Get root key lock status.                    CNcomment:��ȡOTP��״̬��Ϣ CNend
\attention \n
N/A
\param[in] enRootKeySlot: Slot of rootkey.                              CNcomment:����ԿSlot CNend
\param[out] pbLock: Point to root key lock status.                      CNcomment:ָ�����ͣ�����Կ�Ƿ��� CNend
\retval ::HI_SUCCESS Success                                            CNcomment:HI_SUCCESS �ɹ� CNend
\retval ::HI_FAILURE This API fails to be called                        CNcomment:HI_FAILURE  APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_CA_NOT_INIT The advanced CA module is not initialized  CNcomment:HI_ERR_CA_NOT_INIT  CAδ��ʼ�� CNend
\retval ::HI_ERR_CA_INVALID_PARA The input parameter value is invalid   CNcomment:HI_ERR_CA_INVALID_PARA  ��������Ƿ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_root_key_lock_stat(hi_tee_otp_rootkey root_key_slot, hi_bool *lock);

/*
\brief Chip ID select. CNcomment:оƬIDѡ�� CNend
\attention \n
\param[in] enRootKeySlot Slot of root key.                              CNcomment:����Կ��Slotѡ��оƬID CNend
\param[in] pstSlotFlag , Point to the flag of specified rootkey slot.   CNcomment:ָ������Կ��λ�ı�ǡ�CNend
\retval ::HI_SUCCESS Success.                                           CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Failure.                                           CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.        CNcomment:OTPδ��ʼ�� CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.       CNcomment:��������Ƿ� CNend
\retval ::HI_ERR_OTP_SETPARAM_AGAIN The parameter has been set already. CNcomment:�ظ����� CNend
\see \n
None CNcomment:�� CNend
*/
hi_s32 hi_tee_otp_set_root_key_slot_flag(hi_tee_otp_rootkey root_key_slot,
                                         const hi_tee_otp_rootkey_slot_flag *pst_slot_flag);

/*
\brief Chip ID select. CNcomment:оƬIDѡ�� CNend
\attention \n
\param[in] enRootKeySlot Slot of root key.                              CNcomment:����Կ��Slotѡ��оƬID CNend
\param[in] pstSlotFlag , Point to the flag of specified rootkey slot.   CNcomment:ָ������Կ��λ�ı�ǡ�CNend
\retval ::HI_SUCCESS Success.                                           CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Failure.                                           CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.        CNcomment:OTPδ��ʼ�� CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.       CNcomment:��������Ƿ� CNend
\retval ::HI_ERR_OTP_SETPARAM_AGAIN The parameter has been set already. CNcomment:�ظ����� CNend
\see \n
None CNcomment:�� CNend
*/
hi_s32 hi_tee_otp_get_root_key_slot_flag(hi_tee_otp_rootkey root_key_slot, hi_tee_otp_rootkey_slot_flag *pst_slot_flag);

/*
\brief Set ta certificate version
\brief CNcomment ����TA֤��汾�š� CNend
\attention \n
N/A
\param[in] index:     TA index.                     CNcomment:TA ���� CNend
\param[in] version:  version.                       CNcomment:�汾��  CNend
\retval ::HI_SUCCESS  Call this API successful.     CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.          CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_set_ta_certificate_version(hi_tee_otp_ta_index index, hi_u32 version);

/*
\brief Get ta certificate version
\brief CNcomment ��ȡTA֤��汾�š� CNend
\attention \n
N/A
\param[in] index:  TA index.                        CNcomment:TA ���� CNend
\param[out] version:  the point of version.         CNcomment:��ȡ�汾��ָ��  CNend
\retval ::HI_SUCCESS  Call this API successful.     CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.          CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_ta_certificate_version(hi_tee_otp_ta_index index, hi_u32 *version);

/*
\brief Set ta secure version
\brief CNcomment ����TA�汾�š� CNend
\attention \n
N/A
\param[in] index:     TA index.                                             CNcomment:TA ���� CNend
\param[in] version:  version.                                               CNcomment:�汾��  CNend
\retval ::HI_SUCCESS  Call this API successful.                             CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.                                  CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_set_ta_secure_version(hi_tee_otp_ta_index index, hi_u32 version);

/*
\brief Get ta secure version
\brief CNcomment ��ȡTA�汾�š� CNend
\attention \n
N/A
\param[in] index:     TA index.                     CNcomment:TA ���� CNend
\param[out] version:  the point of version.         CNcomment:��ȡ�汾��ָ��  CNend
CNcomment:�����Ҫ��ȡ�����ݳ��ȣ�ͬʱ����������ʵ�Ķ�ȡ���ȡ�  CNend
\retval ::HI_SUCCESS  Call this API successful.     CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.          CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_ta_secure_version(hi_tee_otp_ta_index index, hi_u32 *version);

/*
\brief Sets TA ID and TA market segment ID. CNcomment:����TA ID��TA�г�������  CNend
\attention \n
None CNcomment:�� CNend
\param[in] enIndex: TA ID and TA market segment ID index.           CNcomment:TA ID��TA�г������������  CNend
\param[in] u32TAID: TA ID.                                          CNcomment:TA ID CNend
\param[in] u32MSID: TA market Segment ID.                           CNcomment:TA�г������� CNend
\retval ::HI_SUCCESS Success.                                       CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Failure.                                       CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.    CNcomment:OTPδ��ʼ�� CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.   CNcomment:��������Ƿ� CNend
\see \n
None CNcomment:�� CNend
*/
hi_s32 hi_tee_otp_set_taid_and_msid(hi_tee_otp_ta_index index, hi_u32 taid, hi_u32 msid);

/*
\brief Get TA ID and TA market segment ID. CNcomment:��ȡTA ID��TA�г�������  CNend
\attention \n
None CNcomment:�� CNend
\param[in] enIndex: TA ID and TA market segment ID index.           CNcomment:TA ID��TA�г������������  CNend
\param[out] pu32TAID: TA ID.                                        CNcomment:ָ�����ͣ�TA ID CNend
\param[out] pu32MSID: TA market segment ID.                         CNcomment:ָ�����ͣ�TA�г������� CNend
\retval ::HI_SUCCESS Success.                                       CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Failure.                                       CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.    CNcomment:OTPδ��ʼ�� CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.   CNcomment:��������Ƿ� CNend
\see \n
None CNcomment:�� CNend
*/
hi_s32 hi_tee_otp_get_taid_and_msid(hi_tee_otp_ta_index index, hi_u32 *taid, hi_u32 *msid);

/*
\brief Get ta index
\brief CNcomment ����TA ID�Ż�ȡ����ֵ�� CNend
\attention \n
N/A
\param[in] taid:     TA ID.                         CNcomment:TA ID�� CNend
\param[out] index:    the point of TA index.        CNcomment:��ȡTA������ָ��  CNend
\retval ::HI_SUCCESS  Call this API successful.     CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.          CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_ta_index(hi_u32 taid, hi_tee_otp_ta_index *index);

/*
\brief Get ta index
\brief CNcomment ��ȡ���õ�����ֵ�� CNend
\attention \n
N/A
\param[out] index:    the point of available TA index.  CNcomment:��ȡ����TA������ָ��  CNend
\retval ::HI_SUCCESS  Call this API successful.         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_available_ta_index(hi_tee_otp_ta_index *index);

/*
\brief Get DRM private data information from OTP area.
\brief CNcomment ��OTP�ռ��ȡDRM˽��������Ϣ�� CNend
\attention \n
This function is only used for hisilicon Playready and Widevine scenes,
if CAS has a separate DRM program, can not use this interface to read and write data.
CNcomment:�˺������������ں�˼Playready/Widevine���������CAS���Լ�������DRM����������ʹ�ô˽ӿڶ�д���ݡ� CNend
\param[in] offset: Offset address of read DRM data area.                            CNcomment:��ȡ��DRM��������ƫ�Ƶ�ַ CNend
\param[out] data: the point of buffer used to store the DRM data information.       CNcomment:ָ���Ŷ�ȡ���ݵ��ڴ�ռ䡣  CNend
\param[in/out] data_len: Store the length of the data that needs to be read,
and at the same time the driver returns the actual read length.
CNcomment:�����Ҫ��ȡ�����ݳ��ȣ�ͬʱ����������ʵ�Ķ�ȡ���ȡ�  CNend
\retval :HI_SUCCESS  Call this API successful.                                      CNcomment:APIϵͳ���óɹ��� CNend
\retval :HI_ERR_OTP_NULL_PTR  Parameter is a null pointer.                          CNcomment:����Ϊ��ָ�롣 CNend
\retval :HI_ERR_OTP_INVALID_PARAM  Parameter is invalid.                            CNcomment:���������á� CNend
\retval :HI_FAILURE  Call this API fails.                                           CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_get_priv_drm_data(hi_u32 offset, hi_u8 *data, hi_u32 *data_len);

/*
\brief Set DRM private data information to OTP area.
\brief CNcomment д��DRM˽��������Ϣ��OTP�ռ䡣 CNend
\attention \n
1:This function is only used for hisilicon Playready and Widevine scenes,
if CAS has a separate DRM program, can not use this interface to read and write data.
2:Offset must be 16 bytes aligned.
CNcomment:1:�˺������������ں�˼Playready/Widevine���������CAS���Լ�������DRM����������ʹ�ô˽ӿڶ�д���ݡ�
2:Offset����16�ֽڶ��롣CNend
\param[in] offset: Offset address of read DRM data area.                            CNcomment:��ȡ��DRM��������ƫ�Ƶ�ַ CNend
\param[in] data: the point of buffer used to store the DRM data information.        CNcomment:ָ���Ŵ�д�����ݵ��ڴ�ռ䡣 CNend
\param[in] data_len: Store the length of the data that needs to be witten.          CNcomment:�����Ҫд������ݳ��ȡ� CNend
\retval :HI_SUCCESS  Call this API successful.                                      CNcomment:APIϵͳ���óɹ��� CNend
\retval :HI_ERR_OTP_NULL_PTR  Parameter is a null pointer.                          CNcomment:����Ϊ��ָ�롣 CNend
\retval :HI_ERR_OTP_INVALID_PARAM  Parameter is invalid.                            CNcomment:���������á� CNend
\retval :HI_FAILURE  Call this API fails.                                           CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_set_priv_drm_data(hi_u32 offset, const hi_u8 *data, hi_u32 data_len);

/*
\brief Get runtime-check status CNcomment:��ȡ����ʱУ��״̬ʹ�ܱ��  CNend
\attention \n
None CNcomment:�� CNend
\param[out] enable Point to runtime Check status.                   CNcomment:ָ�����ͣ�����ʱУ��ʹ��״̬ CNend
\retval ::HI_SUCCESS Success.                                       CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Failure.                                       CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.    CNcomment:OTPδ��ʼ�� CNend
\retval ::HI_ERR_OTP_INVALID_PARA The input parameter is invalid.   CNcomment:��������Ƿ� CNend
\see \n
None CNcomment:�� CNend
*/
hi_s32 hi_tee_otp_get_runtime_check_stat(hi_bool *enable);

/*
\brief Enable runtime-check. CNcomment:��������ʱУ�鹦��ʹ�� CNend
\attention \n
None CNcomment:�� CNend
\param[in]  None
\retval ::HI_SUCCESS Success.                                       CNcomment:APIϵͳ���óɹ� CNend
\retval ::HI_FAILURE Failure.                                       CNcomment:APIϵͳ����ʧ�� CNend
\retval ::HI_ERR_OTP_NOT_INIT The otp module is not initialized.    CNcomment:OTPδ��ʼ�� CNend
\see \n
None CNcomment:�� CNend
*/
hi_s32 hi_tee_otp_enable_runtime_check(hi_void);


/* @} */  /* <!-- ==== API declaration end ==== */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_TEE_OTP_H__ */
