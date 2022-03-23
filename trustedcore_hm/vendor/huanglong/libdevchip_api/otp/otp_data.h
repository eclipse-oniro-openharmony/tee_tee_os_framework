/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Structure for otp fuse item.
 * Author: Linux SDK team
 * Create: 2019-06-24
 */


#ifndef __OTP_DATA_H__
#define __OTP_DATA_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#ifndef OTP_FIELD_NAME_MAX_LEN
#define OTP_FIELD_NAME_MAX_LEN 32
#endif

struct hi_otp_field_name {
    hi_char runtime_check_en[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_slot0_flag[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_slot1_flag[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_slot2_flag[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_slot3_flag[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_slot4_flag[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_slot5_flag[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_slot6_flag[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_slot7_flag[OTP_FIELD_NAME_MAX_LEN];
    hi_char privilegedmodeactivation[OTP_FIELD_NAME_MAX_LEN];
    hi_char chip_id_0[OTP_FIELD_NAME_MAX_LEN];
    hi_char chip_id_1[OTP_FIELD_NAME_MAX_LEN];
    hi_char chip_id_2[OTP_FIELD_NAME_MAX_LEN];
    hi_char tee_secversion[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta1_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta1_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta2_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta2_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta3_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta3_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta4_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta4_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta5_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta5_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta6_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta6_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta7_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta7_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta8_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta8_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta9_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta9_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta10_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta10_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta11_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta11_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta12_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta12_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta13_cert_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta13_secversion_ref[OTP_FIELD_NAME_MAX_LEN];
    hi_char dieid0[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_rootkey_0[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_rootkey_1[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_rootkey_2[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_rootkey_3[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_rootkey_4[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_rootkey_5[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_rootkey_6[OTP_FIELD_NAME_MAX_LEN];
    hi_char cas_rootkey_7[OTP_FIELD_NAME_MAX_LEN];
    hi_char boot_rootkey[OTP_FIELD_NAME_MAX_LEN];
    hi_char hisi_rootkey[OTP_FIELD_NAME_MAX_LEN];
    hi_char stbm_rootkey[OTP_FIELD_NAME_MAX_LEN];
    hi_char boot_slot_flag[OTP_FIELD_NAME_MAX_LEN];
    hi_char stbm_slot_flag[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta1_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta2_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta3_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta4_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta5_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta6_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta7_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta8_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta9_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta10_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta11_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta12_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char ta13_id_and_smid[OTP_FIELD_NAME_MAX_LEN];
    hi_char drm_key[OTP_FIELD_NAME_MAX_LEN];
};

struct hi_otp_field_name *__get_otp_field_name(hi_void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
