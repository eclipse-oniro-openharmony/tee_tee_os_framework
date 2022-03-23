/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description :Structure for otp fuse data.
 * Author : Linux SDK team
 * Created : 2019-09-26
 */

#include "otp_data_struct.h"
#include "otp_data.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

otp_data_item g_otp_data[] = {
    { "runtime_check_en",              0x0004, 0x0001, 1, 0x1, 0, 0, 0x0104, 1, 1, {{0}} },
    { "cas_slot0_flag",                0x0010, 0x0020, 0, 0x1, 0, 0, 0x0110, 0, 1, {{0}} },
    { "cas_slot1_flag",                0x0014, 0x0020, 0, 0x1, 0, 0, 0x0110, 1, 1, {{0}} },
    { "cas_slot2_flag",                0x0018, 0x0020, 0, 0x1, 0, 0, 0x0110, 2, 1, {{0}} },
    { "cas_slot3_flag",                0x001c, 0x0020, 0, 0x1, 0, 0, 0x0110, 3, 1, {{0}} },
    { "cas_slot4_flag",                0x0020, 0x0020, 0, 0x1, 0, 0, 0x0110, 4, 1, {{0}} },
    { "cas_slot5_flag",                0x0024, 0x0020, 0, 0x1, 0, 0, 0x0110, 5, 1, {{0}} },
    { "cas_slot6_flag",                0x0028, 0x0020, 0, 0x1, 0, 0, 0x0110, 6, 1, {{0}} },
    { "cas_slot7_flag",                0x002c, 0x0020, 0, 0x1, 0, 0, 0x0110, 7, 1, {{0}} },
    { "privilegedmodeactivation",      0x005f, 0x0004, 4, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "chip_id_0",                     0x0090, 0x0040, 0, 0x1, 0, 0, 0x0141, 4, 2, {{0}} },
    { "chip_id_1",                     0x0098, 0x0040, 0, 0x1, 0, 0, 0x0141, 6, 2, {{0}} },
    { "chip_id_2",                     0x00a0, 0x0040, 0, 0x1, 0, 0, 0x0142, 0, 2, {{0}} },
    { "tee_secversion",                0x0180, 0x0080, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta1_cert_secversion_ref",       0x0198, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta1_secversion_ref",            0x019a, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta2_cert_secversion_ref",       0x01a0, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta2_secversion_ref",            0x01a2, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta3_cert_secversion_ref",       0x01a8, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta3_secversion_ref",            0x01aa, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta4_cert_secversion_ref",       0x01b0, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta4_secversion_ref",            0x01b2, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta5_cert_secversion_ref",       0x01b8, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta5_secversion_ref",            0x01ba, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta6_cert_secversion_ref",       0x01c0, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta6_secversion_ref",            0x01c2, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta7_cert_secversion_ref",       0x01c8, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta7_secversion_ref",            0x01ca, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta8_cert_secversion_ref",       0x01d0, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta8_secversion_ref",            0x01d2, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta9_cert_secversion_ref",       0x01d8, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta9_secversion_ref",            0x01da, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta10_cert_secversion_ref",      0x01e0, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta10_secversion_ref",           0x01e2, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta11_cert_secversion_ref",      0x01e8, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta11_secversion_ref",           0x01ea, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta12_cert_secversion_ref",      0x01f0, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta12_secversion_ref",           0x01f2, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta13_cert_secversion_ref",      0x01f8, 0x0010, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "ta13_secversion_ref",           0x01fa, 0x0030, 0, 0x0, 0, 0, 0x0000, 0, 0, {{0}} },
    { "dieid0",                        0x0300, 0x0080, 0, 0x1, 0, 0, 0x0150, 0, 16, {{0}} },
    { "cas_rootkey_0",                 0x0400, 0x0080, 0, 0x3, 0, 0, 0x0160, 0, 1, {{ 0, 8, 0x0360, 0x015c, 0, 1 }} },
    { "cas_rootkey_1",                 0x0410, 0x0080, 0, 0x3, 0, 0, 0x0160, 1, 1, {{ 0, 8, 0x0361, 0x015c, 1, 1 }} },
    { "cas_rootkey_2",                 0x0420, 0x0080, 0, 0x3, 0, 0, 0x0160, 2, 1, {{ 0, 8, 0x0362, 0x015c, 2, 1 }} },
    { "cas_rootkey_3",                 0x0430, 0x0080, 0, 0xb, 0, 0, 0x0160, 3, 1, {{ 0, 8, 0x0363, 0x015c, 3, 1 }} },
    { "cas_rootkey_4",                 0x0440, 0x0080, 0, 0x3, 0, 0, 0x0160, 4, 1, {{ 0, 8, 0x0364, 0x015c, 4, 1 }} },
    { "cas_rootkey_5",                 0x0450, 0x0080, 0, 0x3, 0, 0, 0x0160, 5, 1, {{ 0, 8, 0x0365, 0x015c, 5, 1 }} },
    { "cas_rootkey_6",                 0x0460, 0x0080, 0, 0x3, 0, 0, 0x0160, 6, 1, {{ 0, 8, 0x0366, 0x015c, 6, 1 }} },
    { "cas_rootkey_7",                 0x0470, 0x0080, 0, 0x3, 0, 0, 0x0160, 7, 1, {{ 0, 8, 0x0367, 0x015c, 7, 1 }} },
    { "boot_rootkey",                  0x04a0, 0x0080, 0, 0x3, 0, 0, 0x0161, 2, 1, {{ 0, 8, 0x036a, 0x015d, 2, 1 }} },
    { "stbm_rootkey",                  0x04c0, 0x0080, 0, 0x3, 0, 0, 0x0161, 4, 1, {{ 0, 8, 0x036c, 0x015d, 4, 1 }} },
    { "boot_slot_flag",                0x04e0, 0x0020, 0, 0x1, 0, 0, 0x0111, 0, 1, {{0}}},
    { "stbm_slot_flag",                0x04e4, 0x0020, 0, 0x1, 0, 0, 0x0111, 1, 1, {{0}}},
    { "ta1_id_and_smid",               0x0700, 0x0040, 0, 0x1, 0, 0, 0x0170, 0, 1, {{0}} },
    { "ta2_id_and_smid",               0x0708, 0x0040, 0, 0x1, 0, 0, 0x0170, 1, 1, {{0}} },
    { "ta3_id_and_smid",               0x0710, 0x0040, 0, 0x1, 0, 0, 0x0170, 2, 1, {{0}} },
    { "ta4_id_and_smid",               0x0718, 0x0040, 0, 0x1, 0, 0, 0x0170, 3, 1, {{0}} },
    { "ta5_id_and_smid",               0x0720, 0x0040, 0, 0x1, 0, 0, 0x0170, 4, 1, {{0}} },
    { "ta6_id_and_smid",               0x0728, 0x0040, 0, 0x1, 0, 0, 0x0170, 5, 1, {{0}} },
    { "ta7_id_and_smid",               0x0730, 0x0040, 0, 0x1, 0, 0, 0x0170, 6, 1, {{0}} },
    { "ta8_id_and_smid",               0x0738, 0x0040, 0, 0x1, 0, 0, 0x0170, 7, 1, {{0}} },
    { "ta9_id_and_smid",               0x0740, 0x0040, 0, 0x1, 0, 0, 0x0171, 0, 1, {{0}} },
    { "ta10_id_and_smid",              0x0748, 0x0040, 0, 0x1, 0, 0, 0x0171, 1, 1, {{0}} },
    { "ta11_id_and_smid",              0x0750, 0x0040, 0, 0x1, 0, 0, 0x0171, 2, 1, {{0}} },
    { "ta12_id_and_smid",              0x0758, 0x0040, 0, 0x1, 0, 0, 0x0171, 3, 1, {{0}} },
    { "ta13_id_and_smid",              0x0760, 0x0040, 0, 0x1, 0, 0, 0x0171, 4, 1, {{0}} },
    { "drm_key",                       0x0800, 0x0400, 0, 0x1, 0, 0, 0x0168, 0, 8, {{0}} },
};

static struct hi_otp_field_name g_otp_field_name = {
    .runtime_check_en                      = "runtime_check_en",
    .cas_slot0_flag                        = "cas_slot0_flag",
    .cas_slot1_flag                        = "cas_slot1_flag",
    .cas_slot2_flag                        = "cas_slot2_flag",
    .cas_slot3_flag                        = "cas_slot3_flag",
    .cas_slot4_flag                        = "cas_slot4_flag",
    .cas_slot5_flag                        = "cas_slot5_flag",
    .cas_slot6_flag                        = "cas_slot6_flag",
    .cas_slot7_flag                        = "cas_slot7_flag",
    .privilegedmodeactivation              = "privilegedmodeactivation",
    .chip_id_0                             = "chip_id_0",
    .chip_id_1                             = "chip_id_1",
    .chip_id_2                             = "chip_id_2",
    .tee_secversion                        = "tee_secversion",
    .ta1_cert_secversion_ref               = "ta1_cert_secversion_ref",
    .ta1_secversion_ref                    = "ta1_secversion_ref",
    .ta2_cert_secversion_ref               = "ta2_cert_secversion_ref",
    .ta2_secversion_ref                    = "ta2_secversion_ref",
    .ta3_cert_secversion_ref               = "ta3_cert_secversion_ref",
    .ta3_secversion_ref                    = "ta3_secversion_ref",
    .ta4_cert_secversion_ref               = "ta4_cert_secversion_ref",
    .ta4_secversion_ref                    = "ta4_secversion_ref",
    .ta5_cert_secversion_ref               = "ta5_cert_secversion_ref",
    .ta5_secversion_ref                    = "ta5_secversion_ref",
    .ta6_cert_secversion_ref               = "ta6_cert_secversion_ref",
    .ta6_secversion_ref                    = "ta6_secversion_ref",
    .ta7_cert_secversion_ref               = "ta7_cert_secversion_ref",
    .ta7_secversion_ref                    = "ta7_secversion_ref",
    .ta8_cert_secversion_ref               = "ta8_cert_secversion_ref",
    .ta8_secversion_ref                    = "ta8_secversion_ref",
    .ta9_cert_secversion_ref               = "ta9_cert_secversion_ref",
    .ta9_secversion_ref                    = "ta9_secversion_ref",
    .ta10_cert_secversion_ref              = "ta10_cert_secversion_ref",
    .ta10_secversion_ref                   = "ta10_secversion_ref",
    .ta11_cert_secversion_ref              = "ta11_cert_secversion_ref",
    .ta11_secversion_ref                   = "ta11_secversion_ref",
    .ta12_cert_secversion_ref              = "ta12_cert_secversion_ref",
    .ta12_secversion_ref                   = "ta12_secversion_ref",
    .ta13_cert_secversion_ref              = "ta13_cert_secversion_ref",
    .ta13_secversion_ref                   = "ta13_secversion_ref",
    .dieid0                                = "dieid0",
    .cas_rootkey_0                         = "cas_rootkey_0",
    .cas_rootkey_1                         = "cas_rootkey_1",
    .cas_rootkey_2                         = "cas_rootkey_2",
    .cas_rootkey_3                         = "cas_rootkey_3",
    .cas_rootkey_4                         = "cas_rootkey_4",
    .cas_rootkey_5                         = "cas_rootkey_5",
    .cas_rootkey_6                         = "cas_rootkey_6",
    .cas_rootkey_7                         = "cas_rootkey_7",
    .boot_rootkey                          = "boot_rootkey",
    .stbm_rootkey                          = "stbm_rootkey",
    .boot_slot_flag                        = "boot_slot_flag",
    .stbm_slot_flag                        = "stbm_slot_flag",
    .ta1_id_and_smid                       = "ta1_id_and_smid",
    .ta2_id_and_smid                       = "ta2_id_and_smid",
    .ta3_id_and_smid                       = "ta3_id_and_smid",
    .ta4_id_and_smid                       = "ta4_id_and_smid",
    .ta5_id_and_smid                       = "ta5_id_and_smid",
    .ta6_id_and_smid                       = "ta6_id_and_smid",
    .ta7_id_and_smid                       = "ta7_id_and_smid",
    .ta8_id_and_smid                       = "ta8_id_and_smid",
    .ta9_id_and_smid                       = "ta9_id_and_smid",
    .ta10_id_and_smid                      = "ta10_id_and_smid",
    .ta11_id_and_smid                      = "ta11_id_and_smid",
    .ta12_id_and_smid                      = "ta12_id_and_smid",
    .ta13_id_and_smid                      = "ta13_id_and_smid",
    .drm_key                               = "drm_key",
};

struct hi_otp_field_name *__get_otp_field_name(hi_void)
{
    return &g_otp_field_name;
}

unsigned int otp_get_data_size(hi_void)
{
    return sizeof(g_otp_data);
}

unsigned int otp_get_data_number(hi_void)
{
    return sizeof(g_otp_data) / sizeof(g_otp_data[0]);
}

otp_data_item *otp_get_data(hi_void)
{
    return g_otp_data;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */
