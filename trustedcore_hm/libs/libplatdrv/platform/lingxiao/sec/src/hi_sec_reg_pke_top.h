/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: PKE¼Ä´æÆ÷¶¨Òå
 * Author: o00302765
 * Create: 2019-10-22
 */

#ifndef __HI_SDK_L0_REG_PKE_TOP_H__
#define __HI_SDK_L0_REG_PKE_TOP_H__

#ifdef __MACRO__
#endif
#define HI_SDK_L0_REG_PKE_TOP_BASE                       0x10770000
#define HI_SDK_L0_REG_PKE_TOP_PKE_WORK_MODE_BASE         (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0004)
#define HI_SDK_L0_REG_PKE_TOP_PKE_START_BASE             (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0008)
#define HI_SDK_L0_REG_PKE_TOP_PKE_BUSY_BASE              (HI_SDK_L0_REG_PKE_TOP_BASE + 0x000C)
#define HI_SDK_L0_REG_PKE_TOP_PKE_RNG_OPTION_BASE        (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0014)
#define HI_SDK_L0_REG_PKE_TOP_PKE_INT_ENABLE_BASE        (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0020)
#define HI_SDK_L0_REG_PKE_TOP_PKE_INT_STATUS_BASE        (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0024)
#define HI_SDK_L0_REG_PKE_TOP_PKE_INT_NOMASK_STATUS_BASE (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0028)
#define HI_SDK_L0_REG_PKE_TOP_PKE_RESULT_FLAG_BASE       (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0040)
#define HI_SDK_L0_REG_PKE_TOP_PKE_FAILURE_FLAG_BASE      (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0044)
#define HI_SDK_L0_REG_PKE_TOP_PKE_SM2_PRIVATE_CRC_BASE   (HI_SDK_L0_REG_PKE_TOP_BASE + 0x006c)
#define HI_SDK_L0_REG_PKE_TOP_OTP_KEY_SEL_EN_BASE        (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0088)
#define HI_SDK_L0_REG_PKE_TOP_PKE_SM2_KEY_RANDOM_BASE    (HI_SDK_L0_REG_PKE_TOP_BASE + 0x008c)
#define HI_SDK_L0_REG_PKE_TOP_PKE_SM2_KEY_CRC_BASE       (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0090)
#define HI_SDK_L0_REG_PKE_TOP_PKE_SM2_KEY_CFG_BASE       (HI_SDK_L0_REG_PKE_TOP_BASE + 0x009c)
#define HI_SDK_L0_REG_PKE_TOP_PKE_SM2_KEY_RANDOM_A_BASE  (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0100)
#define HI_SDK_L0_REG_PKE_TOP_PKE_VERSION_BASE           (HI_SDK_L0_REG_PKE_TOP_BASE + 0x01FC)
#define HI_SDK_L0_REG_PKE_TOP_PKE_ALARM_BASE             (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0104)
#define HI_SDK_L0_REG_PKE_TOP_PKE_WAIT_TIMER_BASE        (HI_SDK_L0_REG_PKE_TOP_BASE + 0x0108)

#ifdef __STRUCT__
#endif
struct hi_sdk_l0_reg_pke_top_pke_work_mode_s {
	hi_uint32  opcode                          : 4 ; /*[0:3]*/
	hi_uint32  resv_0                          : 4 ; /*[4:7]*/
	hi_uint32  mode                            : 7 ; /*[8:14]*/
	hi_uint32  resv_1                          : 17; /*[15:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_start_s {
	hi_uint32  pke_start                       : 4 ; /*[0:3]*/
	hi_uint32  resv_0                          : 28; /*[4:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_busy_s {
	hi_uint32  pke_busy                        : 1 ; /*[0:0]*/
	hi_uint32  resv_0                          : 31; /*[1:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_rng_option_s {
	hi_uint32  pke_rng_option                  : 2 ; /*[0:1]*/
	hi_uint32  resv_0                          : 30; /*[2:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_int_enable_s {
	hi_uint32  pke_finish_int_enable           : 1 ; /*[0:0]*/
	hi_uint32  pke_err_int_enable              : 1 ; /*[1:1]*/
	hi_uint32  resv_0                          : 29; /*[2:30]*/
	hi_uint32  pke_all_int_enable              : 1 ; /*[31:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_int_status_s {
	hi_uint32  finish_int_status               : 4 ; /*[0:3]*/
	hi_uint32  alarm_int_status                : 4 ; /*[4:7]*/
	hi_uint32  resv_0                          : 8 ; /*[8:15]*/
	hi_uint32  resv_1                          : 16; /*[16:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_int_nomask_status_s {
	hi_uint32  finish_int_nomsk_status         : 4 ; /*[0:3]*/
	hi_uint32  alarm_int_nomsk_status          : 4 ; /*[4:7]*/
	hi_uint32  resv_0                          : 8 ; /*[8:15]*/
	hi_uint32  resv_1                          : 16; /*[16:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_result_flag_s {
	hi_uint32  pke_result_flag                 : 4 ; /*[0:3]*/
	hi_uint32  resv_0                          : 28; /*[4:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_failure_flag_s {
	hi_uint32  pke_failure_flag                : 3 ; /*[0:2]*/
	hi_uint32  resv_0                          : 29; /*[3:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_sm2_private_crc_s {
	hi_uint32  resv_0                          : 10; /*[0:9]*/
	hi_uint32  resv_1                          : 6 ; /*[10:15]*/
	hi_uint32  private_crc                     : 16; /*[16:31]*/
};

struct hi_sdk_l0_reg_pke_top_otp_key_sel_en_s {
	hi_uint32  otp_key_sel_en                  : 4 ; /*[0:3]*/
	hi_uint32  resv_0                          : 28; /*[4:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_sm2_key_random_s {
	hi_uint32  sm2_key_random                  : 32; /*[0:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_sm2_key_crc_s {
	hi_uint32  sm2_key_crc                     : 16; /*[0:15]*/
	hi_uint32  resv_0                          : 16; /*[16:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_sm2_key_cfg_s {
	hi_uint32  sm2_key_cfg                     : 4 ; /*[0:3]*/
	hi_uint32  resv_0                          : 28; /*[4:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_sm2_key_random_a_s {
	hi_uint32  sm2_key_random_a                : 32; /*[0:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_version_s {
	hi_uint32  pke_version                     : 32; /*[0:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_alarm_s {
	hi_uint32  protect_key_alarm               : 1 ; /*[0:0]*/
	hi_uint32  key_in_crc_enable_err           : 1 ; /*[1:1]*/
	hi_uint32  int_alarm                       : 1 ; /*[2:2]*/
	hi_uint32  int_mask_alarm                  : 1 ; /*[3:3]*/
	hi_uint32  sm2_key_cfg_alarm               : 1 ; /*[4:4]*/
	hi_uint32  otp_key_sel_en_alarm            : 1 ; /*[5:5]*/
	hi_uint32  random_seed_alarm               : 1 ; /*[6:6]*/
	hi_uint32  key_in_err                      : 1 ; /*[7:7]*/
	hi_uint32  rng_option_alarm                : 1 ; /*[8:8]*/
	hi_uint32  work_mode_alarm                 : 1 ; /*[9:9]*/
	hi_uint32  rsa2ctrl_alarm_new              : 1 ; /*[10:10]*/
	hi_uint32  rsa2ctrl_alarm_flag             : 1 ; /*[11:11]*/
	hi_uint32  resv_0                          : 20; /*[12:31]*/
};

struct hi_sdk_l0_reg_pke_top_pke_wait_timer_s {
	hi_uint32  pke_hub_wait_timer              : 15; /*[0:14]*/
	hi_uint32  pke_hub_timer_en                : 1 ; /*[15:15]*/
	hi_uint32  pke_timeout_cs                  : 8 ; /*[16:23]*/
	hi_uint32  resv_0                          : 7 ; /*[24:30]*/
	hi_uint32  timeout_flag                    : 1 ; /*[31:31]*/
};

#endif
