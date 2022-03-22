/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2019. All rights reserved.
 * Description: 寄存器定义
 * Author: hsan
 * Create: 2015-11-19
 * History: 2015-11-19初稿完成
 *          2019-1-31 hsan code restyle
 */

#ifndef __HI_SEC_REG_TRNG_H__
#define __HI_SEC_REG_TRNG_H__

#define HI_SDK_L0_REG_TRNG_BASE 0x1010f000
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_CTRL_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0000)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_FIFO_DATA_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0004)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_DATA_ST_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0008)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_ERR0_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x000C)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_ERR1_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0010)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_ERR2_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0014)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_ERR3_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0018)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_ALARM_SRC_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x001C)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_ALARM_MASK_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0020)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_ALARM_SRC_POST_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0024)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_FIFO_READY_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0028)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_TIM_OUT_PERIOD_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x002C)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_ALARM_CLR_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0030)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_PRE_CK_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0034)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_PRE_MONO_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0038)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_PRE_LONG_RUN_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x003C)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_PRE_RUN_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0040)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_PRE_SERIAL_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0044)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_PRE_POKER_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0048)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_PRE_ATCR01_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x004C)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_PRE_ATCR23_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0050)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_POS_CK_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0054)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_POS_MONO_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0058)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_POS_LONG_RUN_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x005C)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_POS_RUN_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0060)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_POS_SERIAL_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0064)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_POS_POKER_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0068)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_POS_ATCR01_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x006C)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_POS_ATCR23_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0070)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_AIS31_FAIL_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0074)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_AIS31_BLOCK_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0078)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_AIS31_POKER_LOW_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x007C)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_AIS31_POKER_HIG_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0080)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_DRBG_INIT_ERR_ST_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0090)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_ALL_REG_LOCK_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0094)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_RO_DISABLE_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0098)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_DRBG_RNG_CNT_GEN_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x009C)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_VER_NUM_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0100)
#define HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_DRBG_INIT_CK_CNT_BASE \
	(HI_SDK_L0_REG_TRNG_BASE + 0x0104)

struct hi_sdk_l0_reg_trng_hisc_com_trng_ctrl_s {
	hi_uint32 drbg_enable : 1;
	hi_uint32 fliter_enable : 1;
	hi_uint32 drop_enable : 1;
	hi_uint32 resv_0 : 1;
	hi_uint32 ro_sel : 4;
	hi_uint32 resv_1 : 3;
	hi_uint32 test_disable : 1;
	hi_uint32 pre_test_enable : 1;
	hi_uint32 pos_test_enable : 1;
	hi_uint32 resv_2 : 18;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_fifo_data_s {
	hi_uint32 trng_fifo_data : 32;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_data_st_s {
	hi_uint32 trng_fifo_data_cnt : 8;
	hi_uint32 resv_0 : 24;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_err0_cnt_s {
	hi_uint32 rng_err0_cnt : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_err1_cnt_s {
	hi_uint32 rng_err1_cnt : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_err2_cnt_s {
	hi_uint32 rng_err2_cnt : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_err3_cnt_s {
	hi_uint32 rng_err3_cnt : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_alarm_src_s {
	hi_uint32 pre_self_alarm_src : 1;
	hi_uint32 pos_self_alarm_src : 1;
	hi_uint32 rng_timeout_alarm_src : 1;
	hi_uint32 pri_tim_out_alarm_src : 1;
	hi_uint32 cpu_rd_rnd_step_err : 1;
	hi_uint32 prt_alarm_src : 1;
	hi_uint32 resv_0 : 26;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_alarm_mask_s {
	hi_uint32 trng_alarm_mask : 4;
	hi_uint32 prt_alram_mask : 4;
	hi_uint32 resv_0 : 24;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_alarm_src_post_s {
	hi_uint32 pre_self_alarm_post : 1;
	hi_uint32 pos_self_alarm_post : 1;
	hi_uint32 rng_timeout_alarm_post : 1;
	hi_uint32 pri_tim_out_alarm_post : 1;
	hi_uint32 cpu_rd_rnd_step_err_post : 1;
	hi_uint32 prt_alarm_post : 1;
	hi_uint32 resv_0 : 26;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_fifo_ready_s {
	hi_uint32 trng_data_ready : 2;
	hi_uint32 trng_done : 2;
	hi_uint32 resv_0 : 28;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_tim_out_period_s {
	hi_uint32 tim_out_period : 32;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_alarm_clr_s {
	hi_uint32 trng_alarm_clr : 4;
	hi_uint32 prt_alarm_clr : 4;
	hi_uint32 resv_0 : 24;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pre_ck_cnt_s {
	hi_uint32 pre_self_fail_cnt : 4;
	hi_uint32 resv_0 : 28;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pre_mono_cnt_s {
	hi_uint32 pre_mono_ck_low : 8;
	hi_uint32 pre_mono_ck_hig : 8;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pre_long_run_cnt_s {
	hi_uint32 pre_long_run_hig : 8;
	hi_uint32 resv_0 : 24;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pre_run_cnt_s {
	hi_uint32 pre_run_test_hig : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pre_serial_cnt_s {
	hi_uint32 pre_serial_ck_hig : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pre_poker_cnt_s {
	hi_uint32 pre_poker_ck_hig : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pre_atcr01_cnt_s {
	hi_uint32 pre_actr0_ck_low : 8;
	hi_uint32 pre_actr0_ck_hig : 8;
	hi_uint32 pre_actr1_ck_low : 8;
	hi_uint32 pre_actr1_ck_hig : 8;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pre_atcr23_cnt_s {
	hi_uint32 pre_actr2_ck_low : 8;
	hi_uint32 pre_actr2_ck_hig : 8;
	hi_uint32 pre_actr3_ck_low : 8;
	hi_uint32 pre_actr3_ck_hig : 8;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pos_ck_cnt_s {
	hi_uint32 pos_self_fail_cnt : 4;
	hi_uint32 resv_0 : 28;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pos_mono_cnt_s {
	hi_uint32 pos_mono_ck_low : 8;
	hi_uint32 pos_mono_ck_hig : 8;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pos_long_run_cnt_s {
	hi_uint32 pos_long_run_hig : 8;
	hi_uint32 resv_0 : 24;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pos_run_cnt_s {
	hi_uint32 pos_run_test_hig : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pos_serial_cnt_s {
	hi_uint32 pos_serial_ck_hig : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pos_poker_cnt_s {
	hi_uint32 pos_poker_ck_hig : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pos_atcr01_cnt_s {
	hi_uint32 pos_actr0_ck_low : 8;
	hi_uint32 pos_actr0_ck_hig : 8;
	hi_uint32 pos_actr1_ck_low : 8;
	hi_uint32 pos_actr1_ck_hig : 8;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_pos_atcr23_cnt_s {
	hi_uint32 pos_actr2_ck_low : 8;
	hi_uint32 pos_actr2_ck_hig : 8;
	hi_uint32 pos_actr3_ck_low : 8;
	hi_uint32 pos_actr3_ck_hig : 8;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_ais31_fail_cnt_s {
	hi_uint32 ais31_fail_cnt : 8;
	hi_uint32 resv_0 : 24;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_ais31_block_cnt_s {
	hi_uint32 ais31_block_cnt : 10;
	hi_uint32 resv_0 : 22;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_ais31_poker_low_s {
	hi_uint32 ais31_poker_low : 8;
	hi_uint32 resv_0 : 24;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_ais31_poker_hig_s {
	hi_uint32 ais31_poker_hig : 8;
	hi_uint32 resv_0 : 24;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_drbg_init_err_st_s {
	hi_uint32 drbg_init_err_st : 4;
	hi_uint32 resv_0 : 28;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_all_reg_lock_s {
	hi_uint32 trng_all_reg_lock : 8;
	hi_uint32 resv_0 : 24;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_ro_disable_s {
	hi_uint32 trng_ro_disable : 16;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_drbg_rng_cnt_gen_s {
	hi_uint32 rng_gen_max : 8;
	hi_uint32 reseed_max : 8;
	hi_uint32 resv_0 : 16;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_ver_num_s {
	hi_uint32 trng_ver_num : 32;
};

struct hi_sdk_l0_reg_trng_hisc_com_trng_drbg_init_ck_cnt_s {
	hi_uint32 drbg_init_ck_cnt : 16;
	hi_uint32 resv_0 : 16;
};

#endif
