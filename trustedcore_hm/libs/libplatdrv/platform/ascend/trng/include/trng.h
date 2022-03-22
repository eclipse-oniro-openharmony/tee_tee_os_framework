/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: the head file of trng.c
* Author: huawei
* Create: 2019/12/30
*/
#ifndef TRNG_H
#define TRNG_H

#include "stdint.h"

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI1951)
#define TRNG_BASE_ADDR                          0x88110000U
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI1981)
#define TRNG_BASE_ADDR                          0x843A0000U
#endif

#define TRNG_OUTPUT_0_REG                       (TRNG_BASE_ADDR + 0x0000)
#define TRNG_OUTPUT_1_REG                       (TRNG_BASE_ADDR + 0x0004)
#define TRNG_OUTPUT_2_REG                       (TRNG_BASE_ADDR + 0x0008)
#define TRNG_OUTPUT_3_REG                       (TRNG_BASE_ADDR + 0x000C)
#define TRNG_INPUT_0_REG                        (TRNG_BASE_ADDR + 0x0000)
#define TRNG_INTPUT_1_REG                       (TRNG_BASE_ADDR + 0x0004)
#define TRNG_INTPUT_2_REG                       (TRNG_BASE_ADDR + 0x0008)
#define TRNG_INTPUT_3_REG                       (TRNG_BASE_ADDR + 0x000C)
#define TRNG_STATUS_REG                         (TRNG_BASE_ADDR + 0x0010)
#define TRNG_INTACK_REG                         (TRNG_BASE_ADDR + 0x0010)
#define TRNG_CONTROL_REG                        (TRNG_BASE_ADDR + 0x0014)
#define TRNG_CONFIG_REG                         (TRNG_BASE_ADDR + 0x0018)
#define TRNG_ALARMCNT_REG                       (TRNG_BASE_ADDR + 0x001C)
#define TRNG_FROENABLE_REG                      (TRNG_BASE_ADDR + 0x0020)
#define TRNG_FRODETUNE_REG                      (TRNG_BASE_ADDR + 0x0024)
#define TRNG_ALARMMASK_REG                      (TRNG_BASE_ADDR + 0x0028)
#define TRNG_ALARMSTOP_REG                      (TRNG_BASE_ADDR + 0x002C)
#define TRNG_RAW_L_REG                          (TRNG_BASE_ADDR + 0x0030)
#define TRNG_RAW_H_REG                          (TRNG_BASE_ADDR + 0x0034)
#define TRNG_SPB_TESTS_REG                      (TRNG_BASE_ADDR + 0x0038)
#define TRNG_COUNT_REG                          (TRNG_BASE_ADDR + 0x003C)
#define TRNG_COND_0_REG                         (TRNG_BASE_ADDR + 0x0040)
#define TRNG_COND_1_REG                         (TRNG_BASE_ADDR + 0x0044)
#define TRNG_COND_2_REG                         (TRNG_BASE_ADDR + 0x0048)
#define TRNG_COND_3_REG                         (TRNG_BASE_ADDR + 0x004C)
#define TRNG_COND_4_REG                         (TRNG_BASE_ADDR + 0x0050)
#define TRNG_COND_5_REG                         (TRNG_BASE_ADDR + 0x0054)
#define TRNG_COND_6_REG                         (TRNG_BASE_ADDR + 0x0058)
#define TRNG_COND_7_REG                         (TRNG_BASE_ADDR + 0x005C)
#define TRNG_PS_AI_0_REG                        (TRNG_BASE_ADDR + 0x0040)
#define TRNG_PS_AI_1_REG                        (TRNG_BASE_ADDR + 0x0044)
#define TRNG_PS_AI_2_REG                        (TRNG_BASE_ADDR + 0x0048)
#define TRNG_PS_AI_3_REG                        (TRNG_BASE_ADDR + 0x004C)
#define TRNG_PS_AI_4_REG                        (TRNG_BASE_ADDR + 0x0050)
#define TRNG_PS_AI_5_REG                        (TRNG_BASE_ADDR + 0x0054)
#define TRNG_PS_AI_6_REG                        (TRNG_BASE_ADDR + 0x0058)
#define TRNG_PS_AI_7_REG                        (TRNG_BASE_ADDR + 0x005C)
#define TRNG_PS_AI_8_REG                        (TRNG_BASE_ADDR + 0x0060)
#define TRNG_PS_AI_9_REG                        (TRNG_BASE_ADDR + 0x0064)
#define TRNG_PS_AI_10_REG                       (TRNG_BASE_ADDR + 0x0068)
#define TRNG_PS_AI_11_REG                       (TRNG_BASE_ADDR + 0x006C)
#define TRNG_RUN_CNT_REG                        (TRNG_BASE_ADDR + 0x0040)
#define TRNG_RUN_1_REG                          (TRNG_BASE_ADDR + 0x0044)
#define TRNG_RUN_2_REG                          (TRNG_BASE_ADDR + 0x0048)
#define TRNG_RUN_3_REG                          (TRNG_BASE_ADDR + 0x004C)
#define TRNG_RUN_4_REG                          (TRNG_BASE_ADDR + 0x0050)
#define TRNG_RUN_5_REG                          (TRNG_BASE_ADDR + 0x0054)
#define TRNG_RUN_6_REG                          (TRNG_BASE_ADDR + 0x0058)
#define TRNG_MONOBITCNT_REG                     (TRNG_BASE_ADDR + 0x005C)
#define TRNG_POKER_3_0_REG                      (TRNG_BASE_ADDR + 0x0060)
#define TRNG_POKER_7_4_REG                      (TRNG_BASE_ADDR + 0x0064)
#define TRNG_POKER_B_8_REG                      (TRNG_BASE_ADDR + 0x0068)
#define TRNG_POKER_F_C_REG                      (TRNG_BASE_ADDR + 0x006C)
#define TRNG_TEST_REG                           (TRNG_BASE_ADDR + 0x0070)
#define TRNG_BLOCKCNT_REG                       (TRNG_BASE_ADDR + 0x0074)
#define TRNG_OPTIONS_REG                        (TRNG_BASE_ADDR + 0x0078)
#define TRNG_EIP_REV_REG                        (TRNG_BASE_ADDR + 0x007C)
#define TRNG_CTRL0_REG                          (TRNG_BASE_ADDR + 0x00C0)
#define TRNG_CTRL1_REG                          (TRNG_BASE_ADDR + 0x00C4)
#define RNG_CTRL_REG                            (TRNG_BASE_ADDR + 0x00CC)
#define RNG_SEED_REG                            (TRNG_BASE_ADDR + 0x00D0)
#define TRNG_FSM_ST_REG                         (TRNG_BASE_ADDR + 0x00D4)
#define RNG_NUM_REG                             (TRNG_BASE_ADDR + 0x00D8)
#define RNG_PHY_SEED_REG                        (TRNG_BASE_ADDR + 0x00DC)
#define RNG_ERR_REG                             (TRNG_BASE_ADDR + 0x00E0)
#define TRNG_INT_SET_REG                        (TRNG_BASE_ADDR + 0x00E4)
#define TRNG_RAN_DATA0_REG                      (TRNG_BASE_ADDR + 0x00F0)
#define TRNG_RAN_DATA1_REG                      (TRNG_BASE_ADDR + 0x00F4)
#define TRNG_RAN_DATA2_REG                      (TRNG_BASE_ADDR + 0x00F8)
#define TRNG_RAN_DATA3_REG                      (TRNG_BASE_ADDR + 0x00FC)

/* HAC SUBCTRL */
#define HAC_SUBCTRL_REG_ADDR                    0x880C0000
#define SC_TRNG_RESET_REQ_REG                   (HAC_SUBCTRL_REG_ADDR + 0x0A10)
#define SC_TRNG_RESET_DREQ_REG                  (HAC_SUBCTRL_REG_ADDR + 0x0A14)
#define SC_TRNG_RESET_ST_REG                    (HAC_SUBCTRL_REG_ADDR + 0x5A10)
#define SC_TRNG_ICG_EN_REG                      (HAC_SUBCTRL_REG_ADDR + 0x0310)
#define SC_TRNG_ICG_ST_REG                      (HAC_SUBCTRL_REG_ADDR + 0x5310)
#define SC_TRNG_ICG_DIS_REG                     (HAC_SUBCTRL_REG_ADDR + 0x0314)
#define TRNG_UDELAY                             0xFFFF

#define TIME_OUT                                0xFF
#define TRNG_RST                                0x3
#define TRNG_RST_REF                            0x3
#define TRNG_RST_REL                            0x3
#define TRNG_RST_REL_REF                        0x0
#define TRNG_CLOCK_OPEN                         0x3
#define TRNG_CLOCK_OPEN_REF                     0x3
#define TRNG_CLOCK_CLOSE                        0x3
#define TRNG_CLOCK_CLOSE_REF                    0x0

#define LOOP_COUNT_OLD                          0x3F
#define LOOP_COUNT_NEW                          80
#define LOOP_COUNT                              20
#define STORE_OFF0                              0
#define STORE_OFF1                              1
#define STORE_OFF2                              2
#define STORE_OFF3                              3
#define TIMEOUT                                 0xFFFFF
#define TRNG_UDELAY                             0xFFFF
#define TRNG_SIZE                               0x10
#define RANDATA_SIZE                            0x4
#define TRNG_BYTE_MASK                          0xFF
#define BYTE_LENGTH                             0x8
#define RANDATA_0                               0x4
#define RANDATA_1                               0x8
#define RANDATA_2                               0xC
#define RANDATA_3                               0x10
#define TRNG_TEST_ADD                           0x10A3DC71
#define ENTROPY_FAST                            0x10008
#define SHUTDOWN_OFLO_WRONG                     0x8000FF
#define FULL_FRO                                0xFF
#define NOISE_FAIL_STATUS                       0x8
#define TRNG_DELAY_TIME                         0xFFFF
#define TRNG_DATA_BLOCK_EN                      0xFFF

#define TRNG_READ_ZERO_TIMEOUT                  5
#define TRNG_READ_IS_ZERO(buffer) \
    (((buffer[STORE_OFF0]) == 0) || \
    ((buffer[STORE_OFF1]) == 0) || \
    ((buffer[STORE_OFF2]) == 0) ||  \
    ((buffer[STORE_OFF3]) == 0))

typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    ready_ack           : 1  ; /* [0] */
        uint32_t    shutdown_oflo_ack   : 1  ; /* [1] */
        uint32_t    stuck_out_ack       : 1  ; /* [2] */
        uint32_t    noise_fail_ack      : 1  ; /* [3] */
        uint32_t    run_fail_ack        : 1  ; /* [4] */
        uint32_t    long_run_fail_ack   : 1  ; /* [5] */
        uint32_t    poker_fail_ack      : 1  ; /* [6] */
        uint32_t    monobit_fail_ack    : 1  ; /* [7] */
        uint32_t    test_ready_ack      : 1  ; /* [8] */
        uint32_t    stuck_nrbg_ack      : 1  ; /* [9] */
        uint32_t    open_read_gate      : 3  ; /* [12..10] */
        uint32_t    repcnt_fail_ack     : 1  ; /* [13] */
        uint32_t    aprop_fail_ack      : 1  ; /* [14] */
        uint32_t    test_stuck_out      : 1  ; /* [15] */
        uint32_t    reserved_0          : 16   ; /* [31..16] */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_TRNG_INTACK_REG;

typedef union {
    struct {
        uint32_t    ready               : 1  ; /* [0] */
        uint32_t    shutdown_oflo       : 1  ; /* [1] */
        uint32_t    stuck_out           : 1  ; /* [2] */
        uint32_t    noise_fail          : 1  ; /* [3] */
        uint32_t    run_fail            : 1  ; /* [4] */
        uint32_t    long_run_fail       : 1  ; /* [5] */
        uint32_t    poker_fail          : 1  ; /* [6] */
        uint32_t    monobit_fail        : 1  ; /* [7] */
        uint32_t    test_ready          : 1  ; /* [8] */
        uint32_t    stuck_nrbg          : 1  ; /* [9] */
        uint32_t    reseed_ai           : 1  ; /* [10] */
        uint32_t    reserved_0          : 2  ; /* [12..11] */
        uint32_t    repcnt_fail         : 1  ; /* [13] */
        uint32_t    aprop_fail          : 1  ; /* [14] */
        uint32_t    test_stuck_out      : 1  ; /* [15] */
        uint32_t    blocks_available    : 8  ; /* [23..16] */
        uint32_t    blocks_thresh       : 7  ; /* [30..24] */
        uint32_t    need_clock          : 1   ; /* [31] */
    } bits;

    uint32_t    status;
} U_TRNG_STATUS_REG;

typedef union {
    struct {
        uint32_t    ready_mask          : 1  ; /* [0] */
        uint32_t    shutdown_oflo_mask  : 1  ; /* [1] */
        uint32_t    stuck_out_mask      : 1  ; /* [2] */
        uint32_t    noise_fail_mask     : 1  ; /* [3] */
        uint32_t    run_fail_mask       : 1  ; /* [4] */
        uint32_t    long_run_fail_mask  : 1  ; /* [5] */
        uint32_t    poker_fail_mask     : 1  ; /* [6] */
        uint32_t    monobit_fail_mask   : 1  ; /* [7] */
        uint32_t    test_mode           : 1  ; /* [8] */
        uint32_t    stuck_nrbg_mask     : 1  ; /* [9] */
        uint32_t    enable_trng         : 1  ; /* [10] */
        uint32_t    no_whitening        : 1  ; /* [11] */
        uint32_t    drbg_en             : 1  ; /* [12] */
        uint32_t    repcnt_fail_mask    : 1  ; /* [13] */
        uint32_t    aprop_fail_mask     : 1  ; /* [14] */
        uint32_t    re_seed             : 1  ; /* [15] */
        uint32_t    request_data        : 1  ; /* [16] */
        uint32_t    request_hold        : 1  ; /* [17] */
        uint32_t    reserved_0          : 2  ; /* [19..18] */
        uint32_t    data_blocks         : 12  ; /* [31..20] */
    } bits;

    uint32_t    status;
} U_TRNG_CONTROL_REG;

typedef union {
    struct {
        uint32_t    trng_mode                   : 1  ; /* [0] */
        uint32_t    sec_interface_disable       : 1  ; /* [1] */
        uint32_t    km_interface_disable        : 1  ; /* [2] */
        uint32_t    jtagauth_interface_disable  : 1  ; /* [3] */
        uint32_t    user_interface_disable      : 1  ; /* [4] */
        uint32_t    auto_reseed_enable          : 1  ; /* [5] */
        uint32_t    hpre_interface_disable      : 1  ; /* [6] */
        uint32_t    reserved_1                  : 1  ; /* [7] */
        uint32_t    mem_ctrl                    : 8  ; /* [15..8] */
        uint32_t    block_cnt                   : 12  ; /* [27..16] */
        uint32_t    reserved_0                  : 4  ; /* [31..28] */
    } bits;

    uint32_t    status;
} U_TRNG_CTRL0_REG;

typedef union {
    struct {
        uint32_t    noise_blocks                : 5  ; /* [4..0] */
        uint32_t    use_startup_bits            : 1  ; /* [5] */
        uint32_t    scale                       : 2  ; /* [7..6] */
        uint32_t    sample_div                  : 4  ; /* [11..8] */
        uint32_t    read_timeout                : 4  ; /* [15..12] */
        uint32_t    sample_cycles               : 16  ; /* [31..16] */
    } bits;

    uint32_t    status;
} U_TRNG_CONFIG_REG;

typedef union {
    struct {
        uint32_t    alarm_threshold             : 8  ; /* [7..0] */
        uint32_t    reserved_2                  : 7  ; /* [14..8] */
        uint32_t    stall_run_poker             : 1  ; /* [15] */
        uint32_t    shutdown_threshold          : 5  ; /* [20..16] */
        uint32_t    reserved_1                  : 2  ; /* [22..21] */
        uint32_t    shutdown_fatal              : 1  ; /* [23] */
        uint32_t    shutdown_count              : 6  ; /* [29..24] */
        uint32_t    reserved_0                  : 2  ; /* [31..30] */
    } bits;

    uint32_t    status;
} U_TRNG_ALARMCNT_REG;

typedef union {
    struct {
        uint32_t    rng_en                      : 1  ; /* [0] */
        uint32_t    rng_seed_sel                : 1  ; /* [1] */
        uint32_t    rng_ring_en                 : 1  ; /* [2] */
        uint32_t    reserved_0                  : 29  ; /* [31..3] */
    } bits;

    uint32_t    status;
} U_RNG_CTRL_REG;

typedef union {
    struct {
        uint32_t    test_en_out                 : 1  ; /* [0] */
        uint32_t    test_patt_fro               : 1  ; /* [1] */
        uint32_t    test_patt_det               : 1  ; /* [2] */
        uint32_t    test_shiftreg               : 1  ; /* [3] */
        uint32_t    cont_poker                  : 1  ; /* [4] */
        uint32_t    test_known_noise            : 1  ; /* [5] */
        uint32_t    test_aes_256                : 1  ; /* [6] */
        uint32_t    test_sp_800_90              : 1  ; /* [7] */
        uint32_t    test_select                 : 5  ; /* [12..8] */
        uint32_t    test_noise                  : 1  ; /* [13] */
        uint32_t    test_spb                    : 1  ; /* [14] */
        uint32_t    test_cond_func              : 1  ; /* [15] */
        uint32_t    test_pattern                : 12  ; /* [27..16] */
        uint32_t    fro_testin2_not             : 1  ; /* [28] */
        uint32_t    fro_testin3                 : 1  ; /* [29] */
        uint32_t    fro_testin4                 : 1  ; /* [30] */
        uint32_t    test_irq                    : 1  ; /* [31] */
    } bits;

    uint32_t    status;
} U_TRNG_TEST_REG;


#endif
