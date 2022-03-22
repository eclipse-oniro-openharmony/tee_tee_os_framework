/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee demux register.
 * Author: SDK
 * Create: 2019-10-11
 */

#ifndef __TEE_DRV_DEMUX_REG_H__
#define __TEE_DRV_DEMUX_REG_H__

#include "tee_drv_demux_config.h"

/* add include here */
#ifdef __cplusplus
extern "C"
{
#endif
#define BITS_PER_REG                32
#define DMX_CHAN_CLEAR_TIMEOUT_CNT  100

/* DEMUX config regs */
#define DMX_CRG_REGS_IOBASE         0x00A00000
#define DMX_CRG_REGS205_OFFSET      0x0334
#define DMX_CRG_REGS206_OFFSET      0x0338
#define DMX_CRG_REGS207_OFFSET      0x033C

#ifndef readl
#define readl(addr)             (*(volatile u32 *)(addr))
#endif

#ifndef writel
#define writel(val, addr)       (*(volatile u32 *)(addr) = (val))
#endif

#define dmx_read_reg(base, offset)  readl((void *)(uintptr_t)((base) + (offset)))
#define dmx_write_reg(base, offset, value)   writel((value), (void *)(uintptr_t)((base) + (offset)))
#define dmx_com_equal(exp, act) do { \
    if ((exp) != (act)) {                                                           \
        hi_log_err("write register error, exp=0x%x, act=0x%x\n", (exp), (act));   \
    }                                                                               \
} while (0)

/* TS packet counter 0-5 of joining on someone record buffer low 32bit */
#define ts_cnt0_5_l(rec_id)               (0xC1B0 + ((rec_id) << 3))
/* TS packet counter 0-5 of joining on someone record buffer high 8 bits */
#define ts_cnt0_5_h(rec_id)               (0xC1B4 + ((rec_id) << 3))
/* TS packet counter 6-31 of joining on someone record buffer low 32bit */
#define ts_cnt6_31_l(rec_id)              (0xC500 + ((rec_id) << 3))
/* TS packet counter 6-31 of joining on someone record buffer high 8 bits */
#define ts_cnt6_31_h(rec_id)              (0xC504 + ((rec_id) << 3))

/* output description sub link-queue the first WORD corresponding address */
#define addr_oq_word0(oq_id)             (0xE000 + ((oq_id) << 4))
/* output description sub link-queue the second WORD corresponding address */
#define addr_oq_word1(oq_id)             (0xE004 + ((oq_id) << 4))
/* output description sub link-queue the third WORD corresponding address */
#define addr_oq_word2(oq_id)             (0xE008 + ((oq_id) << 4))
/* output description sub link-queue the fourth WORD corresponding address */
#define addr_oq_word3(oq_id)             (0xE00C + ((oq_id) << 4))
/* output description sub link-queue the fifth WORD corresponding address */
#define addr_oq_word4(oq_id)             (0xE800 + ((oq_id) << 4))
/* output description sub link-queue the sixth WORD corresponding address */
#define addr_oq_word5(oq_id)             (0xE804 + ((oq_id) << 4))
/* output description sub link-queue the seventh WORD corresponding address */
#define addr_oq_word6(oq_id)             (0xE808 + ((oq_id) << 4))
/* output description sub link-queue the eighth WORD corresponding address */
#define addr_oq_word7(oq_id)             (0xE80C + ((oq_id) << 4))

#define dmx_read_reg_sub(base, subbase, offset)  readl((void *)(uintptr_t)((base) + (subbase) + (offset)))
#define dmx_write_reg_sub(base, subbase, offset, val) writel(val, (void*)(uintptr_t)((base) + (subbase) + (offset)))

/* CRG register for demux */
/* Define the union u_peri_crg205 */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    pvr_tsi0_cken         : 1   ; /* [0]  */
        unsigned int    pvr_tsi1_cken         : 1   ; /* [1]  */
        unsigned int    pvr_tsi2_cken         : 1   ; /* [2]  */
        unsigned int    pvr_tsi3_cken         : 1   ; /* [3]  */
        unsigned int    pvr_tsi4_cken         : 1   ; /* [4]  */
        unsigned int    pvr_tsi5_cken         : 1   ; /* [5]  */
        unsigned int    pvr_tsi6_cken         : 1   ; /* [6]  */
        unsigned int    pvr_tsi7_cken         : 1   ; /* [7]  */
        unsigned int    pvr_tsi8_cken         : 1   ; /* [8]  */
        unsigned int    pvr_tsi9_cken         : 1   ; /* [9]  */
        unsigned int    pvr_tsi10_cken        : 1   ; /* [10]  */
        unsigned int    pvr_tsi11_cken        : 1   ; /* [11]  */
        unsigned int    pvr_tsi12_cken        : 1   ; /* [12]  */
        unsigned int    pvr_tsi13_cken        : 1   ; /* [13]  */
        unsigned int    pvr_tsi14_cken        : 1   ; /* [14]  */
        unsigned int    pvr_tsi15_cken        : 1   ; /* [15]  */
        unsigned int    pvr_tsi0_pctrl        : 1   ; /* [16]  */
        unsigned int    pvr_tsi1_pctrl        : 1   ; /* [17]  */
        unsigned int    pvr_tsi2_pctrl        : 1   ; /* [18]  */
        unsigned int    pvr_tsi3_pctrl        : 1   ; /* [19]  */
        unsigned int    pvr_tsi4_pctrl        : 1   ; /* [20]  */
        unsigned int    pvr_tsi5_pctrl        : 1   ; /* [21]  */
        unsigned int    pvr_tsi6_pctrl        : 1   ; /* [22]  */
        unsigned int    pvr_tsi7_pctrl        : 1   ; /* [23]  */
        unsigned int    pvr_tsi8_pctrl        : 1   ; /* [24]  */
        unsigned int    pvr_tsi9_pctrl        : 1   ; /* [25]  */
        unsigned int    pvr_tsi10_pctrl       : 1   ; /* [26]  */
        unsigned int    pvr_tsi11_pctrl       : 1   ; /* [27]  */
        unsigned int    pvr_tsi12_pctrl       : 1   ; /* [28]  */
        unsigned int    pvr_tsi13_pctrl       : 1   ; /* [29]  */
        unsigned int    reserved_0            : 2   ; /* [31..30]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} u_peri_crg205;

/* Define the union u_peri_crg206 */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    pvr_bus_cken          : 1   ; /* [0]  */
        unsigned int    pvr_dmx_cken          : 1   ; /* [1]  */
        unsigned int    pvr_27m_cken          : 1   ; /* [2]  */
        unsigned int    pvr_ts0_cken          : 1   ; /* [3]  */
        unsigned int    pvr_ts1_cken          : 1   ; /* [4]  */
        unsigned int    pvr_tsout0_cken       : 1   ; /* [5]  */
        unsigned int    pvr_tsout1_cken       : 1   ; /* [6]  */
        unsigned int    tsi2x_cken            : 1   ; /* [7]  */
        unsigned int    sw_dmx_clk_div        : 5   ; /* [12..8]  */
        unsigned int    sw_dmxclk_loaden      : 1   ; /* [13]  */
        unsigned int    pvr_tsi14_pctrl       : 1   ; /* [14]  */
        unsigned int    pvr_tsi15_pctrl       : 1   ; /* [15]  */
        unsigned int    dmx_srst_req          : 1   ; /* [16]  */
        unsigned int    dmx_clk_sel           : 2   ; /* [18..17]  */
        unsigned int    tsi2x_clk_sel         : 1   ; /* [19]  */
        unsigned int    reserved_0            : 12  ; /* [31..20]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} u_peri_crg206;

/* Define the union u_peri_crg207 */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    pvr_tsout0_pctrl      : 1   ; /* [0]  */
        unsigned int    pvr_tsout1_pctrl      : 1   ; /* [1]  */
        unsigned int    reserved_0            : 10  ; /* [11..2]  */
        unsigned int    pvr_ts0_cksel         : 2   ; /* [13..12]  */
        unsigned int    pvr_ts1_cksel         : 2   ; /* [15..14]  */
        unsigned int    pvr_ts0_clk_div       : 4   ; /* [19..16]  */
        unsigned int    pvr_ts1_clk_div       : 4   ; /* [23..20]  */
        unsigned int    pvr_tsi0_sel          : 1   ; /* [24]  */
        unsigned int    pvr_tsi1_sel          : 1   ; /* [25]  */
        unsigned int    pvr_tsi2_sel          : 1   ; /* [26]  */
        unsigned int    pvr_tsi3_sel          : 1   ; /* [27]  */
        unsigned int    reserved_1            : 4   ; /* [31..28]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} u_peri_crg207;

/******************************************************************************/
/*                      96cv300 DMX DAV(except RAM) register definition begin */
/******************************************************************************/
#define dmx_read_reg_dav(base, offset)  readl((void *)((base) + DMX_REGS_DAV_BASE + (offset)))
#define dmx_write_reg_dav(base, offset, value)   writel((value), (void*)((base) + DMX_REGS_DAV_BASE + (offset)))

/* Define the union U_DAV_TEE_RD_LOCK */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    dav_tee_rd_lock       : 1   ; /* [0]  */
        unsigned int    reserved_0            : 31  ; /* [31..1]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_DAV_TEE_RD_LOCK;
#define DAV_TEE_RD_LOCK                 0xB700   /* dav rd lock */

/* define the union U_IP_FQ_BUF */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    ip_fqsa              : 20  ; // [19..0] 4K align
        unsigned int    ip_fqsize            : 10  ; // [29..20] the depth of fq description queue
        unsigned int    ip_ip_rd_int_en      : 1   ; // [30]
        unsigned int    ip_tread_int_en      : 1   ; // [31]
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_IP_FQ_BUF;
#define ip_fq_buf(port_id)               (0xB900 + ((port_id) << 5))  /* IP channel 0 FQ descrition */

/* Define the union U_IP_FQ_SESSION */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    ip_fq_session         : 4   ; /* [3..0]  */
        unsigned int    reserved_0            : 28  ; /* [31..4]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_IP_FQ_SESSION;
#define ip_fq_session(port_id)           (0xB91C + ((port_id) << 5))  /* tsbuffer sesstion */

/* define the union U_IP_SEC_ATTR */
typedef union {
    /* define the struct bits  */
    struct {
        unsigned int ip_sec_attr            : 32  ; /* [31..0]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_IP_SEC_ATTR;
#define IP_SEC_ATTR                     0xBF84  /* ramport secure attr */

#define MMU_SEC_TLB               0xF000
#define MMU_SEC_EADDR             0xF008
#define MMU_SEC_EADDR_SESSION     0xF100
#define MMU_R_SEC_EADDR           0xF108
#define MMU_R_SEC_EADDR_SESSION   0xF110

#define MMU_NOSEC_TLB             0xF004
#define MMU_NOSEC_EADDR           0xF00C
#define MMU_NOSEC_EADDR_SESSION   0xF104
#define MMU_R_NOSEC_EADDR         0xF10C
#define MMU_R_NOSEC_EADDR_SESSION 0xF114

/* buf_idx from 0 to 31 */
#define mmu_buf_dis(buf_idx)    (0xF010 + ((buf_idx) << 2))
/* pc_idx from 0 to 1 */
#define mmu_pc_wdis_0(pc_idx)   (0xF090 + ((pc_idx) << 2))
#define mmu_pc_rdis_0(pc_idx)   (0xF098 + ((pc_idx) << 2))

#define MMU_IP_DIS               0xF0A0
#define MMU_IP_DES_DIS           0xF0F0

/* Define the union U_SEC_MMU_EN */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    sec_mmu_en            : 1   ; /* [0]  */
        unsigned int    reserved_0            : 31  ; /* [31..1]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_SEC_MMU_EN;

#define SEC_MMU_EN                    0xF0AC    /* secure smmu enable or disable register */

#define dmx_read_reg_buf(base, offset)  readl((void *)((base) + DMX_REGS_DAV_BASE + (offset)))
#define dmx_write_reg_buf(base, offset, value)   writel((value), (void*)((base) + DMX_REGS_DAV_BASE + (offset)))
/* Define the union U_BUF_SET */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    buf_sec_attr          : 4   ; /* [3..0]  */
        unsigned int    buf_lock              : 1   ; /* [4]  */
        unsigned int    reserved_0            : 27  ; /* [31..5]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_BUF_SET;
#define buf_set(buf_id)              (0x0 + ((buf_id) << 2)) /* buffer secure attribute */

/* define the union U_BUFSA */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    bufsa                 : 20  ; /* [19..0]  */
        unsigned int    buf_session           : 4   ; /* [23..20]  */
        unsigned int    reserved_0            : 8   ; /* [31..24]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_BUFSA;
#define buf_sa(buf_id)   (0x6000 + ((buf_id) << 2))  /* buf start address configure register */

/* define the union U_BUFSIZE */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    bufsize               : 14  ; /* [13..0]  */
        unsigned int    reserved_0            : 18  ; /* [31..14]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_BUFSIZE;
#define buf_size(buf_id)  (0x7000 + ((buf_id) << 2))  /* buf start address configure register */

/* define the union U_BUFRPTR */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    bufrptr               : 26  ; /* [25..0]  */
        unsigned int    reserved_0            : 6   ; /* [31..26]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_BUFRPTR;
#define buf_rptr(buf_id)  (0x9000 + ((buf_id) << 2))  /* buf read pointer configure register */

#define dmx_read_reg_ram(base, offset)  readl((void *)((base) + DMX_REGS_DAV_BASE + (offset)))
#define dmx_write_reg_ram(base, offset, value)   writel((value), (void*)((base) + DMX_REGS_DAV_BASE + (offset)))

/******************************************************************************/
/*                      96cv300 DMX PAR register definition  begin            */
/******************************************************************************/
#define dmx_read_reg_par(base, offset)  readl((void *)((base) + DMX_REGS_PAR_BASE + (offset)))
#define dmx_write_reg_par(base, offset, value)   writel((value), (void*)((base) + DMX_REGS_PAR_BASE + (offset)))

/* define the union U_PID_TAB_FILTER */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    mark_id               : 5   ; /* [4..0]  */
        unsigned int    reserved_0            : 3   ; /* [7..5]  */
        unsigned int    dmx_id                : 6   ; /* [13..8]  */
        unsigned int    reserved_1            : 2   ; /* [15..14]  */
        unsigned int    pid                   : 13  ; /* [28..16]  */
        unsigned int    reserved_2            : 2   ; /* [30..29]  */
        unsigned int    pid_tab_en            : 1   ; /* [31]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_PID_TAB_FILTER;
#define pid_tab_filter(pid_ch)           (0x0000 + ((pid_ch) << 4))   /* pid table filter register */

/* define the union U_PID_TAB_CTRL */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    pid_head_lock         : 1   ; /* [0]  */
        unsigned int    reserved_0            : 7   ; /* [7..1]  */
        unsigned int    pid_copy_en           : 1   ; /* [8]  */
        unsigned int    reserved_1            : 1   ; /* [9]  */
        unsigned int    cw_en                 : 1   ; /* [10]  */
        unsigned int    reserved_2            : 1   ; /* [11]  */
        unsigned int    whole_ts_en           : 1   ; /* [12]  */
        unsigned int    reserved_3            : 1   ; /* [13]  */
        unsigned int    pes_sec_en            : 1   ; /* [14]  */
        unsigned int    reserved_4            : 1   ; /* [15]  */
        unsigned int    av_pes_en             : 1   ; /* [16]  */
        unsigned int    reserved_5            : 1   ; /* [17]  */
        unsigned int    rec_en                : 1   ; /* [18]  */
        unsigned int    reserved_6            : 3   ; /* [21..19]  */
        unsigned int    ts_scd_en             : 1   ; /* [22]  */
        unsigned int    reserved_7            : 1   ; /* [23]  */
        unsigned int    pes_scd_en            : 1   ; /* [24]  */
        unsigned int    reserved_8            : 7   ; /* [31..25]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_PID_TAB_CTRL;
#define PID_TAB_CTRL(pid_ch)           (0x0004 + ((pid_ch) << 4))   /* pid table control register */

/* define the union U_PID_TAB_SUB_ID */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    pid_copy_id           : 6   ; /* [5..0]  */
        unsigned int    reserved_0            : 2   ; /* [7..6]  */
        unsigned int    cw_id                 : 8   ; /* [15..8]  */
        unsigned int    whole_sec_av_id       : 9   ; /* [24..16]  */
        unsigned int    reserved_1            : 3   ; /* [27..25]  */
        unsigned int    cc_repeat_drop        : 1   ; /* [28]  */
        unsigned int    cc_err_drop           : 1   ; /* [29]  */
        unsigned int    dsc_rec_mode          : 1   ; /* [30]  */
        unsigned int    reserved_2            : 1   ; /* [31]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_PID_TAB_SUB_ID;
#define PID_TAB_SUB_ID(pid_ch)         (0x0008 + ((pid_ch) << 4))   /* pid table control register */

/* define the union U_PID_TAB_REC_SCD */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    rec_id                : 7   ; /* [6..0]  */
        unsigned int    reserved_0            : 9   ; /* [15..7]  */
        unsigned int    scd_id                : 8   ; /* [23..16]  */
        unsigned int    reserved_1            : 1   ; /* [24]  */
        unsigned int    pes_scd_id            : 7   ; /* [31..25]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_PID_TAB_REC_SCD;
#define PID_TAB_REC_SCD(pid_ch)        (0x000C + ((pid_ch) << 4))   /* rec scd table control register */

/* define the union U_CW_TAB0 */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    ts_descram            : 1   ; /* [0]  */
        unsigned int    reserved_0            : 7   ; /* [7..1]  */
        unsigned int    pes_descram           : 1   ; /* [8]  */
        unsigned int    reserved_1            : 23  ; /* [31..9]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_CW_TAB;

#define CW_TAB0(dsc_id)           (0x8200 + ((dsc_id) << 2))   /* cw 0~127 control register */
#define CW_TAB1(dsc_id)           (0x8e00 + ((dsc_id) << 2))   /* cw 128~255 control register */

/* define the union U_WHOLE_TS_TAB */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    whole_ts_buf_id       : 10  ; /* [9..0]  */
        unsigned int    reserved_0            : 6   ; /* [15..10]  */
        unsigned int    whole_af_check_dis    : 1   ; /* [16]  */
        unsigned int    reserved_1            : 14  ; /* [30..17]  */
        unsigned int    whole_ts_lock         : 1   ; /* [31] */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_WHOLE_TS_TAB;
#define WHOLE_TS_TAB(ts_ch_id)           (0x8400 + ((ts_ch_id) << 2))   /* whole ts table control register */

    /* define the union U_AV_PES_TAB */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    av_pes_buf_id         : 10  ; /* [9..0]  */
        unsigned int    reserved_0            : 6   ; /* [15..10]  */
        unsigned int    av_pusi_en            : 1   ; /* [16]  */
        unsigned int    reserved_1            : 7   ; /* [23..17]  */
        unsigned int    flt_rec_sel           : 1   ; /* [24]  */
        unsigned int    reserved_2            : 3   ; /* [27..25]  */
        unsigned int    av_pes_len_det        : 1   ; /* [28]  */
        unsigned int    reserved_3            : 2   ; /* [30..29]  */
        unsigned int    av_pes_lock           : 1   ; /* [31]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_AV_PES_TAB;
#define AV_PES_TAB(av_ch_idx)            (0x9200 + ((av_ch_idx) << 2))   /* avpes table control register */

/* define the union U_PES_SEC_TAB0 */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    data_type             : 1   ; /* [0]  */
        unsigned int    reserved_0            : 7   ; /* [7..1]  */
        unsigned int    pes_sec_pusi_en       : 1   ; /* [8]  */
        unsigned int    reserved_1            : 7   ; /* [15..9]  */
        unsigned int    pes_sec_len_det       : 1   ; /* [16]  */
        unsigned int    reserved_2            : 7   ; /* [23..17]  */
        unsigned int    pes_sec_lock          : 1   ; /* [24]  */
        unsigned int    reserved_3            : 7   ; /* [31..25]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_PES_SEC_TAB0;
#define PES_SEC_TAB0(pes_sec_ch_inx)     (0x9600 + ((pes_sec_ch_inx) << 2))   /* pes section table control register */

/* define the union u_pid_tab_sub_id */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    pid_copy_id           : 6   ; /* [5..0]  */
        unsigned int    reserved_0            : 2   ; /* [7..6]  */
        unsigned int    cw_id                 : 8   ; /* [15..8]  */
        unsigned int    whole_sec_av_id       : 9   ; /* [24..16]  */
        unsigned int    reserved_1            : 3   ; /* [27..25]  */
        unsigned int    cc_repeat_drop        : 1   ; /* [28]  */
        unsigned int    cc_err_drop           : 1   ; /* [29]  */
        unsigned int    dsc_rec_mode          : 1   ; /* [30]  */
        unsigned int    reserved_2            : 1   ; /* [31]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} u_pid_tab_sub_id;

#define pid_tab_sub_id(pid_ch)         (0x0008 + ((pid_ch) << 4))   /* pid table control register */

/******************************************************************************/
/*               96cv300 DMX SCD register definition  begin                   */
/******************************************************************************/
#define dmx_read_reg_scd(base, offset)  readl((void *)((base) + DMX_REGS_SCD_BASE + (offset)))
#define dmx_write_reg_scd(base, offset, value)   writel((value), (void*)((base) + DMX_REGS_SCD_BASE + (offset)))

/* define the union U_TS_REC_CFG_H32 */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    rec_cnt_h8            : 8   ; /* [7..0]  */
        unsigned int    ctrl_mode             : 1   ; /* [8]  */
        unsigned int    af_error              : 3   ; /* [11..9]  */
        unsigned int    crc_ctrl_err          : 1   ; /* [12]  */
        unsigned int    crc_sync_err          : 1   ; /* [13]  */
        unsigned int    ctrl_edit_dis         : 1   ; /* [14]  */
        unsigned int    chn_crc_en            : 1   ; /* [15]  */
        unsigned int    rec_bufid             : 10  ; /* [25..16]  */
        unsigned int    avpes_drop_en         : 1   ; /* [26]  */
        unsigned int    avpes_cut_dis         : 1   ; /* [27]  */
        unsigned int    avpes_len_dis         : 1   ; /* [28]  */
        unsigned int    chn_mode              : 1   ; /* [29]  */
        unsigned int    chn_tee_lock          : 1   ; /* [30]  */
        unsigned int    rec_chn_en            : 1   ; /* [31]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_REC_CFG_H32;

#define TS_REC_CFG_H32(rec_id)      (0x0200 + ((rec_id) << 2))   /* rec configure high 32bits register */
#define TS_REC_CFG_L32(rec_id)      (0x0400 + ((rec_id) << 2))   /* rec configure low 32bits register */

/* define the union U_TS_SCD_CFG_H32 */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    scd_flth_en           : 8   ; /* [7..0]  */
        unsigned int    lock_drop_en          : 1   ; /* [8]  */
        unsigned int    idx_mode              : 1   ; /* [9]  */
        unsigned int    reserved_0            : 5   ; /* [14..10]  */
        unsigned int    pes_len_det_en        : 1   ; /* [15]  */
        unsigned int    ts_scd_bufid          : 10  ; /* [25..16]  */
        unsigned int    scd_es_short_en       : 1   ; /* [26]  */
        unsigned int    scd_es_long_en        : 1   ; /* [27]  */
        unsigned int    scd_pes_en            : 1   ; /* [28]  */
        unsigned int    scd_tpit_en           : 1   ; /* [29]  */
        unsigned int    scd_tee_lock          : 1   ; /* [30]  */
        unsigned int    scd_chn_en            : 1   ; /* [31]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} u_scd_cfg_h32;

#define ts_scd_cfg_h32(scd_id)      (0x0600 + ((scd_id) << 2))   /* scd configure high 32bits register */
#define ts_scd_cfg_l32(scd_id)      (0x0A00 + ((scd_id) << 2))   /* scd configure low 32bits register */

/******************************************************************************/
/*                      hi96cv300 DMX MDSC register definition  begin                  */
/******************************************************************************/
#define dmx_read_reg_mdsc(base, offset)  readl((void *)((base) + (offset)))
#define dmx_write_reg_mdsc(base, offset, value)   writel((value), (void*)((base) + (offset)))

#define KEY_ENCRPTY_SEL(reg_idx)      (0x0000 + ((reg_idx) << 2))  /* IV or CW KEY even/odd bits select register */
#define CSA2_ENTROPY_CLOSE(reg_idx)   (0x0020 + ((reg_idx) << 2))  /* CSA2 entropy decrease register */

/* define the union U_MDSC_EN */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    reserved_0            : 8   ; /* [7..0]  */
        unsigned int    ca_en                 : 1   ; /* [8]  */
        unsigned int    reserved_1            : 3   ; /* [11..9]  */
        unsigned int    ts_ctrl_dsc_change_en : 1   ; /* [12]  */
        unsigned int    reserved_2            : 11  ; /* [23..13]  */
        unsigned int    cw_iv_en              : 1   ; /* [24]  */
        unsigned int    reserved_3            : 7   ; /* [31..25]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_MDSC_EN;
#define MDSC_EN                     (0x0050)          /* MDSC enable register  */

/* define the union U_MDSC_CPD_CORE_DISABLE */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    cpd_core_disable      : 8   ; /* [7..0]  */
        unsigned int    reserved_0            : 24  ; /* [31..8]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_MDSC_CPD_CORE_DISABLE;
#define MDSC_CPD_CORE_DISABLE       (0x0054)          /* MDSC CPD core enable register  */

/* define the union U_MDSC_CA_CORE_DISABLE */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    ca_core_disable       : 28  ; /* [27..0]  */
        unsigned int    reserved_0            : 4   ; /* [31..28]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_MDSC_CA_CORE_DISABLE;
#define MDSC_CA_CORE_DISABLE        (0x0058)          /* MDSC CA core enable register  */

/* define the union U_MDSC_CPS_CORE_DISABLE */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    cps_core_disable      : 8   ; /* [7..0]  */
        unsigned int    reserved_0            : 24  ; /* [31..8]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} U_MDSC_CPS_CORE_DISABLE;
#define MDSC_CPS_CORE_DISABLE       (0x005C)          /* MDSC CPS core enable register  */

#define  KEY_SLOT_SEC_CFG0           0x400            /* cw0~31 */
#define  KEY_SLOT_SEC_CFG1           0x404            /* cw32~63 */
#define  KEY_SLOT_SEC_CFG2           0x408            /* cw64~95 */
#define  KEY_SLOT_SEC_CFG3           0x40c            /* cw96~127 */
#define  KEY_SLOT_SEC_CFG4           0x410            /* cw128~159 */
#define  KEY_SLOT_SEC_CFG5           0x414            /* cw160~191 */
#define  KEY_SLOT_SEC_CFG6           0x418            /* cw192~223 */
#define  KEY_SLOT_SEC_CFG7           0x41c            /* cw224~255 */

/* Define the union U_KEY_SLOT_SEC_CFG_LOCK */
typedef union {
    /* Define the struct bits */
    struct    {
        unsigned int    key_slot_sec_cfg_lock : 4   ; /* [3..0]  */
        unsigned int    reserved_0            : 28  ; /* [31..4]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} U_KEY_SLOT_SEC_CFG_LOCK;

/* define the union u_dmx_filter_ctrl */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    crc_mode              : 3   ; /* [2..0]  */
        unsigned int    reserved_0            : 5   ; /* [7..3]  */
        unsigned int    pes_len_err_drop_dis  : 1   ; /* [8]  */
        unsigned int    reserved_1            : 7   ; /* [15..9]  */
        unsigned int    flt_num               : 5   ; /* [20..16]  */
        unsigned int    reserved_2            : 3   ; /* [23..21]  */
        unsigned int    flt_min               : 4   ; /* [27..24]  */
        unsigned int    reserved_3            : 1   ; /* [28]  */
        unsigned int    no_flt_mode           : 1   ; /* [29]  */
        unsigned int    reserved_4            : 1   ; /* [30]  */
        unsigned int    flt_pes_sec_lock      : 1   ; /* [31]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} u_dmx_filter_ctrl;

#define DMX_FILTER_CTRL                         (0x0104)   /* filter ctrl register */

/* define the union u_dmx_pes_sec_id */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    pes_sec_id            : 9   ; /* [8..0]  */
        unsigned int    reserved_0            : 7   ; /* [15..9]  */
        unsigned int    pes_sec_id_lock       : 1   ; /* [16]  */
        unsigned int    reserved_1            : 15  ; /* [31..17]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} u_dmx_pes_sec_id;
#define DMX_PES_SEC_ID                          (0x0100)   /* filter pes sec id */

/* define the union u_dmx_filter_id */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    fit_id                : 10  ; /* [9..0]  */
        unsigned int    reserved_0            : 22  ; /* [31..10]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} u_dmx_filter_id;

#define dmx_filter_id(flt_id)                    (0x010C + ((flt_id) << 2))   /* filter id register */

#define DMX_FILTER_EN                           (0x0108)   /* filter enable register */

#define dmx_read_reg_flt(base, offset)  readl((void *)((base) + DMX_REGS_FLT_BASE + (offset)))
#define dmx_write_reg_flt(base, offset, value)   writel((value), (void*)((base) + DMX_REGS_FLT_BASE + (offset)))

/* define the union u_dmx_filter_buf_id */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    flt_buf_id            : 10  ; /* [9..0]  */
        unsigned int    reserved_0            : 22  ; /* [31..10]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} u_dmx_filter_buf_id;

#define DMX_FILTER_BUF_ID                       (0x018C)   /* filter buffer id */

/* define the union u_dmx_ts_ctrl_tab */
typedef union {
    /* Define the struct bits */
    struct {
        unsigned int    full_ts_buf_id        : 10  ; /* [9..0]  */
        unsigned int    reserved_0            : 1   ; /* [10]  */
        unsigned int    tei_drop              : 1   ; /* [11]  */
        unsigned int    cc_err_pusi_save      : 1   ; /* [12]  */
        unsigned int    cc_repeat_pusi_save   : 1   ; /* [13]  */
        unsigned int    dmx_ts_replace_47     : 1   ; /* [14]  */
        unsigned int    reserved_1            : 16  ; /* [30..15]  */
        unsigned int    dmx_tab_lock          : 1   ; /* [31]  */
    } bits;

    /* Define an unsigned member */
    unsigned int    u32;
} u_dmx_ts_ctrl_tab;

#define dmx_ts_ctrl_tab(band)               (0x9e00 + ((band) << 2))

/* define the union u_dmx_sec_global_ctrl */
typedef union {
    /* define the struct bits */
    struct {
        unsigned int    point_err_mode        : 1   ; /* [0]  */
        unsigned int    reserved_0            : 3   ; /* [3..1]  */
        unsigned int    point_err_deal        : 1   ; /* [4]  */
        unsigned int    reserved_1            : 3   ; /* [7..5]  */
        unsigned int    new_sec_pusi_point    : 1   ; /* [8]  */
        unsigned int    new_sec_pusi_nopint   : 1   ; /* [9]  */
        unsigned int    new_sec_nopusi        : 1   ; /* [10]  */
        unsigned int    reserved_2            : 21  ; /* [31..11]  */
    } bits;

    /* define an unsigned member */
    unsigned int    u32;
} u_dmx_sec_global_ctrl;

#define DMX_SEC_GLOBAL_CTRL                     (0x0200)   /* section global ctrl register */

#define KEY_SLOT_SEC_CFG_LOCK       (0x0460)          /* key slot secure config register  */

#define MULTI2_SYS_KEY0             (0x0480)          /* MULTI2 sys_key0 */
#define MULTI2_SYS_KEY1             (0x0484)          /* MULTI2 sys_key1 */
#define MULTI2_SYS_KEY2             (0x0488)          /* MULTI2 sys_key2 */
#define MULTI2_SYS_KEY3             (0x048c)          /* MULTI2 sys_key3 */
#define MULTI2_SYS_KEY4             (0x0490)          /* MULTI2 sys_key4 */
#define MULTI2_SYS_KEY5             (0x0494)          /* MULTI2 sys_key5 */
#define MULTI2_SYS_KEY6             (0x0498)          /* MULTI2 sys_key6 */
#define MULTI2_SYS_KEY7             (0x049c)          /* MULTI2 sys_key7 */

#ifdef __cplusplus
}
#endif
#endif /* end #ifndef __TEE_DRV_DEMUX_REG_H__ */

