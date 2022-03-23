/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: CRG¼Ä´æÆ÷¶¨Òå
 * Author: o00302765
 * Create: 2019-10-22
 */

#ifndef __HI_SEC_REG_CRG_DIO_H__
#define __HI_SEC_REG_CRG_DIO_H__

#ifdef __MACRO__
#endif
#define HI_SEC_REG_CRG_DIO_BASE                    0x14880000
#define HI_SEC_REG_CRG_DIO_SC_SYSSTAT_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x0000)
#define HI_SEC_REG_CRG_DIO_COMBPLL_CTRL0_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x0004)
#define HI_SEC_REG_CRG_DIO_COMBPLL_CTRL1_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x0008)
#define HI_SEC_REG_CRG_DIO_SC_RST_PROTECT_BASE     (HI_SEC_REG_CRG_DIO_BASE + 0x000C)
#define HI_SEC_REG_CRG_DIO_SC_SYSCNT_PROTECT_BASE  (HI_SEC_REG_CRG_DIO_BASE + 0x0010)
#define HI_SEC_REG_CRG_DIO_SC_PER_CLK_EN0_BASE     (HI_SEC_REG_CRG_DIO_BASE + 0x0014)
#define HI_SEC_REG_CRG_DIO_SC_PER_CLK_DIS0_BASE    (HI_SEC_REG_CRG_DIO_BASE + 0x0018)
#define HI_SEC_REG_CRG_DIO_SC_PER_CLK_ST0_BASE     (HI_SEC_REG_CRG_DIO_BASE + 0x001C)
#define HI_SEC_REG_CRG_DIO_SC_PER_CLK_EN1_BASE     (HI_SEC_REG_CRG_DIO_BASE + 0x0020)
#define HI_SEC_REG_CRG_DIO_SC_PER_CLK_DIS1_BASE    (HI_SEC_REG_CRG_DIO_BASE + 0x0024)
#define HI_SEC_REG_CRG_DIO_SC_PER_CLK_ST1_BASE     (HI_SEC_REG_CRG_DIO_BASE + 0x0028)
#define HI_SEC_REG_CRG_DIO_SC_RST_CTRL0_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x002C)
#define HI_SEC_REG_CRG_DIO_SC_RST_CTRL1_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x0030)
#define HI_SEC_REG_CRG_DIO_SC_RST_CTRL2_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x0034)
#define HI_SEC_REG_CRG_DIO_CPU_CFG_BASE            (HI_SEC_REG_CRG_DIO_BASE + 0x0038)
#define HI_SEC_REG_CRG_DIO_HW_CFG_BASE             (HI_SEC_REG_CRG_DIO_BASE + 0x003C)
#define HI_SEC_REG_CRG_DIO_WIFI_CFG_BASE           (HI_SEC_REG_CRG_DIO_BASE + 0x0040)
#define HI_SEC_REG_CRG_DIO_USB_CFG_BASE            (HI_SEC_REG_CRG_DIO_BASE + 0x0044)
#define HI_SEC_REG_CRG_DIO_SC_PERCTRL2_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x0048)
#define HI_SEC_REG_CRG_DIO_CLK_FREQ_CFG_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x004C)
#define HI_SEC_REG_CRG_DIO_SC_PERCTRL4_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x0050)
#define HI_SEC_REG_CRG_DIO_SC_PERCTRL5_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x0054)
#define HI_SEC_REG_CRG_DIO_SC_PERCTRL6_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x0058)
#define HI_SEC_REG_CRG_DIO_SC_PERCTRL7_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x0060)
#define HI_SEC_REG_CRG_DIO_SC_PERCTRL8_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x0064)
#define HI_SEC_REG_CRG_DIO_WDG_INIT_CFG_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x0070)
#define HI_SEC_REG_CRG_DIO_A9PLL_CTRL0_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x0074)
#define HI_SEC_REG_CRG_DIO_A9PLL_CTRL1_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x0078)
#define HI_SEC_REG_CRG_DIO_PCIEPLL_CTRL0_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x007C)
#define HI_SEC_REG_CRG_DIO_PCIEPLL_CTRL1_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x0080)
#define HI_SEC_REG_CRG_DIO_USR_DF_CFG0_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x0084)
#define HI_SEC_REG_CRG_DIO_CLK_DET_CTRL_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x008C)
#define HI_SEC_REG_CRG_DIO_CRG_STAT0_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x0090)
#define HI_SEC_REG_CRG_DIO_CRG_STAT1_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x0094)
#define HI_SEC_REG_CRG_DIO_PLL_LOCK_FILTER_EN_BASE (HI_SEC_REG_CRG_DIO_BASE + 0x0098)
#define HI_SEC_REG_CRG_DIO_PD_RESET_CTRL_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x00A0)
#define HI_SEC_REG_CRG_DIO_RAM_CTRL0_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x00B0)
#define HI_SEC_REG_CRG_DIO_RAM_CTRL1_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x00B4)
#define HI_SEC_REG_CRG_DIO_RAM_CTRL2_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x00B8)
#define HI_SEC_REG_CRG_DIO_RAM_CTRL3_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x00BC)
#define HI_SEC_REG_CRG_DIO_GEMAC0_RGMII_CTRL_BASE  (HI_SEC_REG_CRG_DIO_BASE + 0x00D0)
#define HI_SEC_REG_CRG_DIO_GEMAC1_RGMII_CTRL_BASE  (HI_SEC_REG_CRG_DIO_BASE + 0x00D4)
#define HI_SEC_REG_CRG_DIO_GEMAC2_RGMII_CTRL_BASE  (HI_SEC_REG_CRG_DIO_BASE + 0x00D8)
#define HI_SEC_REG_CRG_DIO_GEMAC3_RGMII_CTRL_BASE  (HI_SEC_REG_CRG_DIO_BASE + 0x00DC)
#define HI_SEC_REG_CRG_DIO_GEMAC4_RGMII_CTRL_BASE  (HI_SEC_REG_CRG_DIO_BASE + 0x00E0)
#define HI_SEC_REG_CRG_DIO_GEMAC5_RGMII_CTRL_BASE  (HI_SEC_REG_CRG_DIO_BASE + 0x00E4)
#define HI_SEC_REG_CRG_DIO_A9_PLL_AFS_CTRL_BASE    (HI_SEC_REG_CRG_DIO_BASE + 0x00E8)
#define HI_SEC_REG_CRG_DIO_PCIE_REF_DIV_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x00EC)
#define HI_SEC_REG_CRG_DIO_PTP_8K_FTW_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x00F0)
#define HI_SEC_REG_CRG_DIO_PTP_8K_MAX_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x00F4)
#define HI_SEC_REG_CRG_DIO_CLK_SHUT_SEL_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x00F8)
#define HI_SEC_REG_CRG_DIO_CRG_INT_STATUS_BASE     (HI_SEC_REG_CRG_DIO_BASE + 0x0100)
#define HI_SEC_REG_CRG_DIO_CRG_INT_MASK_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x0104)
#define HI_SEC_REG_CRG_DIO_CRG_INT_SET_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x0108)
#define HI_SEC_REG_CRG_DIO_NNI_MODE_BASE           (HI_SEC_REG_CRG_DIO_BASE + 0x0118)
#define HI_SEC_REG_CRG_DIO_UNI_MODE_BASE           (HI_SEC_REG_CRG_DIO_BASE + 0x011C)
#define HI_SEC_REG_CRG_DIO_PON_PRI_MODE_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x0120)
#define HI_SEC_REG_CRG_DIO_SATA_MODE_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x0124)
#define HI_SEC_REG_CRG_DIO_I2S0_CFG0_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x0128)
#define HI_SEC_REG_CRG_DIO_I2S0_CFG1_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x012C)
#define HI_SEC_REG_CRG_DIO_EMMC_CFG_BASE           (HI_SEC_REG_CRG_DIO_BASE + 0x0130)
#define HI_SEC_REG_CRG_DIO_CLK_PLL_SRC_SEL_BASE    (HI_SEC_REG_CRG_DIO_BASE + 0x0134)
#define HI_SEC_REG_CRG_DIO_CLK_OTHER_SRC_SEL_BASE  (HI_SEC_REG_CRG_DIO_BASE + 0x0138)
#define HI_SEC_REG_CRG_DIO_CMU_TRACE_DIV_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x013C)
#define HI_SEC_REG_CRG_DIO_CMU_CTRL0_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x0140)
#define HI_SEC_REG_CRG_DIO_CMU_CTRL1_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x0144)
#define HI_SEC_REG_CRG_DIO_PON_SDS_CTRL0_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x0148)
#define HI_SEC_REG_CRG_DIO_PON_SDS_CTRL1_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x014C)
#define HI_SEC_REG_CRG_DIO_XFI_SDS_CTRL0_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x0150)
#define HI_SEC_REG_CRG_DIO_XFI_SDS_CTRL1_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x0154)
#define HI_SEC_REG_CRG_DIO_I2S1_CFG0_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x0158)
#define HI_SEC_REG_CRG_DIO_I2S1_CFG1_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x015C)
#define HI_SEC_REG_CRG_DIO_SDS_ST_BASE             (HI_SEC_REG_CRG_DIO_BASE + 0x0160)
#define HI_SEC_REG_CRG_DIO_SDS_CMU_ST_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x0164)
#define HI_SEC_REG_CRG_DIO_SDS_CMU_HIS_ST_BASE     (HI_SEC_REG_CRG_DIO_BASE + 0x0168)
#define HI_SEC_REG_CRG_DIO_RCD_CTRL0_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x0170)
#define HI_SEC_REG_CRG_DIO_RCD_CTRL1_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x0174)
#define HI_SEC_REG_CRG_DIO_RCD_CTRL2_BASE          (HI_SEC_REG_CRG_DIO_BASE + 0x0178)
#define HI_SEC_REG_CRG_DIO_USBPLL_FBDIV_CHK_BASE   (HI_SEC_REG_CRG_DIO_BASE + 0x017C)
#define HI_SEC_REG_CRG_DIO_OSC_RING_CTRL_BASE      (HI_SEC_REG_CRG_DIO_BASE + 0x0180)
#define HI_SEC_REG_CRG_DIO_CPUPLL_FBDIV_CHK_BASE   (HI_SEC_REG_CRG_DIO_BASE + 0x0184)
#define HI_SEC_REG_CRG_DIO_DDRPLL_FBDIV_CHK_BASE   (HI_SEC_REG_CRG_DIO_BASE + 0x0188)
#define HI_SEC_REG_CRG_DIO_HWPLL_FBDIV_CHK_BASE    (HI_SEC_REG_CRG_DIO_BASE + 0x018C)
#define HI_SEC_REG_CRG_DIO_LSWPLL_FBDIV_CHK_BASE   (HI_SEC_REG_CRG_DIO_BASE + 0x0190)
#define HI_SEC_REG_CRG_DIO_COMBPLL_FBDIV_CHK_BASE  (HI_SEC_REG_CRG_DIO_BASE + 0x0194)
#define HI_SEC_REG_CRG_DIO_CPUPLL_CTRL0_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x0198)
#define HI_SEC_REG_CRG_DIO_CPUPLL_CTRL1_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x019C)
#define HI_SEC_REG_CRG_DIO_CPUPLL_CTRL2_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01A0)
#define HI_SEC_REG_CRG_DIO_CPUPLL_CTRL3_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01A4)
#define HI_SEC_REG_CRG_DIO_CPUPLL_CTRL4_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01A8)
#define HI_SEC_REG_CRG_DIO_CPUPLL_CTRL5_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01AC)
#define HI_SEC_REG_CRG_DIO_DDRPLL_CTRL0_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01B0)
#define HI_SEC_REG_CRG_DIO_DDRPLL_CTRL1_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01B4)
#define HI_SEC_REG_CRG_DIO_USBPLL_CTRL0_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01B8)
#define HI_SEC_REG_CRG_DIO_USBPLL_CTRL1_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01BC)
#define HI_SEC_REG_CRG_DIO_HWPLL_CTRL0_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x01C8)
#define HI_SEC_REG_CRG_DIO_HWPLL_CTRL1_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x01CC)
#define HI_SEC_REG_CRG_DIO_HWPLL_CTRL2_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x01D0)
#define HI_SEC_REG_CRG_DIO_HWPLL_CTRL3_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x01D4)
#define HI_SEC_REG_CRG_DIO_HWPLL_CTRL4_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x01D8)
#define HI_SEC_REG_CRG_DIO_HWPLL_CTRL5_BASE        (HI_SEC_REG_CRG_DIO_BASE + 0x01DC)
#define HI_SEC_REG_CRG_DIO_LSWPLL_CTRL0_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01E0)
#define HI_SEC_REG_CRG_DIO_LSWPLL_CTRL1_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01E4)
#define HI_SEC_REG_CRG_DIO_LSWPLL_CTRL2_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01E8)
#define HI_SEC_REG_CRG_DIO_LSWPLL_CTRL3_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01EC)
#define HI_SEC_REG_CRG_DIO_LSWPLL_CTRL4_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01F0)
#define HI_SEC_REG_CRG_DIO_LSWPLL_CTRL5_BASE       (HI_SEC_REG_CRG_DIO_BASE + 0x01F4)
#define HI_SEC_REG_CRG_DIO_SAFE_CTRL0_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x40000)
#define HI_SEC_REG_CRG_DIO_SAFE_CTRL1_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x40004)
#define HI_SEC_REG_CRG_DIO_SAFE_CTRL2_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x40008)
#define HI_SEC_REG_CRG_DIO_SAFE_CTRL3_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x4000c)
#define HI_SEC_REG_CRG_DIO_SAFE_CTRL4_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x40010)
#define HI_SEC_REG_CRG_DIO_SAFE_CTRL5_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x40014)
#define HI_SEC_REG_CRG_DIO_SAFE_CTRL6_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x40018)
#define HI_SEC_REG_CRG_DIO_SAFE_CTRL7_BASE         (HI_SEC_REG_CRG_DIO_BASE + 0x4001c)

#ifdef __STRUCT__
#endif
struct hi_sec_reg_crg_dio_sc_sysstat_s {
	hi_uint32  ui_soft_cfg                        : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_combpll_ctrl0_s {
	hi_uint32  ui_foutvcopd_comb                  : 1 ; /*[0:0]*/
	hi_uint32  ui_foutpostdivpd_comb              : 1 ; /*[1:1]*/
	hi_uint32  ui_fout4phasepd_comb               : 1 ; /*[2:2]*/
	hi_uint32  ui_dsmpd_comb                      : 1 ; /*[3:3]*/
	hi_uint32  ui_postdiv2_comb                   : 3 ; /*[4:6]*/
	hi_uint32  ui_pd_comb                         : 1 ; /*[7:7]*/
	hi_uint32  ui_postdiv1_comb                   : 3 ; /*[8:10]*/
	hi_uint32  ui_dacpd_comb                      : 1 ; /*[11:11]*/
	hi_uint32  ui_fbdiv_comb                      : 12; /*[12:23]*/
	hi_uint32  ui_refdiv_comb                     : 6 ; /*[24:29]*/
	hi_uint32  ui_bypass_comb                     : 1 ; /*[30:30]*/
	hi_uint32  ui_disable_sscg_comb               : 1 ; /*[31:31]*/
};

struct hi_sec_reg_crg_dio_combpll_ctrl1_s {
	hi_uint32  ui_frac_comb                       : 24; /*[0:23]*/
	hi_uint32  ui_downspread_comb                 : 1 ; /*[24:24]*/
	hi_uint32  ui_spread_comb                     : 3 ; /*[25:27]*/
	hi_uint32  ui_divval_comb                     : 4 ; /*[28:31]*/
};

struct hi_sec_reg_crg_dio_sc_rst_protect_s {
	hi_uint32 kdf_srst_n                      : 1 ; /*[0:0]*/
	hi_uint32 trng_srst_n                     : 1 ; /*[1:1]*/
	hi_uint32 timer0_srst_n                   : 1 ; /*[2:2]*/
	hi_uint32 timer1_srst_n                   : 1 ; /*[3:3]*/
	hi_uint32 timer2_srst_n                   : 1 ; /*[4:4]*/
	hi_uint32 pke_srst_n                      : 1 ; /*[5:5]*/
	hi_uint32 sa_srst_n                       : 1 ; /*[6:6]*/
	hi_uint32 sec_srst_n                      : 1 ; /*[7:7]*/
	hi_uint32 gic_srst_n                      : 1 ; /*[8:8]*/
	hi_uint32 ddrc_srst_n                     : 1 ; /*[9:9]*/
	hi_uint32 apb_ddrc_srst_n                 : 1 ; /*[10:10]*/
	hi_uint32 ddrt_srst_n                     : 1 ; /*[11:11]*/
	hi_uint32 apb_ddrt_srst_n                 : 1 ; /*[12:12]*/
	hi_uint32 apb_syscnt_srst_n               : 1 ; /*[13:13]*/
	hi_uint32 base_syscnt_srst_n              : 1 ; /*[14:14]*/
	hi_uint32 resv_0                          : 17; /*[15:31]*/
};

struct hi_sec_reg_crg_dio_sc_syscnt_protect_s {
	hi_uint32  ui_syscnt_clk_stat                 : 1 ; /*[0:0]*/
	hi_uint32  ui_syscnt_clk_dis                  : 1 ; /*[1:1]*/
	hi_uint32  ui_syscnt_clk_en                   : 1 ; /*[2:2]*/
	hi_uint32  ui_resv_0                          : 29; /*[3:31]*/
};

struct hi_sec_reg_crg_dio_sc_per_clk_en0_s {
	hi_uint32 fmc_clk_en      : 1 ;
	hi_uint32 resv_0          : 1 ;
	hi_uint32 ec_clk_en       : 1 ;
	hi_uint32 hw_clk_en       : 1 ;
	hi_uint32 ddrc_clk_en     : 1 ;
	hi_uint32 ddrc_apb_clk_en : 1 ;
	hi_uint32 ddrt_clk_en     : 1 ;
	hi_uint32 ddrt_apb_clk_en : 1 ;
	hi_uint32 spi0_clk_en     : 1 ;
	hi_uint32 spi1_clk_en     : 1 ;
	hi_uint32 uart0_clk_en    : 1 ;
	hi_uint32 uart1_clk_en    : 1 ;
	hi_uint32 uart2_clk_en    : 1 ;
	hi_uint32 uart3_clk_en    : 1 ;
	hi_uint32 led_clk_en      : 1 ;
	hi_uint32 resv_1          : 2 ;
	hi_uint32 timer0_clk_en   : 1 ;
	hi_uint32 timer1_clk_en   : 1 ;
	hi_uint32 timer2_clk_en   : 1 ;
	hi_uint32 gpio0_clk_en    : 1 ;
	hi_uint32 gpio1_clk_en    : 1 ;
	hi_uint32 gpio2_clk_en    : 1 ;
	hi_uint32 gpio3_clk_en    : 1 ;
	hi_uint32 i2c0_clk_en     : 1 ;
	hi_uint32 i2c1_clk_en     : 1 ;
	hi_uint32 kdf_clk_en      : 1 ;
	hi_uint32 trng_clk_en     : 1 ;
	hi_uint32 tzpc_clk_en     : 1 ;
	hi_uint32 resv_3          : 2 ;
	hi_uint32 resv_4          : 1 ;
};

struct hi_sec_reg_crg_dio_sc_per_clk_en1_s {
	hi_uint32 dp_clk_en             : 1 ;
	hi_uint32 pfe_clk_en            : 1 ;
	hi_uint32 resv_0                : 1 ;
	hi_uint32 mdio0_clk_en          : 1 ;
	hi_uint32 mdio1_clk_en          : 1 ;
	hi_uint32 pcs_clk_en            : 1 ;
	hi_uint32 resv_1                : 1 ;
	hi_uint32 pke_clk_en            : 1 ;
	hi_uint32 sa_clk_en             : 1 ;
	hi_uint32 sec_clk_en            : 1 ;
	hi_uint32 gic_clk_en            : 1 ;
	hi_uint32 dma_clk_en            : 1 ;
	hi_uint32 pcie0_clk_en          : 1 ;
	hi_uint32 pcie1_clk_en          : 1 ;
	hi_uint32 pcie2_clk_en          : 1 ;
	hi_uint32 port0_usb2_phy_clk_en : 1 ;
	hi_uint32 usb_ctrl_clk_en       : 1 ;
	hi_uint32 port0_usb3_phy_clk_en : 1 ;
	hi_uint32 sata_phy_clk_en       : 1 ;
	hi_uint32 gemac0_clk_en         : 1 ;
	hi_uint32 gemac1_clk_en         : 1 ;
	hi_uint32 gemac2_clk_en         : 1 ;
	hi_uint32 gemac3_clk_en         : 1 ;
	hi_uint32 gemac4_clk_en         : 1 ;
	hi_uint32 gemac5_clk_en         : 1 ;
	hi_uint32 pie_clk_en            : 1 ;
	hi_uint32 sdio_clk_en           : 1 ;
	hi_uint32 i2s0_clk_en           : 1 ;
	hi_uint32 usb_apb_clk_en        : 1 ;
	hi_uint32 i2s1_clk_en           : 1 ;
	hi_uint32 codec_clk_en          : 1 ;
	hi_uint32 resv_2                : 1 ;
};

struct hi_sec_reg_crg_dio_sc_per_clk_dis1_s {
	hi_uint32  ui_dp_clk_dis                      : 1 ; /*[0:0]*/
	hi_uint32  ui_pfe_clk_dis                     : 1 ; /*[1:1]*/
	hi_uint32  ui_resv_0                          : 1 ; /*[2:2]*/
	hi_uint32  ui_mdio0_clk_dis                   : 1 ; /*[3:3]*/
	hi_uint32  ui_mdio1_clk_dis                   : 1 ; /*[4:4]*/
	hi_uint32  ui_pcs_clk_dis                     : 1 ; /*[5:5]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[6:6]*/
	hi_uint32  ui_pke_clk_dis                     : 1 ; /*[7:7]*/
	hi_uint32  ui_sa_clk_dis                      : 1 ; /*[8:8]*/
	hi_uint32  ui_sec_clk_dis                     : 1 ; /*[9:9]*/
	hi_uint32  ui_gic_clk_dis                     : 1 ; /*[10:10]*/
	hi_uint32  ui_dma_clk_dis                     : 1 ; /*[11:11]*/
	hi_uint32  ui_pcie0_clk_dis                   : 1 ; /*[12:12]*/
	hi_uint32  ui_pcie1_clk_dis                   : 1 ; /*[13:13]*/
	hi_uint32  ui_pcie2_clk_dis                   : 1 ; /*[14:14]*/
	hi_uint32  ui_port0_usb2_phy_clk_dis          : 1 ; /*[15:15]*/
	hi_uint32  ui_usb_ctrl_clk_dis                : 1 ; /*[16:16]*/
	hi_uint32  ui_port0_usb3_phy_clk_dis          : 1 ; /*[17:17]*/
	hi_uint32  ui_sata_phy_clk_dis                : 1 ; /*[18:18]*/
	hi_uint32  ui_gemac0_clk_dis                  : 1 ; /*[19:19]*/
	hi_uint32  ui_gemac1_clk_dis                  : 1 ; /*[20:20]*/
	hi_uint32  ui_gemac2_clk_dis                  : 1 ; /*[21:21]*/
	hi_uint32  ui_gemac3_clk_dis                  : 1 ; /*[22:22]*/
	hi_uint32  ui_gemac4_clk_dis                  : 1 ; /*[23:23]*/
	hi_uint32  ui_gemac5_clk_dis                  : 1 ; /*[24:24]*/
	hi_uint32  ui_pie_clk_dis                     : 1 ; /*[25:25]*/
	hi_uint32  ui_sdio_clk_dis                    : 1 ; /*[26:26]*/
	hi_uint32  ui_i2s0_clk_dis                    : 1 ; /*[27:27]*/
	hi_uint32  ui_usb_apb_clk_dis                 : 1 ; /*[28:28]*/
	hi_uint32  ui_i2s1_clk_dis                    : 1 ; /*[29:29]*/
	hi_uint32  ui_codec_clk_dis                   : 1 ; /*[30:30]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[31:31]*/
};

struct hi_sec_reg_crg_dio_sc_per_clk_st1_s {
	hi_uint32  ui_dp_clk_stat                     : 1 ; /*[0:0]*/
	hi_uint32  ui_pfe_clk_stat                    : 1 ; /*[1:1]*/
	hi_uint32  ui_resv_0                          : 1 ; /*[2:2]*/
	hi_uint32  ui_mdio0_clk_stat                  : 1 ; /*[3:3]*/
	hi_uint32  ui_mdio1_clk_stat                  : 1 ; /*[4:4]*/
	hi_uint32  ui_pcs_clk_stat                    : 1 ; /*[5:5]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[6:6]*/
	hi_uint32  ui_pke_clk_stat                    : 1 ; /*[7:7]*/
	hi_uint32  ui_sa_clk_stat                     : 1 ; /*[8:8]*/
	hi_uint32  ui_sec_clk_stat                    : 1 ; /*[9:9]*/
	hi_uint32  ui_gic_clk_stat                    : 1 ; /*[10:10]*/
	hi_uint32  ui_dma_clk_stat                    : 1 ; /*[11:11]*/
	hi_uint32  ui_pcie0_clk_stat                  : 1 ; /*[12:12]*/
	hi_uint32  ui_pcie1_clk_stat                  : 1 ; /*[13:13]*/
	hi_uint32  ui_pcie2_clk_stat                  : 1 ; /*[14:14]*/
	hi_uint32  ui_port0_usb2_phy_clk_stat         : 1 ; /*[15:15]*/
	hi_uint32  ui_usb_ctrl_clk_stat               : 1 ; /*[16:16]*/
	hi_uint32  ui_port0_usb3_phy_clk_stat         : 1 ; /*[17:17]*/
	hi_uint32  ui_sata_phy_clk_stat               : 1 ; /*[18:18]*/
	hi_uint32  ui_gemac0_clk_stat                 : 1 ; /*[19:19]*/
	hi_uint32  ui_gemac1_clk_stat                 : 1 ; /*[20:20]*/
	hi_uint32  ui_gemac2_clk_stat                 : 1 ; /*[21:21]*/
	hi_uint32  ui_gemac3_clk_stat                 : 1 ; /*[22:22]*/
	hi_uint32  ui_gemac4_clk_stat                 : 1 ; /*[23:23]*/
	hi_uint32  ui_gemac5_clk_stat                 : 1 ; /*[24:24]*/
	hi_uint32  ui_pie_clk_stat                    : 1 ; /*[25:25]*/
	hi_uint32  ui_sdio_clk_stat                   : 1 ; /*[26:26]*/
	hi_uint32  ui_i2s0_clk_stat                   : 1 ; /*[27:27]*/
	hi_uint32  ui_usb_apb_clk_stat                : 1 ; /*[28:28]*/
	hi_uint32  ui_i2s1_clk_stat                   : 1 ; /*[29:29]*/
	hi_uint32  ui_codec_clk_stat                  : 1 ; /*[30:30]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[31:31]*/
};

struct hi_sec_reg_crg_dio_sc_rst_ctrl0_s {
	hi_uint32  ui_fmc_srst_n                      : 1 ; /*[0:0]*/
	hi_uint32  ui_ec_srst_n                       : 1 ; /*[1:1]*/
	hi_uint32  ui_hw_logic_srst_n                 : 1 ; /*[2:2]*/
	hi_uint32  ui_hw_srst_n                       : 1 ; /*[3:3]*/
	hi_uint32  ui_resv_0                          : 4 ; /*[4:7]*/
	hi_uint32  ui_spi0_srst_n                     : 1 ; /*[8:8]*/
	hi_uint32  ui_spi1_srst_n                     : 1 ; /*[9:9]*/
	hi_uint32  ui_uart0_srst_n                    : 1 ; /*[10:10]*/
	hi_uint32  ui_uart1_srst_n                    : 1 ; /*[11:11]*/
	hi_uint32  ui_uart2_srst_n                    : 1 ; /*[12:12]*/
	hi_uint32  ui_uart3_srst_n                    : 1 ; /*[13:13]*/
	hi_uint32  ui_led_srst_n                      : 1 ; /*[14:14]*/
	hi_uint32  ui_resv_1                          : 5 ; /*[15:19]*/
	hi_uint32  ui_gpio0_srst_n                    : 1 ; /*[20:20]*/
	hi_uint32  ui_gpio1_srst_n                    : 1 ; /*[21:21]*/
	hi_uint32  ui_gpio2_srst_n                    : 1 ; /*[22:22]*/
	hi_uint32  ui_gpio3_srst_n                    : 1 ; /*[23:23]*/
	hi_uint32  ui_i2c0_srst_n                     : 1 ; /*[24:24]*/
	hi_uint32  ui_i2c1_srst_n                     : 1 ; /*[25:25]*/
	hi_uint32  ui_resv_2                          : 2 ; /*[26:27]*/
	hi_uint32  ui_tzpc_srst_n                     : 1 ; /*[28:28]*/
	hi_uint32  ui_resv_3                          : 3 ; /*[29:31]*/
};

struct hi_sec_reg_crg_dio_sc_rst_ctrl1_s {
	hi_uint32  ui_dp_logic_srst_n                 : 1 ; /*[0:0]*/
	hi_uint32  ui_dp_srst_n                       : 1 ; /*[1:1]*/
	hi_uint32  ui_pcs_logic_srst_n                : 1 ; /*[2:2]*/
	hi_uint32  ui_pfe_logic_srst_n                : 1 ; /*[3:3]*/
	hi_uint32  ui_pfe_srst_n                      : 1 ; /*[4:4]*/
	hi_uint32  ui_pcs_srst_n                      : 1 ; /*[5:5]*/
	hi_uint32  ui_mdio0_srst_n                    : 1 ; /*[6:6]*/
	hi_uint32  ui_mdio1_srst_n                    : 1 ; /*[7:7]*/
	hi_uint32  ui_resv_0                          : 4 ; /*[8:11]*/
	hi_uint32  ui_dma_srst_n                      : 1 ; /*[12:12]*/
	hi_uint32  ui_gemac0_logic_srst_n             : 1 ; /*[13:13]*/
	hi_uint32  ui_gemac0_srst_n                   : 1 ; /*[14:14]*/
	hi_uint32  ui_gemac1_logic_srst_n             : 1 ; /*[15:15]*/
	hi_uint32  ui_gemac1_srst_n                   : 1 ; /*[16:16]*/
	hi_uint32  ui_gemac2_logic_srst_n             : 1 ; /*[17:17]*/
	hi_uint32  ui_gemac2_srst_n                   : 1 ; /*[18:18]*/
	hi_uint32  ui_gemac3_logic_srst_n             : 1 ; /*[19:19]*/
	hi_uint32  ui_gemac3_srst_n                   : 1 ; /*[20:20]*/
	hi_uint32  ui_gemac4_logic_srst_n             : 1 ; /*[21:21]*/
	hi_uint32  ui_gemac4_srst_n                   : 1 ; /*[22:22]*/
	hi_uint32  ui_gemac5_logic_srst_n             : 1 ; /*[23:23]*/
	hi_uint32  ui_gemac5_srst_n                   : 1 ; /*[24:24]*/
	hi_uint32  ui_pie_srst_n                      : 1 ; /*[25:25]*/
	hi_uint32  ui_gephy_srst_n                    : 1 ; /*[26:26]*/
	hi_uint32  ui_gephy_p0_srst_n                 : 1 ; /*[27:27]*/
	hi_uint32  ui_gephy_p1_srst_n                 : 1 ; /*[28:28]*/
	hi_uint32  ui_gephy_p2_srst_n                 : 1 ; /*[29:29]*/
	hi_uint32  ui_i2s0_srst_n                     : 1 ; /*[30:30]*/
	hi_uint32  ui_i2s1_srst_n                     : 1 ; /*[31:31]*/
};

struct hi_sec_reg_crg_dio_sc_rst_ctrl2_s {
	hi_uint32  ui_efuse_srst_n                    : 1 ; /*[0:0]*/
	hi_uint32  ui_c2j_srst_n                      : 1 ; /*[1:1]*/
	hi_uint32  ui_sdio_srst_n                     : 1 ; /*[2:2]*/
	hi_uint32  ui_rgmii0_div_srst_n               : 1 ; /*[3:3]*/
	hi_uint32  ui_rgmii1_div_srst_n               : 1 ; /*[4:4]*/
	hi_uint32  ui_rgmii2_div_srst_n               : 1 ; /*[5:5]*/
	hi_uint32  ui_sds_tx0_srst_n                  : 1 ; /*[6:6]*/
	hi_uint32  ui_sds_rx0_srst_n                  : 1 ; /*[7:7]*/
	hi_uint32  ui_sds_phy_srst_n                  : 1 ; /*[8:8]*/
	hi_uint32  ui_avs_srst_n                      : 1 ; /*[9:9]*/
	hi_uint32  ui_sata_cfg_srst_n                 : 1 ; /*[10:10]*/
	hi_uint32  ui_apb_usb_srst_n                  : 1 ; /*[11:11]*/
	hi_uint32  ui_apb_pcie0_srst_n                : 1 ; /*[12:12]*/
	hi_uint32  ui_pcie0_pcs_srst_n                : 1 ; /*[13:13]*/
	hi_uint32  ui_pcie0_phy_srst_n                : 1 ; /*[14:14]*/
	hi_uint32  ui_pcie0_srst_n                    : 1 ; /*[15:15]*/
	hi_uint32  ui_apb_pcie1_srst_n                : 1 ; /*[16:16]*/
	hi_uint32  ui_pcie1_pcs_srst_n                : 1 ; /*[17:17]*/
	hi_uint32  ui_pcie1_phy_srst_n                : 1 ; /*[18:18]*/
	hi_uint32  ui_pcie1_srst_n                    : 1 ; /*[19:19]*/
	hi_uint32  ui_apb_pcie2_srst_n                : 1 ; /*[20:20]*/
	hi_uint32  ui_pcie2_pcs_srst_n                : 1 ; /*[21:21]*/
	hi_uint32  ui_pcie2_phy_srst_n                : 1 ; /*[22:22]*/
	hi_uint32  ui_pcie2_srst_n                    : 1 ; /*[23:23]*/
	hi_uint32  ui_usb_ctrl_srst_n                 : 1 ; /*[24:24]*/
	hi_uint32  ui_usb2_phy0_por_srst_n            : 1 ; /*[25:25]*/
	hi_uint32  ui_usb2_phy0_port_srst_n           : 1 ; /*[26:26]*/
	hi_uint32  ui_sata_phy_srst_n                 : 1 ; /*[27:27]*/
	hi_uint32  ui_sata_port_srst_n                : 1 ; /*[28:28]*/
	hi_uint32  ui_sata_srst_n                     : 1 ; /*[29:29]*/
	hi_uint32  ui_usb3_phy_srst_n                 : 1 ; /*[30:30]*/
	hi_uint32  ui_usb3_port_srst_n                : 1 ; /*[31:31]*/
};

struct hi_sec_reg_crg_dio_cpu_cfg_s {
	hi_uint32  ui_a53crg_pclkdbg_to_cs_clkoff_sys : 1 ; /*[0:0]*/
	hi_uint32  ui_a53crg_pclkdbg_to_a53_asyn_bri_clkoff_sys: 1 ; /*[1:1]*/
	hi_uint32  ui_a53crg_aclkenm_sel              : 3 ; /*[2:4]*/
	hi_uint32  ui_a53crg_core_por_rst_req         : 4 ; /*[5:8]*/
	hi_uint32  ui_a53crg_rst_software_req         : 1 ; /*[9:9]*/
	hi_uint32  ui_a53crg_rst_software_nol2_req    : 1 ; /*[10:10]*/
	hi_uint32  ui_a53crg_core_rst_software_req    : 4 ; /*[11:14]*/
	hi_uint32  ui_a53crg_coresight_soft_rst_req   : 1 ; /*[15:15]*/
	hi_uint32  ui_a53crg_npresetdbg_rst_req       : 1 ; /*[16:16]*/
	hi_uint32  ui_resv_0                          : 1 ; /*[17:17]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[18:18]*/
	hi_uint32  ui_resv_2                          : 13; /*[19:31]*/
};

struct hi_sec_reg_crg_dio_hw_cfg_s {
	hi_uint32  ui_hw_zsi_sel                      : 1 ; /*[0:0]*/
	hi_uint32  ui_hwclk_freq_sel                  : 3 ; /*[1:3]*/
	hi_uint32  ui_hw_clk_sel                      : 1 ; /*[4:4]*/
	hi_uint32  ui_resv_0                          : 1 ; /*[5:5]*/
	hi_uint32  ui_hw_tdmtx_sel                    : 1 ; /*[6:6]*/
	hi_uint32  ui_hw_tdmrx_sel                    : 1 ; /*[7:7]*/
	hi_uint32  ui_hw_fs_sel                       : 1 ; /*[8:8]*/
	hi_uint32  ui_hw_sync_oen                     : 1 ; /*[9:9]*/
	hi_uint32  ui_hw_clk_oen                      : 1 ; /*[10:10]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[11:11]*/
	hi_uint32  ui_hw_isi_sel                      : 1 ; /*[12:12]*/
	hi_uint32  ui_ec_clk_elim_num                 : 4 ; /*[13:16]*/
	hi_uint32  ui_resv_2                          : 15; /*[17:31]*/
};

struct hi_sec_reg_crg_dio_wifi_cfg_s {
	hi_uint32  ui_wifi0_clk_ctrl                  : 3 ; /*[0:2]*/
	hi_uint32  ui_resv_0                          : 1 ; /*[3:3]*/
	hi_uint32  ui_pcie0_clk_ctrl                  : 3 ; /*[4:6]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[7:7]*/
	hi_uint32  ui_wifi1_clk_ctrl                  : 3 ; /*[8:10]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[11:11]*/
	hi_uint32  ui_pcie1_clk_ctrl                  : 3 ; /*[12:14]*/
	hi_uint32  ui_resv_3                          : 1 ; /*[15:15]*/
	hi_uint32  ui_wifi2_clk_ctrl                  : 3 ; /*[16:18]*/
	hi_uint32  ui_resv_4                          : 1 ; /*[19:19]*/
	hi_uint32  ui_pcie2_clk_ctrl                  : 3 ; /*[20:22]*/
	hi_uint32  ui_resv_5                          : 9 ; /*[23:31]*/
};

struct hi_sec_reg_crg_dio_usb_cfg_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_sc_perctrl2_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_clk_freq_cfg_s {
	hi_uint32  ui_fmc_freq_sel                    : 2 ; /*[0:1]*/
	hi_uint32  ui_axi_freq_sel                    : 1 ; /*[2:2]*/
	hi_uint32  ui_c2j_clk_freq_sel                : 2 ; /*[3:4]*/
	hi_uint32  ui_hs_uart_clk_src_freq_sel        : 1 ; /*[5:5]*/
	hi_uint32  ui_ec_freq_sel                     : 1 ; /*[6:6]*/
	hi_uint32  ui_ts_freq_sel                     : 1 ; /*[7:7]*/
	hi_uint32  ui_resv_0                          : 24; /*[8:31]*/
};

struct hi_sec_reg_crg_dio_sc_perctrl4_s {
	hi_uint32  ui_resv_0                          : 10; /*[0:9]*/
	hi_uint32  ui_wdg_rst_time_cfg                : 9 ; /*[10:18]*/
	hi_uint32  ui_resv_1                          : 9 ; /*[19:27]*/
	hi_uint32  ui_wdg_rst_dly_cfg                 : 2 ; /*[28:29]*/
	hi_uint32  ui_resv_2                          : 2 ; /*[30:31]*/
};

struct hi_sec_reg_crg_dio_sc_perctrl5_s {
	hi_uint32  ui_rst_fast_sim                    : 1 ; /*[0:0]*/
	hi_uint32  ui_resv_0                          : 3 ; /*[1:3]*/
	hi_uint32  ui_wifi0_clkreq_filter_en          : 1 ; /*[4:4]*/
	hi_uint32  ui_wifi1_clkreq_filter_en          : 1 ; /*[5:5]*/
	hi_uint32  ui_wifi2_clkreq_filter_en          : 1 ; /*[6:6]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[7:7]*/
	hi_uint32  ui_lsw_lrdxmd_rstack               : 1 ; /*[8:8]*/
	hi_uint32  ui_lsw_lrdxmd_rstreq               : 1 ; /*[9:9]*/
	hi_uint32  ui_lsw_lrdxmd_bypass               : 1 ; /*[10:10]*/
	hi_uint32  ui_tx_tbi_order                    : 1 ; /*[11:11]*/
	hi_uint32  ui_sata_phy_port_rst_sel           : 1 ; /*[12:12]*/
	hi_uint32  ui_resv_2                          : 19; /*[13:31]*/
};

struct hi_sec_reg_crg_dio_sc_perctrl6_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_sc_perctrl7_s {
	hi_uint32  ui_pfe_clk_elim_num0               : 4 ; /*[0:3]*/
	hi_uint32  ui_pfe_clk_elim_num1               : 4 ; /*[4:7]*/
	hi_uint32  ui_resv_0                          : 4 ; /*[8:11]*/
	hi_uint32  ui_resv_1                          : 4 ; /*[12:15]*/
	hi_uint32  ui_dp_clk_elim_num0                : 4 ; /*[16:19]*/
	hi_uint32  ui_dp_clk_elim_num1                : 4 ; /*[20:23]*/
	hi_uint32  ui_resv_2                          : 4 ; /*[24:27]*/
	hi_uint32  ui_resv_3                          : 4 ; /*[28:31]*/
};

struct hi_sec_reg_crg_dio_sc_perctrl8_s {
	hi_uint32  ui_wdg_en_cfg                      : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_wdg_init_cfg_s {
	hi_uint32  ui_wdg_init_cfg                    : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_a9pll_ctrl0_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_a9pll_ctrl1_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_pciepll_ctrl0_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_pciepll_ctrl1_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_usr_df_cfg0_s {
	hi_uint32  ui_usr_df_cfg0                     : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_clk_det_ctrl_s {
	hi_uint32  ui_test_clk_ctrl                   : 6 ; /*[0:5]*/
	hi_uint32  ui_resv_0                          : 1 ; /*[6:6]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[7:7]*/
	hi_uint32  ui_det_clk_en                      : 1 ; /*[8:8]*/
	hi_uint32  ui_test_div_bypass                 : 1 ; /*[9:9]*/
	hi_uint32  ui_resv_2                          : 2 ; /*[10:11]*/
	hi_uint32  ui_det_period_sel                  : 3 ; /*[12:14]*/
	hi_uint32  ui_resv_3                          : 1 ; /*[15:15]*/
	hi_uint32  ui_det_num                         : 8 ; /*[16:23]*/
	hi_uint32  ui_observe_clk_sel                 : 5 ; /*[24:28]*/
	hi_uint32  ui_wifi0_observe_en                : 1 ; /*[29:29]*/
	hi_uint32  ui_resv_4                          : 2 ; /*[30:31]*/
};

struct hi_sec_reg_crg_dio_crg_stat0_s {
	hi_uint32  ui_acctl_pll_unlock_his            : 1 ; /*[0:0]*/
	hi_uint32  ui_dxctl0_pll_unlock_his           : 1 ; /*[1:1]*/
	hi_uint32  ui_dxctl1_pll_unlock_his           : 1 ; /*[2:2]*/
	hi_uint32  ui_acctl_pll_lock                  : 1 ; /*[3:3]*/
	hi_uint32  ui_dxctl0_pll_lock                 : 1 ; /*[4:4]*/
	hi_uint32  ui_dxctl1_pll_lock                 : 1 ; /*[5:5]*/
	hi_uint32  ui_resv_0                          : 6 ; /*[6:11]*/
	hi_uint32  ui_safe_hard_reset_type            : 2 ; /*[12:13]*/
	hi_uint32  ui_hard_reset_type                 : 2 ; /*[14:15]*/
	hi_uint32  ui_hw_msif_unlock_his              : 1 ; /*[16:16]*/
	hi_uint32  ui_hw_msif_lock                    : 1 ; /*[17:17]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[18:18]*/
	hi_uint32  ui_gephy_pll_unlock_his            : 1 ; /*[19:19]*/
	hi_uint32  ui_comb_pll_unlock_his             : 1 ; /*[20:20]*/
	hi_uint32  ui_lsw_pll_unlock_his              : 1 ; /*[21:21]*/
	hi_uint32  ui_hw_pll_unlock_his               : 1 ; /*[22:22]*/
	hi_uint32  ui_ddr_pll_unlock_his              : 1 ; /*[23:23]*/
	hi_uint32  ui_cpu_pll_unlock_his              : 1 ; /*[24:24]*/
	hi_uint32  ui_gephy_pll_lock                  : 1 ; /*[25:25]*/
	hi_uint32  ui_comb_pll_lock                   : 1 ; /*[26:26]*/
	hi_uint32  ui_lsw_pll_lock                    : 1 ; /*[27:27]*/
	hi_uint32  ui_hw_pll_lock                     : 1 ; /*[28:28]*/
	hi_uint32  ui_ddr_pll_lock                    : 1 ; /*[29:29]*/
	hi_uint32  ui_cpu_pll_lock                    : 1 ; /*[30:30]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[31:31]*/
};

struct hi_sec_reg_crg_dio_crg_stat1_s {
	hi_uint32  ui_clk_min_freq                    : 12; /*[0:11]*/
	hi_uint32  ui_clk_max_freq                    : 12; /*[12:23]*/
	hi_uint32  ui_freq_out_en                     : 1 ; /*[24:24]*/
	hi_uint32  ui_det_clk_los                     : 1 ; /*[25:25]*/
	hi_uint32  ui_resv_0                          : 6 ; /*[26:31]*/
};

struct hi_sec_reg_crg_dio_pll_lock_filter_en_s {
	hi_uint32  ui_resv_0                          : 1 ; /*[0:0]*/
	hi_uint32  ui_combpll_lock_filter_en          : 1 ; /*[1:1]*/
	hi_uint32  ui_lswpll_lock_filter_en           : 1 ; /*[2:2]*/
	hi_uint32  ui_hwpll_lock_filter_en            : 1 ; /*[3:3]*/
	hi_uint32  ui_ddrpll_lock_filter_en           : 1 ; /*[4:4]*/
	hi_uint32  ui_cpupll_lock_filter_en           : 1 ; /*[5:5]*/
	hi_uint32  ui_gephypll_lock_filter_en         : 1 ; /*[6:6]*/
	hi_uint32  ui_acctlpll_lock_filter_en         : 1 ; /*[7:7]*/
	hi_uint32  ui_dxctl0pll_lock_filter_en        : 1 ; /*[8:8]*/
	hi_uint32  ui_dxctl1pll_lock_filter_en        : 1 ; /*[9:9]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[10:10]*/
	hi_uint32  ui_resv_2                          : 21; /*[11:31]*/
};

struct hi_sec_reg_crg_dio_pd_reset_ctrl_s {
	hi_uint32  ui_pd_reset_en                     : 1 ; /*[0:0]*/
	hi_uint32  ui_resv_0                          : 3 ; /*[1:3]*/
	hi_uint32  ui_pd_reset_dly_time               : 12; /*[4:15]*/
	hi_uint32  ui_resv_1                          : 16; /*[16:31]*/
};

struct hi_sec_reg_crg_dio_ram_ctrl0_s {
	hi_uint32  ui_lsw_ctrl_bus                    : 10; /*[0:9]*/
	hi_uint32  ui_resv_0                          : 6 ; /*[10:15]*/
	hi_uint32  ui_dp_shape_ctrl_bus               : 10; /*[16:25]*/
	hi_uint32  ui_resv_1                          : 6 ; /*[26:31]*/
};

struct hi_sec_reg_crg_dio_ram_ctrl1_s {
	hi_uint32  ui_iomux_ctrl_bus                  : 10; /*[0:9]*/
	hi_uint32  ui_resv_0                          : 6 ; /*[10:15]*/
	hi_uint32  ui_itf_ctrl_bus                    : 10; /*[16:25]*/
	hi_uint32  ui_resv_1                          : 6 ; /*[26:31]*/
};

struct hi_sec_reg_crg_dio_ram_ctrl2_s {
	hi_uint32  ui_ecs_peri_ctrl_bus               : 10; /*[0:9]*/
	hi_uint32  ui_resv_0                          : 6 ; /*[10:15]*/
	hi_uint32  ui_ecs_rom_ctrl_bus                : 4 ; /*[16:19]*/
	hi_uint32  ui_resv_1                          : 12; /*[20:31]*/
};

struct hi_sec_reg_crg_dio_ram_ctrl3_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_gemac0_rgmii_ctrl_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_gemac1_rgmii_ctrl_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_gemac2_rgmii_ctrl_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_gemac3_rgmii_ctrl_s {
	hi_uint32  ui_rgmii0_tx_tune                  : 2 ; /*[0:1]*/
	hi_uint32  ui_resv_0                          : 2 ; /*[2:3]*/
	hi_uint32  ui_rgmii0_tx_tune_frac             : 3 ; /*[4:6]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[7:7]*/
	hi_uint32  ui_rgmii0_rx_tune                  : 4 ; /*[8:11]*/
	hi_uint32  ui_rgmii0_rxc_inv_sel              : 1 ; /*[12:12]*/
	hi_uint32  ui_rgmii0_rx_shift_src_sel         : 1 ; /*[13:13]*/
	hi_uint32  ui_rgmii0_cf_speed                 : 2 ; /*[14:15]*/
	hi_uint32  ui_rgmii0_cf_duplex                : 1 ; /*[16:16]*/
	hi_uint32  ui_rgmii0_cf_en                    : 1 ; /*[17:17]*/
	hi_uint32  ui_rgmii0_cf_rx_seq_sel            : 2 ; /*[18:19]*/
	hi_uint32  ui_rgmii0_cf_tx_seq_sel            : 2 ; /*[20:21]*/
	hi_uint32  ui_resv_2                          : 2 ; /*[22:23]*/
	hi_uint32  ui_rgmii0_fixed_dly_tune_sel       : 1 ; /*[24:24]*/
	hi_uint32  ui_rgmii0_rx_fixed_dly_tune        : 4 ; /*[25:28]*/
	hi_uint32  ui_resv_3                          : 3 ; /*[29:31]*/
};

struct hi_sec_reg_crg_dio_gemac4_rgmii_ctrl_s {
	hi_uint32  ui_rgmii1_tx_tune                  : 2 ; /*[0:1]*/
	hi_uint32  ui_resv_0                          : 2 ; /*[2:3]*/
	hi_uint32  ui_rgmii1_tx_tune_frac             : 3 ; /*[4:6]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[7:7]*/
	hi_uint32  ui_rgmii1_rx_tune                  : 4 ; /*[8:11]*/
	hi_uint32  ui_rgmii1_rxc_inv_sel              : 1 ; /*[12:12]*/
	hi_uint32  ui_rgmii1_rx_shift_src_sel         : 1 ; /*[13:13]*/
	hi_uint32  ui_rgmii1_cf_speed                 : 2 ; /*[14:15]*/
	hi_uint32  ui_rgmii1_cf_duplex                : 1 ; /*[16:16]*/
	hi_uint32  ui_rgmii1_cf_en                    : 1 ; /*[17:17]*/
	hi_uint32  ui_rgmii1_cf_rx_seq_sel            : 2 ; /*[18:19]*/
	hi_uint32  ui_rgmii1_cf_tx_seq_sel            : 2 ; /*[20:21]*/
	hi_uint32  ui_resv_2                          : 2 ; /*[22:23]*/
	hi_uint32  ui_rgmii1_fixed_dly_tune_sel       : 1 ; /*[24:24]*/
	hi_uint32  ui_rgmii1_rx_fixed_dly_tune        : 4 ; /*[25:28]*/
	hi_uint32  ui_resv_3                          : 3 ; /*[29:31]*/
};

struct hi_sec_reg_crg_dio_gemac5_rgmii_ctrl_s {
	hi_uint32  ui_rgmii2_tx_tune                  : 2 ; /*[0:1]*/
	hi_uint32  ui_resv_0                          : 2 ; /*[2:3]*/
	hi_uint32  ui_rgmii2_tx_tune_frac             : 3 ; /*[4:6]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[7:7]*/
	hi_uint32  ui_rgmii2_rx_tune                  : 4 ; /*[8:11]*/
	hi_uint32  ui_rgmii2_rxc_inv_sel              : 1 ; /*[12:12]*/
	hi_uint32  ui_rgmii2_rx_shift_src_sel         : 1 ; /*[13:13]*/
	hi_uint32  ui_rgmii2_cf_speed                 : 2 ; /*[14:15]*/
	hi_uint32  ui_rgmii2_cf_duplex                : 1 ; /*[16:16]*/
	hi_uint32  ui_rgmii2_cf_en                    : 1 ; /*[17:17]*/
	hi_uint32  ui_rgmii2_cf_rx_seq_sel            : 2 ; /*[18:19]*/
	hi_uint32  ui_rgmii2_cf_tx_seq_sel            : 2 ; /*[20:21]*/
	hi_uint32  ui_resv_2                          : 2 ; /*[22:23]*/
	hi_uint32  ui_rgmii2_fixed_dly_tune_sel       : 1 ; /*[24:24]*/
	hi_uint32  ui_rgmii2_rx_fixed_dly_tune        : 4 ; /*[25:28]*/
	hi_uint32  ui_resv_3                          : 3 ; /*[29:31]*/
};

struct hi_sec_reg_crg_dio_a9_pll_afs_ctrl_s {
	hi_uint32  ui_resv_0                          : 5 ; /*[0:4]*/
	hi_uint32  ui_resv_1                          : 3 ; /*[5:7]*/
	hi_uint32  ui_resv_2                          : 5 ; /*[8:12]*/
	hi_uint32  ui_resv_3                          : 3 ; /*[13:15]*/
	hi_uint32  ui_resv_4                          : 1 ; /*[16:16]*/
	hi_uint32  ui_resv_5                          : 3 ; /*[17:19]*/
	hi_uint32  ui_resv_6                          : 1 ; /*[20:20]*/
	hi_uint32  ui_resv_7                          : 3 ; /*[21:23]*/
	hi_uint32  ui_resv_8                          : 1 ; /*[24:24]*/
	hi_uint32  ui_resv_9                          : 1 ; /*[25:25]*/
	hi_uint32  ui_resv_10                         : 1 ; /*[26:26]*/
	hi_uint32  ui_resv_11                         : 1 ; /*[27:27]*/
	hi_uint32  ui_resv_12                         : 1 ; /*[28:28]*/
	hi_uint32  ui_resv_13                         : 3 ; /*[29:31]*/
};

struct hi_sec_reg_crg_dio_pcie_ref_div_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_ptp_8k_ftw_s {
	hi_uint32  ui_resv_0                          : 10; /*[0:9]*/
	hi_uint32  ui_resv_1                          : 2 ; /*[10:11]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[12:12]*/
	hi_uint32  ui_resv_3                          : 3 ; /*[13:15]*/
	hi_uint32  ui_resv_4                          : 1 ; /*[16:16]*/
	hi_uint32  ui_resv_5                          : 15; /*[17:31]*/
};

struct hi_sec_reg_crg_dio_ptp_8k_max_s {
	hi_uint32  ui_resv_0                          : 24; /*[0:23]*/
	hi_uint32  ui_resv_1                          : 8 ; /*[24:31]*/
};

struct hi_sec_reg_crg_dio_clk_shut_sel_s {
	hi_uint32  ui_resv_0                          : 3 ; /*[0:2]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[3:3]*/
	hi_uint32  ui_resv_2                          : 3 ; /*[4:6]*/
	hi_uint32  ui_resv_3                          : 1 ; /*[7:7]*/
	hi_uint32  ui_resv_4                          : 1 ; /*[8:8]*/
	hi_uint32  ui_resv_5                          : 23; /*[9:31]*/
};

struct hi_sec_reg_crg_dio_crg_int_status_s {
	hi_uint32  ui_wdg_time_out_int                : 1 ; /*[0:0]*/
	hi_uint32  ui_resv_0                          : 31; /*[1:31]*/
};

struct hi_sec_reg_crg_dio_crg_int_mask_s {
	hi_uint32  ui_wdg_time_out_int_mask           : 1 ; /*[0:0]*/
	hi_uint32  ui_resv_0                          : 31; /*[1:31]*/
};

struct hi_sec_reg_crg_dio_crg_int_set_s {
	hi_uint32  ui_wdg_time_out_int_set            : 1 ; /*[0:0]*/
	hi_uint32  ui_resv_0                          : 31; /*[1:31]*/
};

struct hi_sec_reg_crg_dio_nni_mode_s {
	hi_uint32  ui_gemac5_mode                     : 2 ; /*[0:1]*/
	hi_uint32  ui_combophy_mode_sel               : 2 ; /*[2:3]*/
	hi_uint32  ui_resv_0                          : 28; /*[4:31]*/
};

struct hi_sec_reg_crg_dio_uni_mode_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_pon_pri_mode_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_sata_mode_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_i2s0_cfg0_s {
	hi_uint32  ui_i2s0_clk_div_ftw                : 12; /*[0:11]*/
	hi_uint32  ui_resv_0                          : 4 ; /*[12:15]*/
	hi_uint32  ui_i2s0_sample_width_sel           : 3 ; /*[16:18]*/
	hi_uint32  ui_resv_1                          : 5 ; /*[19:23]*/
	hi_uint32  ui_i2s0_clk_oen                    : 1 ; /*[24:24]*/
	hi_uint32  ui_resv_2                          : 3 ; /*[25:27]*/
	hi_uint32  ui_i2s0_clk_sel                    : 1 ; /*[28:28]*/
	hi_uint32  ui_resv_3                          : 3 ; /*[29:31]*/
};

struct hi_sec_reg_crg_dio_i2s0_cfg1_s {
	hi_uint32  ui_i2s0_clk_div_max                : 24; /*[0:23]*/
	hi_uint32  ui_resv_0                          : 8 ; /*[24:31]*/
};

struct hi_sec_reg_crg_dio_emmc_cfg_s {
	hi_uint32  ui_sdio_clk_sample_phase_shift_ctrl: 5 ; /*[0:4]*/
	hi_uint32  ui_resv_0                          : 3 ; /*[5:7]*/
	hi_uint32  ui_sdio_clk_drv_phase_shift_ctrl   : 5 ; /*[8:12]*/
	hi_uint32  ui_resv_1                          : 3 ; /*[13:15]*/
	hi_uint32  ui_sdio_clk_freq_sel               : 2 ; /*[16:17]*/
	hi_uint32  ui_resv_2                          : 14; /*[18:31]*/
};

struct hi_sec_reg_crg_dio_clk_pll_src_sel_s {
	hi_uint32  ui_resv_0                          : 3 ; /*[0:2]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[3:3]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[4:4]*/
	hi_uint32  ui_resv_3                          : 3 ; /*[5:7]*/
	hi_uint32  ui_resv_4                          : 3 ; /*[8:10]*/
	hi_uint32  ui_resv_5                          : 1 ; /*[11:11]*/
	hi_uint32  ui_resv_6                          : 2 ; /*[12:13]*/
	hi_uint32  ui_resv_7                          : 2 ; /*[14:15]*/
	hi_uint32  ui_resv_8                          : 1 ; /*[16:16]*/
	hi_uint32  ui_resv_9                          : 3 ; /*[17:19]*/
	hi_uint32  ui_resv_10                         : 2 ; /*[20:21]*/
	hi_uint32  ui_resv_11                         : 10; /*[22:31]*/
};

struct hi_sec_reg_crg_dio_clk_other_src_sel_s {
	hi_uint32  ui_resv_0                          : 1 ; /*[0:0]*/
	hi_uint32  ui_func_dieid_clk_sel              : 1 ; /*[1:1]*/
	hi_uint32  ui_func_dieid_clk_sel_ctrl         : 1 ; /*[2:2]*/
	hi_uint32  ui_cpu_clk_sel                     : 1 ; /*[3:3]*/
	hi_uint32  ui_xtal_clk_sel                    : 1 ; /*[4:4]*/
	hi_uint32  ui_spi0_clk_src_sel                : 1 ; /*[5:5]*/
	hi_uint32  ui_spi1_clk_src_sel                : 1 ; /*[6:6]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[7:7]*/
	hi_uint32  ui_pcie0_phy_refclk_sel            : 1 ; /*[8:8]*/
	hi_uint32  ui_pcie1_phy_refclk_sel            : 1 ; /*[9:9]*/
	hi_uint32  ui_pcie2_phy_refclk_sel            : 1 ; /*[10:10]*/
	hi_uint32  ui_comb0_refclk_sel                : 1 ; /*[11:11]*/
	hi_uint32  ui_comb1_refclk_sel                : 1 ; /*[12:12]*/
	hi_uint32  ui_usb2_refclk_sel                 : 1 ; /*[13:13]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[14:14]*/
	hi_uint32  ui_cmos_clock_sel_i                : 1 ; /*[15:15]*/
	hi_uint32  ui_ext_phy_refclk_sel              : 1 ; /*[16:16]*/
	hi_uint32  ui_gephy_refclk_sel                : 1 ; /*[17:17]*/
	hi_uint32  ui_ddr_clk_src_sel                 : 1 ; /*[18:18]*/
	hi_uint32  ui_ddr_div_clk_sel                 : 1 ; /*[19:19]*/
	hi_uint32  ui_hw_clk_49m_src_sel              : 1 ; /*[20:20]*/
	hi_uint32  ui_resv_3                          : 11; /*[21:31]*/
};

struct hi_sec_reg_crg_dio_cmu_trace_div_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_cmu_ctrl0_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_cmu_ctrl1_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_pon_sds_ctrl0_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_pon_sds_ctrl1_s {
	hi_uint32  ui_resv_0                          : 4 ; /*[0:3]*/
	hi_uint32  ui_resv_1                          : 4 ; /*[4:7]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[8:8]*/
	hi_uint32  ui_resv_3                          : 1 ; /*[9:9]*/
	hi_uint32  ui_resv_4                          : 2 ; /*[10:11]*/
	hi_uint32  ui_resv_5                          : 2 ; /*[12:13]*/
	hi_uint32  ui_resv_6                          : 2 ; /*[14:15]*/
	hi_uint32  ui_resv_7                          : 1 ; /*[16:16]*/
	hi_uint32  ui_resv_8                          : 1 ; /*[17:17]*/
	hi_uint32  ui_resv_9                          : 1 ; /*[18:18]*/
	hi_uint32  ui_resv_10                         : 1 ; /*[19:19]*/
	hi_uint32  ui_resv_11                         : 1 ; /*[20:20]*/
	hi_uint32  ui_resv_12                         : 11; /*[21:31]*/
};

struct hi_sec_reg_crg_dio_xfi_sds_ctrl0_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_xfi_sds_ctrl1_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_i2s1_cfg0_s {
	hi_uint32  ui_i2s1_clk_div_ftw                : 12; /*[0:11]*/
	hi_uint32  ui_resv_0                          : 4 ; /*[12:15]*/
	hi_uint32  ui_i2s1_sample_width_sel           : 3 ; /*[16:18]*/
	hi_uint32  ui_resv_1                          : 5 ; /*[19:23]*/
	hi_uint32  ui_i2s1_clk_oen                    : 1 ; /*[24:24]*/
	hi_uint32  ui_resv_2                          : 3 ; /*[25:27]*/
	hi_uint32  ui_i2s1_clk_sel                    : 1 ; /*[28:28]*/
	hi_uint32  ui_resv_3                          : 3 ; /*[29:31]*/
};

struct hi_sec_reg_crg_dio_i2s1_cfg1_s {
	hi_uint32  ui_i2s1_clk_div_max                : 24; /*[0:23]*/
	hi_uint32  ui_resv_0                          : 8 ; /*[24:31]*/
};

struct hi_sec_reg_crg_dio_sds_st_s {
	hi_uint32  ui_resv_0                          : 4 ; /*[0:3]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[4:4]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[5:5]*/
	hi_uint32  ui_resv_3                          : 1 ; /*[6:6]*/
	hi_uint32  ui_resv_4                          : 5 ; /*[7:11]*/
	hi_uint32  ui_resv_5                          : 1 ; /*[12:12]*/
	hi_uint32  ui_resv_6                          : 1 ; /*[13:13]*/
	hi_uint32  ui_resv_7                          : 1 ; /*[14:14]*/
	hi_uint32  ui_resv_8                          : 17; /*[15:31]*/
};

struct hi_sec_reg_crg_dio_sds_cmu_st_s {
	hi_uint32  ui_resv_0                          : 1 ; /*[0:0]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[1:1]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[2:2]*/
	hi_uint32  ui_resv_3                          : 1 ; /*[3:3]*/
	hi_uint32  ui_resv_4                          : 2 ; /*[4:5]*/
	hi_uint32  ui_resv_5                          : 2 ; /*[6:7]*/
	hi_uint32  ui_resv_6                          : 2 ; /*[8:9]*/
	hi_uint32  ui_resv_7                          : 2 ; /*[10:11]*/
	hi_uint32  ui_resv_8                          : 1 ; /*[12:12]*/
	hi_uint32  ui_resv_9                          : 1 ; /*[13:13]*/
	hi_uint32  ui_resv_10                         : 1 ; /*[14:14]*/
	hi_uint32  ui_resv_11                         : 1 ; /*[15:15]*/
	hi_uint32  ui_resv_12                         : 8 ; /*[16:23]*/
	hi_uint32  ui_resv_13                         : 1 ; /*[24:24]*/
	hi_uint32  ui_resv_14                         : 7 ; /*[25:31]*/
};

struct hi_sec_reg_crg_dio_sds_cmu_his_st_s {
	hi_uint32  ui_resv_0                          : 1 ; /*[0:0]*/
	hi_uint32  ui_resv_1                          : 1 ; /*[1:1]*/
	hi_uint32  ui_resv_2                          : 1 ; /*[2:2]*/
	hi_uint32  ui_resv_3                          : 1 ; /*[3:3]*/
	hi_uint32  ui_resv_4                          : 1 ; /*[4:4]*/
	hi_uint32  ui_resv_5                          : 1 ; /*[5:5]*/
	hi_uint32  ui_resv_6                          : 1 ; /*[6:6]*/
	hi_uint32  ui_resv_7                          : 1 ; /*[7:7]*/
	hi_uint32  ui_resv_8                          : 1 ; /*[8:8]*/
	hi_uint32  ui_resv_9                          : 3 ; /*[9:11]*/
	hi_uint32  ui_resv_10                         : 1 ; /*[12:12]*/
	hi_uint32  ui_resv_11                         : 1 ; /*[13:13]*/
	hi_uint32  ui_resv_12                         : 18; /*[14:31]*/
};

struct hi_sec_reg_crg_dio_rcd_ctrl0_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_rcd_ctrl1_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_rcd_ctrl2_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_usbpll_fbdiv_chk_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_osc_ring_ctrl_s {
	hi_uint32  ui_osc_ring_en                     : 1 ; /*[0:0]*/
	hi_uint32  ui_osc_ring_sel                    : 1 ; /*[1:1]*/
	hi_uint32  ui_resv_0                          : 30; /*[2:31]*/
};

struct hi_sec_reg_crg_dio_cpupll_fbdiv_chk_s {
	hi_uint32  ui_cpupll_fbdiv_min_his            : 12; /*[0:11]*/
	hi_uint32  ui_cpupll_fbdiv_max_his            : 12; /*[12:23]*/
	hi_uint32  ui_resv_0                          : 8 ; /*[24:31]*/
};

struct hi_sec_reg_crg_dio_ddrpll_fbdiv_chk_s {
	hi_uint32  ui_ddrpll_fbdiv_min_his            : 12; /*[0:11]*/
	hi_uint32  ui_ddrpll_fbdiv_max_his            : 12; /*[12:23]*/
	hi_uint32  ui_resv_0                          : 8 ; /*[24:31]*/
};

struct hi_sec_reg_crg_dio_hwpll_fbdiv_chk_s {
	hi_uint32  ui_hwpll_fbdiv_min_his             : 12; /*[0:11]*/
	hi_uint32  ui_hwpll_fbdiv_max_his             : 12; /*[12:23]*/
	hi_uint32  ui_resv_0                          : 8 ; /*[24:31]*/
};

struct hi_sec_reg_crg_dio_lswpll_fbdiv_chk_s {
	hi_uint32  ui_lswpll_fbdiv_min_his            : 12; /*[0:11]*/
	hi_uint32  ui_lswpll_fbdiv_max_his            : 12; /*[12:23]*/
	hi_uint32  ui_resv_0                          : 8 ; /*[24:31]*/
};

struct hi_sec_reg_crg_dio_combpll_fbdiv_chk_s {
	hi_uint32  ui_combpll_fbdiv_min_his           : 12; /*[0:11]*/
	hi_uint32  ui_combpll_fbdiv_max_his           : 12; /*[12:23]*/
	hi_uint32  ui_resv_0                          : 8 ; /*[24:31]*/
};

struct hi_sec_reg_crg_dio_cpupll_ctrl0_s {
	hi_uint32  ui_foutvcopd_cpu                   : 1 ; /*[0:0]*/
	hi_uint32  ui_foutpostdivpd_cpu               : 1 ; /*[1:1]*/
	hi_uint32  ui_fout4phasepd_cpu                : 1 ; /*[2:2]*/
	hi_uint32  ui_dsmpd_cpu                       : 1 ; /*[3:3]*/
	hi_uint32  ui_postdiv2_cpu                    : 3 ; /*[4:6]*/
	hi_uint32  ui_pd_cpu                          : 1 ; /*[7:7]*/
	hi_uint32  ui_postdiv1_cpu                    : 3 ; /*[8:10]*/
	hi_uint32  ui_dacpd_cpu                       : 1 ; /*[11:11]*/
	hi_uint32  ui_fbdiv_cpu                       : 12; /*[12:23]*/
	hi_uint32  ui_refdiv_cpu                      : 6 ; /*[24:29]*/
	hi_uint32  ui_bypass_cpu                      : 1 ; /*[30:30]*/
	hi_uint32  ui_disable_sscg_cpu                : 1 ; /*[31:31]*/
};

struct hi_sec_reg_crg_dio_cpupll_ctrl1_s {
	hi_uint32  ui_frac_cpu                        : 24; /*[0:23]*/
	hi_uint32  ui_downspread_cpu                  : 1 ; /*[24:24]*/
	hi_uint32  ui_spread_cpu                      : 3 ; /*[25:27]*/
	hi_uint32  ui_divval_cpu                      : 4 ; /*[28:31]*/
};

struct hi_sec_reg_crg_dio_cpupll_ctrl2_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_cpupll_ctrl3_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_cpupll_ctrl4_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_cpupll_ctrl5_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_ddrpll_ctrl0_s {
	hi_uint32  ui_foutvcopd_ddr                   : 1 ; /*[0:0]*/
	hi_uint32  ui_foutpostdivpd_ddr               : 1 ; /*[1:1]*/
	hi_uint32  ui_fout4phasepd_ddr                : 1 ; /*[2:2]*/
	hi_uint32  ui_dsmpd_ddr                       : 1 ; /*[3:3]*/
	hi_uint32  ui_postdiv2_ddr                    : 3 ; /*[4:6]*/
	hi_uint32  ui_pd_ddr                          : 1 ; /*[7:7]*/
	hi_uint32  ui_postdiv1_ddr                    : 3 ; /*[8:10]*/
	hi_uint32  ui_dacpd_ddr                       : 1 ; /*[11:11]*/
	hi_uint32  ui_fbdiv_ddr                       : 12; /*[12:23]*/
	hi_uint32  ui_refdiv_ddr                      : 6 ; /*[24:29]*/
	hi_uint32  ui_bypass_ddr                      : 1 ; /*[30:30]*/
	hi_uint32  ui_disable_sscg_ddr                : 1 ; /*[31:31]*/
};

struct hi_sec_reg_crg_dio_ddrpll_ctrl1_s {
	hi_uint32  ui_frac_ddr                        : 24; /*[0:23]*/
	hi_uint32  ui_downspread_ddr                  : 1 ; /*[24:24]*/
	hi_uint32  ui_spread_ddr                      : 3 ; /*[25:27]*/
	hi_uint32  ui_divval_ddr                      : 4 ; /*[28:31]*/
};

struct hi_sec_reg_crg_dio_usbpll_ctrl0_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_usbpll_ctrl1_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_hwpll_ctrl0_s {
	hi_uint32  ui_foutvcopd_hw                    : 1 ; /*[0:0]*/
	hi_uint32  ui_foutpostdivpd_hw                : 1 ; /*[1:1]*/
	hi_uint32  ui_fout4phasepd_hw                 : 1 ; /*[2:2]*/
	hi_uint32  ui_dsmpd_hw                        : 1 ; /*[3:3]*/
	hi_uint32  ui_postdiv2_hw                     : 3 ; /*[4:6]*/
	hi_uint32  ui_pd_hw                           : 1 ; /*[7:7]*/
	hi_uint32  ui_postdiv1_hw                     : 3 ; /*[8:10]*/
	hi_uint32  ui_dacpd_hw                        : 1 ; /*[11:11]*/
	hi_uint32  ui_fbdiv_hw                        : 12; /*[12:23]*/
	hi_uint32  ui_refdiv_hw                       : 6 ; /*[24:29]*/
	hi_uint32  ui_bypass_hw                       : 1 ; /*[30:30]*/
	hi_uint32  ui_disable_sscg_hw                 : 1 ; /*[31:31]*/
};

struct hi_sec_reg_crg_dio_hwpll_ctrl1_s {
	hi_uint32  ui_frac_hw                         : 24; /*[0:23]*/
	hi_uint32  ui_downspread_hw                   : 1 ; /*[24:24]*/
	hi_uint32  ui_spread_hw                       : 3 ; /*[25:27]*/
	hi_uint32  ui_divval_hw                       : 4 ; /*[28:31]*/
};

struct hi_sec_reg_crg_dio_hwpll_ctrl2_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_hwpll_ctrl3_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_hwpll_ctrl4_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_hwpll_ctrl5_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_lswpll_ctrl0_s {
	hi_uint32  ui_foutvcopd_lsw                   : 1 ; /*[0:0]*/
	hi_uint32  ui_foutpostdivpd_lsw               : 1 ; /*[1:1]*/
	hi_uint32  ui_fout4phasepd_lsw                : 1 ; /*[2:2]*/
	hi_uint32  ui_dsmpd_lsw                       : 1 ; /*[3:3]*/
	hi_uint32  ui_postdiv2_lsw                    : 3 ; /*[4:6]*/
	hi_uint32  ui_pd_lsw                          : 1 ; /*[7:7]*/
	hi_uint32  ui_postdiv1_lsw                    : 3 ; /*[8:10]*/
	hi_uint32  ui_dacpd_lsw                       : 1 ; /*[11:11]*/
	hi_uint32  ui_fbdiv_lsw                       : 12; /*[12:23]*/
	hi_uint32  ui_refdiv_lsw                      : 6 ; /*[24:29]*/
	hi_uint32  ui_bypass_lsw                      : 1 ; /*[30:30]*/
	hi_uint32  ui_disable_sscg_lsw                : 1 ; /*[31:31]*/
};

struct hi_sec_reg_crg_dio_lswpll_ctrl1_s {
	hi_uint32  ui_frac_lsw                        : 24; /*[0:23]*/
	hi_uint32  ui_downspread_lsw                  : 1 ; /*[24:24]*/
	hi_uint32  ui_spread_lsw                      : 3 ; /*[25:27]*/
	hi_uint32  ui_divval_lsw                      : 4 ; /*[28:31]*/
};

struct hi_sec_reg_crg_dio_lswpll_ctrl2_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_lswpll_ctrl3_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_lswpll_ctrl4_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_lswpll_ctrl5_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_safe_ctrl0_s {
	hi_uint32  ui_resv_0                          : 10; /*[0:9]*/
	hi_uint32  ui_wdg_rst_time_cfg                : 9 ; /*[10:18]*/
	hi_uint32  ui_resv_1                          : 9 ; /*[19:27]*/
	hi_uint32  ui_wdg_rst_dly_cfg                 : 2 ; /*[28:29]*/
	hi_uint32  ui_resv_2                          : 2 ; /*[30:31]*/
};

struct hi_sec_reg_crg_dio_safe_ctrl1_s {
	hi_uint32  ui_wdg_en_cfg                      : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_safe_ctrl2_s {
	hi_uint32  ui_wdg_init_cfg                    : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_safe_ctrl3_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_safe_ctrl4_s {
	hi_uint32  ui_resv_0                          : 32; /*[0:31]*/
};

struct hi_sec_reg_crg_dio_safe_ctrl5_s {
	hi_uint32  ui_wdg_time_out_int                : 1 ; /*[0:0]*/
	hi_uint32  ui_resv_0                          : 31; /*[1:31]*/
};

struct hi_sec_reg_crg_dio_safe_ctrl6_s {
	hi_uint32  ui_wdg_time_out_int_mask           : 1 ; /*[0:0]*/
	hi_uint32  ui_resv_0                          : 31; /*[1:31]*/
};

struct hi_sec_reg_crg_dio_safe_ctrl7_s {
	hi_uint32  ui_wdg_time_out_int_set            : 1 ; /*[0:0]*/
	hi_uint32  ui_resv_0                          : 31; /*[1:31]*/
};

#endif    //__HI_SEC_REG_CRG_DIO_H__
