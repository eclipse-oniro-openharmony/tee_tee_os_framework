/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file about sys
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_PLATFORM_SYS_GENERIC_H
#define DRV_TIMER_PLATFORM_SYS_GENERIC_H

#include "soc_acpu_baseaddr_interface.h"

#ifdef REG_BASE_SCTRL
#undef REG_BASE_SCTRL
#endif
#define REG_BASE_SCTRL SOC_ACPU_SCTRL_BASE_ADDR

#define SCTIMERCTRL0            (REG_BASE_SCTRL + 0x3c0)
#define SCTIMERCTRL1            (REG_BASE_SCTRL + 0x3c4)
#define TIMER1_B_EN_SEL         (1U << 2)
#define TIMER1_B_EN_OV          (1U << 3)
#define TIMER7_A_EN_SEL         (1U << 13)
#define TIMER7_A_EN_OV          (1U << 12)

#define CNT_TIMER_EN_SEL        (1u << 1)

#define SCPEREN0                (REG_BASE_SCTRL + 0x160)
#define SCPERCLKEN0             (REG_BASE_SCTRL + 0x168)
#define SCPEREN1                (REG_BASE_SCTRL + 0x170)
#define SCPERCLKEN1             (REG_BASE_SCTRL + 0x178)

#define SCPERCLKEN0_SEC         (REG_BASE_SCTRL + 0x908)
#define SCPEREN0_SEC            (REG_BASE_SCTRL + 0x900)
#ifdef REG_BASE_PERI_CRG
#undef REG_BASE_PERI_CRG
#endif

#define REG_BASE_PERI_CRG SOC_ACPU_PERI_CRG_BASE_ADDR

#ifdef REG_BASE_PCTRL
#undef REG_BASE_PCTRL
#endif

#define REG_BASE_PCTRL SOC_ACPU_PCTRL_BASE_ADDR

#define SCCTRL                 (REG_BASE_SCTRL + 0x000)
#define SCSYSSTAT              (REG_BASE_SCTRL + 0x004)
#define SCITMCTRL              (REG_BASE_SCTRL + 0x008)
#define SCIMSTAT               (REG_BASE_SCTRL + 0x00C)
#define SCXTALCTRL             (REG_BASE_SCTRL + 0x010)

#define SCPLLSTAT              (REG_BASE_SCTRL + 0x02C)
#define SCPERDIS0              (REG_BASE_SCTRL + 0x034)
#define SCPERSTAT0             (REG_BASE_SCTRL + 0x03C)
#define SCPERDIS1              (REG_BASE_SCTRL + 0x044)
#define SCPERSTAT1             (REG_BASE_SCTRL + 0x04C)
#define SCPEREN2               (REG_BASE_SCTRL + 0x050)
#define SCPERDIS2              (REG_BASE_SCTRL + 0x054)
#define SCPERCLKEN2            (REG_BASE_SCTRL + 0x058)
#define SCPERSTAT2             (REG_BASE_SCTRL + 0x05C)

#define SCPERRSTEN0            (REG_BASE_SCTRL + 0x080)
#define SCPERRSTDIS0           (REG_BASE_SCTRL + 0x084)
#define SCPERRSTSTAT0          (REG_BASE_SCTRL + 0x088)
#define SCPERRSTEN1            (REG_BASE_SCTRL + 0x08C)
#define SCPERRSTDIS1           (REG_BASE_SCTRL + 0x090)
#define SCPERRSTSTAT1          (REG_BASE_SCTRL + 0x094)
#define SCPERRSTEN2            (REG_BASE_SCTRL + 0x098)
#define SCPERRSTDIS2           (REG_BASE_SCTRL + 0x09C)

#define SCPERRSTSTAT2          (REG_BASE_SCTRL + 0x0A0)
#define SCIPCLKRSTBUS          (REG_BASE_SCTRL + 0x0A4)

#define SCISOEN                (REG_BASE_SCTRL + 0x0C0)
#define SCISODIS               (REG_BASE_SCTRL + 0x0C4)
#define SCISOSTAT              (REG_BASE_SCTRL + 0x0C8)
#define SCPERPWREN             (REG_BASE_SCTRL + 0x0D0)
#define SCPERPWRDIS            (REG_BASE_SCTRL + 0x0D4)
#define SCPERPWRSTAT           (REG_BASE_SCTRL + 0x0D8)
#define SCPERPWRACK            (REG_BASE_SCTRL + 0x0DC)
#define SCPERPWRDOWNTIME       (REG_BASE_SCTRL + 0x0E0)

#define SCPERPWRUPTIME         (REG_BASE_SCTRL + 0x0E4)

#define SCCLKDIV0              (REG_BASE_SCTRL + 0x100)
#define SCCLKDIV1              (REG_BASE_SCTRL + 0x104)
#define SCCLKDIV2              (REG_BASE_SCTRL + 0x108)
#define SCCLKDIV3              (REG_BASE_SCTRL + 0x10C)
#define SCCLKDIV4              (REG_BASE_SCTRL + 0x110)
#define SCCLKDIV5              (REG_BASE_SCTRL + 0x114)
#define SCCLKDIV6              (REG_BASE_SCTRL + 0x118)
#define SCCLKDIV7              (REG_BASE_SCTRL + 0x11C)
#define SCCLKDIV8              (REG_BASE_SCTRL + 0x120)
#define SCCLKDIV9              (REG_BASE_SCTRL + 0x124)
#define SCCLKDIV10             (REG_BASE_SCTRL + 0x128)
#define SCCLKDIV11             (REG_BASE_SCTRL + 0x12C)
#define SCCLKDIV12             (REG_BASE_SCTRL + 0x130)
#define SCCLKDIV13             (REG_BASE_SCTRL + 0x134)
#define SCCLKDIV14             (REG_BASE_SCTRL + 0x138)
#define SCCLKDIV15             (REG_BASE_SCTRL + 0x13C)
#define SCCLKDIV16             (REG_BASE_SCTRL + 0x140)
#define SCCLKDIV17             (REG_BASE_SCTRL + 0x144)
#define SCCLKDIV18             (REG_BASE_SCTRL + 0x148)
#define SCCLKDIV19             (REG_BASE_SCTRL + 0x14C)
#define SCPERCTRL0             (REG_BASE_SCTRL + 0x200)
#define SCPERCTRL1             (REG_BASE_SCTRL + 0x204)
#define SCPERCTRL2             (REG_BASE_SCTRL + 0x208)
#define SCPERCTRL3             (REG_BASE_SCTRL + 0x20C)
#define SCPERCTRL4             (REG_BASE_SCTRL + 0x210)
#define SCPERCTRL5             (REG_BASE_SCTRL + 0x214)
#define SCPERCTRL6             (REG_BASE_SCTRL + 0x218)
#define SCDEEPSLEEPED          (REG_BASE_SCTRL + 0x300)
#define SCINNERRSTAT           (REG_BASE_SCTRL + 0x304)
#define SCSWADDR               (REG_BASE_SCTRL + 0x308)
#define SCDDRADDR              (REG_BASE_SCTRL + 0x30C)
#define SCDDRDATA              (REG_BASE_SCTRL + 0x310)
#define SCBAKDATA0             (REG_BASE_SCTRL + 0x314)
#define SCBAKDATA1             (REG_BASE_SCTRL + 0x318)
#define SCBAKDATA2             (REG_BASE_SCTRL + 0x31C)
#define SCBAKDATA3             (REG_BASE_SCTRL + 0x320)
#define SCBAKDATA4             (REG_BASE_SCTRL + 0x324)
#define SCBAKDATA5             (REG_BASE_SCTRL + 0x328)
#define SCBAKDATA6             (REG_BASE_SCTRL + 0x32C)
#define SCBAKDATA7             (REG_BASE_SCTRL + 0x330)
#define SCSLICE32K             (REG_BASE_SCTRL + 0x534)
#define SCCLKCNTCFG            (REG_BASE_SCTRL + 0x820)

#if defined(WITH_CHIP_BALTIMORE)
#define SCTIMERCTRL_SEC        (REG_BASE_SCTRL + 0x90C)
#else
#define SCTIMERCTRL_SEC        (REG_BASE_SCTRL + 0x940)
#endif

#define SCSOCID0               (REG_BASE_SCTRL + 0xE00)

#ifdef REG_BASE_IOC
#undef REG_BASE_IOC
#undef REG_BASE_SPI0
#undef REG_BASE_SPI1
#undef REG_BASE_GPIO0
#undef REG_BASE_GPIO1
#undef REG_BASE_GPIO2
#undef REG_BASE_GPIO3
#undef REG_BASE_GPIO4
#undef REG_BASE_GPIO5
#undef REG_BASE_GPIO6
#undef REG_BASE_GPIO7
#undef REG_BASE_GPIO8
#undef REG_BASE_GPIO9
#undef REG_BASE_GPIO10
#undef REG_BASE_GPIO11
#undef REG_BASE_GPIO12
#undef REG_BASE_GPIO13
#undef REG_BASE_GPIO14
#undef REG_BASE_GPIO15
#undef REG_BASE_GPIO16
#undef REG_BASE_GPIO17
#undef REG_BASE_GPIO18
#undef REG_BASE_GPIO19
#undef REG_BASE_GPIO20
#undef REG_BASE_GPIO21
#undef REG_BASE_GPIO22
#undef REG_BASE_GPIO23
#undef REG_BASE_GPIO24
#undef REG_BASE_GPIO25
#undef REG_BASE_GPIO26
#endif

#define REG_BASE_IOC                0xE8612000
#define REG_BASE_SPI0               0xFDF07000
#define REG_BASE_SPI1               0xFDF08000
#define REG_BASE_GPIO0              0xE8A0B000
#define REG_BASE_GPIO1              0xE8A0C000
#define REG_BASE_GPIO2              0xE8A0D000
#define REG_BASE_GPIO3              0xE8A0E000
#define REG_BASE_GPIO4              0xE8A0F000
#define REG_BASE_GPIO5              0xE8A10000
#define REG_BASE_GPIO6              0xE8A11000
#define REG_BASE_GPIO7              0xE8A12000
#define REG_BASE_GPIO8              0xE8A13000
#define REG_BASE_GPIO9              0xE8A14000
#define REG_BASE_GPIO10             0xE8A15000
#define REG_BASE_GPIO11             0xE8A16000
#define REG_BASE_GPIO12             0xE8A17000
#define REG_BASE_GPIO13             0xE8A18000
#define REG_BASE_GPIO14             0xE8A19000
#define REG_BASE_GPIO15             0xE8A1A000
#define REG_BASE_GPIO16             0xE8A1B000
#define REG_BASE_GPIO17             0xE8A1C000
#define REG_BASE_GPIO18             0xE8A1D000
#define REG_BASE_GPIO19             0xE8A1E000
#define REG_BASE_GPIO20             0xE8A1F000
#define REG_BASE_GPIO21             0xE8A20000
#define REG_BASE_GPIO22             0xFFF0B000
#define REG_BASE_GPIO23             0xFFF0C000
#define REG_BASE_GPIO24             0xFFF0D000
#define REG_BASE_GPIO25             0xFFF0E000
#define REG_BASE_GPIO26             0xFFF0F000

#define PERTIMECTRL     (REG_BASE_PERI_CRG + 0x140)

/* close ccs soft reset */
#define PERRSTDIS4      (REG_BASE_PERI_CRG + 0x094)
#define PERRSTSTAT4     (REG_BASE_PERI_CRG + 0x098)
#define IP_RST_SECS (1 << 14)
/* enable ccs clk */
#define CCS_CLK_REG_ADDR  (REG_BASE_SCTRL + 0x840)

#define SOC_SC_ON_BASE_ADDR                           0xF7410000

#define TIMER_SECU_EN           (1U << 16)

#define TIME_FORCE_HIGH         (1U << 8)

#define PERIPHERAL_BASE_CTRL    0xE8A09000
#define PCPEREN1                (PERIPHERAL_BASE_CTRL + 0x10)
#define PCPERCLKEN1             (PERIPHERAL_BASE_CTRL + 0x18)

#define EFUSEC_PHY_BASE         0xFFF10000
#define PMURTC_PHY_BASE         0xFFF34000

#ifdef REG_BASE_DMA0
#undef REG_BASE_DMA0
#endif
#define REG_BASE_DMA0           0xFDF30000

#define TEMP_RDR_MEM_SIZE       (10 * 1024)
#define DUMP_DDR_STATUS_OFFSET  20
#define STORE_OFFSET_UNIT       0x200
#define SAVE_CTX_OFFSET         68

#define RDR_MEM_ADDR            0x3f800000
#define EXCEPT_CORE_ADDR        64
#define EXCEPT_REASON_ADDR      68
#define EXCEPT_CORE_VALUE       0x01000000
#define EXCEPT_REASON_VALUE     0x00000003

#define REBOOT_WATCHDOG_CMDNUM  15

#endif
