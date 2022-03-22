/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Spi Register Define Header File
 * Author: tangjianbo
 * Create: 2020-01-21
 */
#ifndef SPI_TZ_REG_REG_H
#define SPI_TZ_REG_REG_H

/* spi base address (physical address) */
#define SPI0_BASE_ADDR 0x1100A000
#define SPI1_BASE_ADDR 0x11010000
#define SPI2_BASE_ADDR 0x11012000
#define SPI3_BASE_ADDR 0x11013000
#define SPI4_BASE_ADDR 0x11018000
#define SPI5_BASE_ADDR 0x11019000
#define SPI6_BASE_ADDR 0x1101D000
#define SPI7_BASE_ADDR 0x1101E000

#define SPI_CFG0_SCK_HIGH_OFFSET          0
#define SPI_CFG0_SCK_LOW_OFFSET           16
#define SPI_CFG0_CS_HOLD_OFFSET           0
#define SPI_CFG0_CS_SETUP_OFFSET          16
#define SPI_CFG1_REG_VAL_OFFSET           26

#define SPI_CFG0_SCK_HIGH_MASK            0xffff
#define SPI_CFG0_SCK_LOW_MASK             0xffff0000
#define SPI_CFG0_CS_HOLD_MASK             0xffff
#define SPI_CFG0_CS_SETUP_MASK            0xffff0000
#define SPI_CFG1_REG_VAL_MASK             0x7

#define SPI_CFG1_CS_IDLE_OFFSET           0
#define SPI_CFG1_PACKET_LOOP_OFFSET       8
#define SPI_CFG1_PACKET_LENGTH_OFFSET     16
#define SPI_CFG1_GET_TICK_DLY_OFFSET      29

#define SPI_CFG1_CS_IDLE_MASK             0xff
#define SPI_CFG1_PACKET_LOOP_MASK         0xff00
#define SPI_CFG1_PACKET_LENGTH_MASK       0x3fff0000
#define SPI_CFG1_GET_TICK_DLY_MASK        0xe0000000

#define SPI_CMD_ACT_OFFSET                0
#define SPI_CMD_RESUME_OFFSET             1
#define SPI_CMD_RST_OFFSET                2
#define SPI_CMD_PAUSE_EN_OFFSET           4
#define SPI_CMD_DEASSERT_OFFSET           5
#define SPI_CMD_SAMPLE_SEL_OFFSET         6
#define SPI_CMD_CS_POL_OFFSET             7
#define SPI_CMD_CPHA_OFFSET               8
#define SPI_CMD_CPOL_OFFSET               9
#define SPI_CMD_RX_DMA_OFFSET             10
#define SPI_CMD_TX_DMA_OFFSET             11
#define SPI_CMD_TXMSBF_OFFSET             12
#define SPI_CMD_RXMSBF_OFFSET             13
#define SPI_CMD_RX_ENDIAN_OFFSET          14
#define SPI_CMD_TX_ENDIAN_OFFSET          15
#define SPI_CMD_FINISH_IE_OFFSET          16
#define SPI_CMD_PAUSE_IE_OFFSET           17

#define SPI_CMD_ACT_MASK                  0x1
#define SPI_CMD_RESUME_MASK               0x2
#define SPI_CMD_RST_MASK                  0x4
#define SPI_CMD_PAUSE_EN_MASK             0x10
#define SPI_CMD_DEASSERT_MASK             0x20
#define SPI_CMD_CPHA_MASK                 0x100
#define SPI_CMD_CPOL_MASK                 0x200
#define SPI_CMD_RX_DMA_MASK               0x400
#define SPI_CMD_TX_DMA_MASK               0x800
#define SPI_CMD_TXMSBF_MASK               0x1000
#define SPI_CMD_RXMSBF_MASK               0x2000
#define SPI_CMD_RX_ENDIAN_MASK            0x4000
#define SPI_CMD_TX_ENDIAN_MASK            0x8000
#define SPI_CMD_FINISH_IE_MASK            0x10000
#define SPI_CMD_PAUSE_IE_MASK             0x20000

#define SPI_ULTRA_HIGH_EN_OFFSET          0
#define SPI_ULTRA_HIGH_THRESH_OFFSET      16

#define SPI_ULTRA_HIGH_EN_MASK            0x1
#define SPI_ULTRA_HIGH_THRESH_MASK        0xffff0000

/*
 * spi clock control define
 * please don't control spi clock in tee evnirment,
 * we hardly suggest that control the clock via kernel,
 * the API has bee provided by kernel spi
 */
#define SPI_PDN_PA_BASE     0x10001000

#define SPI12345_PDN_SET    (SPI_PDN_VA_BASE + 0xA4)
#define SPI12345_PDN_CLR    (SPI_PDN_VA_BASE + 0xA8)
#define SPI12345_PDN_STA    (SPI_PDN_VA_BASE + 0xAC)

#define SPI0_PDN_OFFSET     1
#define SPI1_PDN_OFFSET     6
#define SPI2_PDN_OFFSET     9
#define SPI3_PDN_OFFSET     10
#define SPI4_PDN_OFFSET     25
#define SPI5_PDN_OFFSET     26

#define SPI0_PDN_MASK       0x2
#define SPI1_PDN_MASK       0x40
#define SPI2_PDN_MASK       0x200
#define SPI3_PDN_MASK       0x400
#define SPI4_PDN_MASK       0x2000000
#define SPI5_PDN_MASK       0x4000000

/*
 * SPI clock
 * reg_base      reg_name          sta_ofs  set_ofs  clr_ofs    BIT    CG
 * 0x10001000    MODULE_SW_CG_2    0xac     0xa4     0xa8       26     SPI5_CG
 */
#define MODULE_SW_CG_2_SET    (0x10001000 + 0x00A4)
#define MODULE_SW_CG_2_CLR    (0x10001000 + 0x00A8)
#define MODULE_SW_CG_2_STA    (0x10001000 + 0x00AC)
#define CLK_CTL_CFG           0x04000000

/*
 * READ/WRITE register API
 * please don't hard code set any register in tee,
 * it may lead to issue difficult to debug
 */
#define spi_reg_get_32(addr, ret) do {        \
    __asm__ volatile("isb");                  \
    __asm__ volatile("dsb sy");               \
    (ret) = *(volatile unsigned int *)(addr); \
    __asm__ volatile("isb");                  \
    __asm__ volatile("dsb sy");               \
} while (0)

#define spi_reg_set_32(addr, val) do {        \
    __asm__ volatile("isb");                  \
    __asm__ volatile("dsb sy");               \
    *(volatile unsigned int *)(addr) = (val); \
    __asm__ volatile("isb");                  \
    __asm__ volatile("dsb sy");               \
} while (0)

#define SPI_READ(addr, ret)  spi_reg_get_32(addr, ret)
#define SPI_WRITE(addr, val) spi_reg_set_32(addr, val)

#endif /* SPI_TZ_REG_REG_H */
