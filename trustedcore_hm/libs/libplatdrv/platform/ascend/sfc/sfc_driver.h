/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
* Description: SFC driver head file
* Author: huawei
* Create: 2019/11/20
*/

#ifndef SFC_DRIVER_H
#define SFC_DRIVER_H

#include <alltypes.h>

#ifdef ASCEND920_BUILD
#define SFC_REG_BASE_ADDR                           0x85000000U
#else
#define SFC_REG_BASE_ADDR                           0x84100000U
#endif
#define SFC_CHIP_OFFSET                             0x8000000000U
#define SFC_REG_BUS_CONFIG1                         (SFC_REG_BASE_ADDR + 0x0200)
#define SFC_CMD_CONFIG_OFFSET                       (SFC_REG_BASE_ADDR + 0x0300)
#define SFC_CMD_INS_OFFSET                          (SFC_REG_BASE_ADDR + 0x0308)
#define SFC_CMD_ADDR_OFFSET                         (SFC_REG_BASE_ADDR + 0x030C)
#define SFC_CMD_DATABUF_OFFSET                      (SFC_REG_BASE_ADDR + 0x0400)

#define SPI_FLASH_SIZE                              (16 * 1024 * 1024)
#define SPI_FLASH_SECTOR_SIZE                       (0x10000)

#define N25Q_MANU_ID                                0x20
#define N25Q_DEVICE_ID                              0x18BA
#define N25Q_SIZE                                   0x1000000
#define N25Q_SECTOR_SIZE                            0x10000
#define N25Q_PAGE_SIZE                              0x100
#define MIRCON_N25Q128_INDEX                        0

#define MT25_MANU_ID                                0x20
#define MT25_DEVICE_ID                              0x18BB
#define MT25_SIZE                                   0x1000000
#define MT25_SECTOR_SIZE                            0x10000
#define MT25_PAGE_SIZE                              0x100
#define MIRCON_25QU128AB_INDEX                      1

#define MX25_MANU_ID                                0xC2
#define MX25_DEVICE_ID                              0x3825
#define MX25_SIZE                                   SPI_FLASH_SIZE
#define MX25_SECTOR_SIZE                            SPI_FLASH_SECTOR_SIZE
#define MX25_PAGE_SIZE                              0x100
#define MX25_INDEX                                  2

#define S25F_MANU_ID                                0x01
#define S25F_DEVICE_ID                              0x1820
#define S25F_SIZE                                   SPI_FLASH_SIZE
#define S25F_SECTOR_SIZE                            SPI_FLASH_SECTOR_SIZE
#define S25F_PAGE_SIZE                              0x100
#define S25F_INDEX                                  3

#define W25Q_MANU_ID                                0xEF
#define W25Q_DEVICE_ID                              0x6018
#define W25Q_SIZE                                   0x1000000
#define W25Q_SECTOR_SIZE                            0x10000
#define W25Q_PAGE_SIZE                              0x100
#define WINBOND_W25Q128_INDEX                       4

#define N25Q5_MANU_ID                               0x20
#define N25Q5_DEVICE_ID                             0x20BB
#define N25Q5_SIZE                                  0x4000000
#define N25Q5_SECTOR_SIZE                           0x10000
#define N25Q5_PAGE_SIZE                             0x100
#define MIRCON_N25Q512A_INDEX                       5

#define MX66_MANU_ID                                0xC2
#define MX66_DEVICE_ID                              0x3A25
#define MX66_SIZE                                   0x4000000
#define MX66_SECTOR_SIZE                            0x10000
#define MX66_PAGE_SIZE                              0x100
#define MXIC_MX66U512_INDEX                         6

#define S25FS_MANU_ID                               0x01
#define S25FS_DEVICE_ID                             0x2002
#define S25FS_SIZE                                  0x4000000
#define S25FS_SECTOR_SIZE                           0x40000
#define S25FS_PAGE_SIZE                             0x100
#define SPANSION_S25FS512S_INDEX                    7

#define MX25U_MANU_ID                               0xC2
#define MX25U_DEVICE_ID                             0x3725
#define MX25U_SIZE                                  0x800000
#define MX25U_SECTOR_SIZE                           0x10000
#define MX25U_PAGE_SIZE                             0x100
#define MXIC_MX25U6473F_INDEX                       8

#define W25Q6_MANU_ID                               0xEF
#define W25Q6_DEVICE_ID                             0x1760
#define W25Q6_SIZE                                  0x800000
#define W25Q6_SECTOR_SIZE                           0x10000
#define W25Q6_PAGE_SIZE                             0x100
#define WINBOND_W25Q64FW_INDEX                      9

#define ISSI_MANU_ID                                0x9D
#define ISSI_DEVICE_ID                              0x1870
#define ISSI_SIZE                                   SPI_FLASH_SIZE
#define ISSI_SECTOR_SIZE                            SPI_FLASH_SECTOR_SIZE
#define ISSI_PAGE_SIZE                              0x100
#define ISSI_IS25WP128_INDEX                        10

#define GD25_MANU_ID                                0xC8
#define GD25_DEVICE_ID                              0x1A67
#define GD25_SIZE                                   0x4000000
#define GD25_SECTOR_SIZE                            0x10000
#define GD25_PAGE_SIZE                              0x100
#define GIGA_GD25LB512_INDEX                        11

#define GD25L_MANU_ID                               0xC8
#define GD25L_DEVICE_ID                             0x1860
#define GD25L_SIZE                                  0x1000000
#define GD25L_SECTOR_SIZE                           0x10000
#define GD25L_PAGE_SIZE                             0x100
#define GIGA_GD25LE128_INDEX                        12

#define SFC_CMD_CFG_WRITE                           0
#define SPI_CMD_PP                                  0x02 /* 1B Page Programming */
#define SPI_4B_CMD_PP                               0x12 /* 4B Page Programming */
#define SPI_CMD_WREN                                0x06 /* write enable */
#define SPI_CMD_WRDISABLE                           0x04
#define SPI_4B_CMD_SE                               0xDC
#define SPI_CMD_SE                                  0xD8 /* 64K sector erase */

#define SPI_FLASH_IDLE_CHECK_FIR                    100000
#define SPI_FLASH_IDLE_CHECK_SEC                    100
#define SPI_FLASH_IDLE_CHECK_FOU                    1000

#define CURR_DATA_CON                               3
#define SPI_CMD_RDSR                                0x05 /* Read Status Register */
#define SPI_CMD_SR_WIP                              1    /* Write in Progress bit in status register position */

#define FLASH_INDEX_INITIAL_VALUE                   0xFF
#define SFC_CMD_ADDR_MSK                            0x3FFFFFFF

#define SFC_CMD_CFG_READ                            1
#define SFC_CMD_DATA_CNT(x)                         ((x) - 1)
#define SFC_CMD_MAX_WORD_WRITE_LEN                  16
#define SPI_CMD_RDID                                0x9F  /* Read Identification */
#define SPI_FLASH_CMD_EXECUTE_TIMEOUT               5000000
#define SPI_CMD_OP_END                              1    /* Operation end test bit */

#define SPI_CMD_READ                                0x03 /* Read Data bytes */
#define SPI_4B_CMD_READ                             0x13 /* 4B READ */
#define FLASH_BASE_ADDR                             0x90000000U /* SFC Mem(taishan view) */
#define SPI_DEFAULT_ID                              0xFFFFFFFFU
#define SPI_DEVID_MASK                              0xFFFFFFU
#define SFC_TIMING_SH_PARAM                         6U
#define SFC_TIMING_SS_PARAM                         6U
#define SFC_TIMING_SHSL_PARAM                       0xFU
#define SFC_CFG_BUS_OP_WR_PARAM0                    3U
#define SFC_CFG_BUS_OP_RD_PARAM1                    3U
#define SFC_CFG_BUS_OP_WR_INS_PARAM                 2U
#define SFC_CFG_BUS_OP_RD_INS_PARAM                 3U
#define SFC_CMD_OP_PARAM1                           3U
#define SFC_API_SHIFT_32BITS                        32
#define FLASH_STATE_OK                              0

typedef union Sfc_Cmd_Config {
    struct {
        uint32_t start:1;
        uint32_t sel_cs:1;
        uint32_t rsv0:1;
        uint32_t addr_en:1;
        uint32_t dummy_byte_cnt:3;
        uint32_t data_en:1;
        uint32_t rw:1;
        uint32_t data_cnt:8;
        uint32_t mem_if_type:3;
        uint32_t rsv1:12;
    }bits;
    uint32_t u32;
} UN_SFC_CMD_CONFIG;

typedef enum Spi_If_Type {
    SPI_IF_STD,                     /* Standard SPI */
    SPI_IF_DUAL_INPUT_DUAL_OUTPUT,  /* Dual-Input/Dual-Output SPI */
    SPI_IF_DUAL_IO,                 /* Dual-I/O SPI */
    SPI_IF_FULL_DIO,                /* Full DIO SPI */
    SPI_IF_QUAD_INPUT_QUAD_OUTPUT = 5,  /* Quad-Input/Dual-Output SPI */
    SPI_IF_QUAD_IO,      /* Quad-I/O SPI */
    SPI_IF_FULL_QIO,     /* Full QIO SPI */
    SPI_IF_SPI_IF_TYPE_MAX,
} EN_SPI_IF_TPYE;

typedef struct Sfc_Timing {
    uint32_t      tcsh;
    uint32_t      tcss;
    uint32_t      tshsl;
} SFC_TIMING;

typedef struct Spi_Flash {
    const char    *model_name;
    uint8_t       manufactureID;
    uint8_t       Index;
    uint16_t      deviceID;
    uint32_t      cs;
    uint32_t      size;
    uint32_t      sector_size;
    uint32_t      interface_type;
    uint32_t      rd_dummy_bytes;
    uint32_t      wr_dummy_bytes;
    uint32_t      page_size;
    uint64_t      map_base;
} SPI_FLASH;

typedef struct Sfc_Cfg_Global {
    uint32_t      rd_delay;        /* num of data delay cycles */
    uint32_t      flash_addr_mode; /* SPI ADDR mode */
    uint32_t      mode;
} SFC_CFG_GLOBAL;

typedef struct Sfc_Cfg_Bus_Op {
    uint8_t       wr_ins;
    uint8_t       wr_dummy_bytes;
    uint8_t       wr_mem_if_type;
    uint8_t       rd_ins;
    uint8_t       rd_prefetch_cnt;
    uint8_t       rd_dummy_bytes;
    uint8_t       rd_mem_if_type;
    uint8_t       wip_locate;
} SFC_CFG_BUS_OP;

typedef struct Sfc_Cfg_Cmd_Op {
    uint8_t       mem_if_type;
    uint8_t       dummy_byte_cnt;
} SFC_CFG_CMD_OP;

typedef struct Sfc {
    uint32_t        version;
    uint64_t        reg_base;
    SFC_TIMING      timing;
    SFC_CFG_GLOBAL  global_cfg;
    SFC_CFG_BUS_OP  bus_op_cfg;
    uint32_t        pp_timing;
    uint32_t        pp_timeout_en;
    SPI_FLASH       *spi_flash;
    SFC_CFG_CMD_OP  cmd_op_cfg;
} SFC;

typedef struct FlashInfo {
    uint64_t   flash_id;
    uint16_t   device_id;
    uint16_t   vendor_id;
    uint32_t   state;
    uint64_t   size;
    uint32_t   sector_cnt;
    uint16_t   manufacturer_id;
} FLASHINFO;

static inline uint64_t get_sfc_chip_offset(uint32_t chip_id)
{
    uint64_t offset = (chip_id != 0) ? SFC_CHIP_OFFSET : 0;

    return offset;
}

uint32_t sfc_cmd_write(uint32_t offset, uint8_t *buffer, uint32_t len, uint32_t chip_id);
uint32_t sfc_bus_read(uint32_t offset, uint8_t *buffer, uint32_t len, uint32_t chip_id);
uint32_t sfc_cmd_read(uint32_t offset, uint8_t *buffer, uint32_t len, uint32_t chip_id);
uint32_t get_spi_flash_index(uint32_t chip_id);
uint32_t sfc_cmd_erase(uint32_t offset, uint32_t length, uint32_t chip_id);
uint32_t get_device_id(uint32_t *id, uint8_t cs, uint32_t chip_id);
void get_manu_device_id(uint32_t id, uint32_t *out_manu_id, uint32_t *out_device_id);

#endif
