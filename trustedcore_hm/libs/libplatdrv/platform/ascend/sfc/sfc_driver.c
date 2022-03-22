/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: SFC driver source file
* Author: huawei
* Create: 2020/3/25
*/
#include <register_ops.h>
#include "io_operations.h"
#include "drv_mem.h"
#include <tee_defines.h>

#include "driver_common.h"
#include "timer.h"
#include "securec.h"
#include "tee_log.h"
#include "sfc_driver.h"
#include "sfc_api.h"

static uint8_t g_SpiFlashIndex = FLASH_INDEX_INITIAL_VALUE;
static SPI_FLASH g_SpiFlashInstance[] = {
    {
        .model_name = "n25q128mb", // MIRCON chip
        .manufactureID = N25Q_MANU_ID,
        .deviceID    = N25Q_DEVICE_ID,
        .cs      = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = N25Q_SIZE,
        .sector_size = N25Q_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = N25Q_PAGE_SIZE,
        .Index = MIRCON_N25Q128_INDEX,
    },
    {
        .model_name = "MT25QU128AB", // MIRCON chip
        .manufactureID = MT25_MANU_ID,
        .deviceID   = MT25_DEVICE_ID,
        .cs      = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = MT25_SIZE,
        .sector_size = MT25_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = MT25_PAGE_SIZE,
        .Index = MIRCON_25QU128AB_INDEX,
    },
    {
        .model_name = "MX25U12835F",
        .manufactureID = MX25_MANU_ID,
        .deviceID = MX25_DEVICE_ID,
        .cs = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = MX25_SIZE,
        .sector_size = MX25_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = MX25_PAGE_SIZE,
        .Index = MX25_INDEX,
    },
    {
        .model_name = "S25FL128S",
        .manufactureID = S25F_MANU_ID,
        .deviceID = S25F_DEVICE_ID,
        .cs = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = S25F_SIZE,
        .sector_size = S25F_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = S25F_PAGE_SIZE,
        .Index = S25F_INDEX,
    },
    {
        .model_name = "W25Q128FW",
        .manufactureID = W25Q_MANU_ID,
        .deviceID   = W25Q_DEVICE_ID,
        .cs      = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = W25Q_SIZE,
        .sector_size = W25Q_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = W25Q_PAGE_SIZE,
        .Index = WINBOND_W25Q128_INDEX,
    },
    {
        .model_name = "N25Q512A", // MIRCON chip
        .manufactureID = N25Q5_MANU_ID,
        .deviceID   = N25Q5_DEVICE_ID,
        .cs      = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = N25Q5_SIZE,
        .sector_size = N25Q5_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = N25Q5_PAGE_SIZE,
        .Index = MIRCON_N25Q512A_INDEX,
    },
    {
        .model_name = "MX66U51235FMI",
        .manufactureID = MX66_MANU_ID,
        .deviceID   = MX66_DEVICE_ID,
        .cs      = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = MX66_SIZE,
        .sector_size = MX66_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = MX66_PAGE_SIZE,
        .Index = MXIC_MX66U512_INDEX,
    },
    {
        .model_name = "S25FS512S", // spansion chip
        .manufactureID = S25FS_MANU_ID,
        .deviceID   = S25FS_DEVICE_ID,
        .cs      = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = S25FS_SIZE,
        .sector_size = S25FS_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = S25FS_PAGE_SIZE,
        .Index = SPANSION_S25FS512S_INDEX,
    },
    {
        .model_name = "MX25U6437F", // MIXC chip
        .manufactureID = MX25U_MANU_ID,
        .deviceID   = MX25U_DEVICE_ID,
        .cs      = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = MX25U_SIZE,
        .sector_size = MX25U_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = MX25U_PAGE_SIZE,
        .Index = MXIC_MX25U6473F_INDEX,
    },
    {
        .model_name = "W25Q64FW",
        .manufactureID = W25Q6_MANU_ID,
        .deviceID   = W25Q6_DEVICE_ID,
        .cs      = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = W25Q6_SIZE,
        .sector_size = W25Q6_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = W25Q6_PAGE_SIZE,
        .Index = WINBOND_W25Q64FW_INDEX,
    },
    {
        .model_name = "IS25WP128",
        .manufactureID = ISSI_MANU_ID,
        .deviceID   = ISSI_DEVICE_ID,
        .cs = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = ISSI_SIZE,
        .sector_size = ISSI_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = ISSI_PAGE_SIZE,
        .Index = ISSI_IS25WP128_INDEX,
    },
    {
        .model_name = "GD25LB512ME",
        .manufactureID = GD25_MANU_ID,
        .deviceID   = GD25_DEVICE_ID,
        .cs      = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = GD25_SIZE,
        .sector_size = GD25_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = GD25_PAGE_SIZE,
        .Index = GIGA_GD25LB512_INDEX,
    },
    {
        .model_name = "GD25LE128E",
        .manufactureID = GD25L_MANU_ID,
        .deviceID   = GD25L_DEVICE_ID,
        .cs      = 0,
        .map_base = FLASH_BASE_ADDR,
        .size = GD25L_SIZE,
        .sector_size = GD25L_SECTOR_SIZE,
        .interface_type = SPI_IF_STD,
        .rd_dummy_bytes = 0,
        .wr_dummy_bytes = 0,
        .page_size = GD25L_PAGE_SIZE,
        .Index = GIGA_GD25LE128_INDEX,
    }
};

static SFC g_Sfc = {
    .reg_base = SFC_REG_BASE_ADDR,
    {
        .tcsh = SFC_TIMING_SH_PARAM,
        .tcss = SFC_TIMING_SS_PARAM,
        .tshsl = SFC_TIMING_SHSL_PARAM,
    },
    {
        .rd_delay = 0,
        .flash_addr_mode = 0, /* 3Bytes addr mode(default) */
        .mode = 0,
    },
    {
        .wr_ins = SFC_CFG_BUS_OP_WR_INS_PARAM,
        .wr_dummy_bytes = SFC_CFG_BUS_OP_WR_PARAM0,
        .wr_mem_if_type = 0,
        .rd_ins = SFC_CFG_BUS_OP_RD_INS_PARAM,
        .rd_prefetch_cnt = 0,
        .rd_dummy_bytes = SFC_CFG_BUS_OP_RD_PARAM1,
        .rd_mem_if_type = 0,
        .wip_locate = 0,
    },
    .pp_timing = 0,
    .pp_timeout_en = 0,
    .spi_flash = g_SpiFlashInstance,
    {
        .mem_if_type = 0,
        .dummy_byte_cnt = SFC_CMD_OP_PARAM1,
    },
};

STATIC uint32_t check_cmd_execute_status(uint32_t chip_id)
{
    volatile uint32_t val;
    volatile uint32_t timeout = SPI_FLASH_CMD_EXECUTE_TIMEOUT;
    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    val = read32(SFC_CMD_CONFIG_OFFSET + chip_offset);

    do {
        if ((timeout % SPI_FLASH_IDLE_CHECK_FOU) == 0) {
            val = read32(SFC_CMD_CONFIG_OFFSET + chip_offset);
        }

        timeout--;

        if (timeout == 0) {
            tloge("chk cmd exe status timeout, 0x%x.\n", val);
            return TEE_ERROR_BUSY;
        }
    } while ((val & SPI_CMD_OP_END) > 0);

    return TEE_SUCCESS;
}

STATIC uint32_t sfc_cmd_write_en(SPI_FLASH *spi, uint32_t cmd, uint32_t chip_id)
{
    UN_SFC_CMD_CONFIG temp = {.u32 = 0};
    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    write32(SFC_CMD_INS_OFFSET + chip_offset, cmd);
    temp.u32 = read32(SFC_CMD_CONFIG_OFFSET + chip_offset);
    temp.bits.addr_en = 0;
    temp.bits.data_en = 0;
    temp.bits.sel_cs = spi->cs;
    temp.bits.start = 1;
    write32(SFC_CMD_CONFIG_OFFSET + chip_offset, temp.u32);

    return check_cmd_execute_status(chip_id);
}

STATIC uint32_t sfc_cmd_buf_check(uint64_t chip_offset)
{
    volatile uint32_t timeout = SPI_FLASH_IDLE_CHECK_SEC;

    while (timeout > 0) {
        uint32_t val;

        val = read32(SFC_CMD_DATABUF_OFFSET + chip_offset);
        if (!(val & SPI_CMD_SR_WIP)) {
            return TEE_SUCCESS;
        }

        timeout--;
    }

    return TEE_ERROR_BUSY;
}

STATIC uint32_t spi_flash_idle(SPI_FLASH *spi, uint32_t chip_id)
{
    UN_SFC_CMD_CONFIG temp = {.u32 = 0};
    volatile uint32_t timeout = SPI_FLASH_IDLE_CHECK_FIR;

    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    write32(SFC_CMD_INS_OFFSET + chip_offset, SPI_CMD_RDSR);
    do {
        temp.bits.rw = SFC_CMD_CFG_READ;
        temp.bits.addr_en = 0;
        temp.bits.data_en = 1;
        temp.bits.data_cnt = SFC_CMD_DATA_CNT(1);
        temp.bits.sel_cs = spi->cs;
        temp.bits.start = 1;
        write32(SFC_CMD_CONFIG_OFFSET + chip_offset, temp.u32);

        /* waiting operation be finished */
        uint32_t ret = check_cmd_execute_status(chip_id);
        if (ret != TEE_SUCCESS) {
            tloge("chk spi flash idle status failed!\n");
            return ret;
        }

        if (sfc_cmd_buf_check(chip_offset) == TEE_SUCCESS) {
            return TEE_SUCCESS;
        }

        timeout--;
    } while (timeout > 0);

    tloge("spi flash not idle!\n");

    return TEE_ERROR_BAD_STATE;
}

STATIC uint32_t sfc_cmd_buf_write(uint32_t offset, uint8_t *buf_src, uint32_t len,
    uint32_t chip_id)
{
    uint32_t ret;
    UN_SFC_CMD_CONFIG temp = {.u32 = 0};
    uint32_t *src_addr = NULL;
    SPI_FLASH *spi = &g_Sfc.spi_flash[g_SpiFlashIndex];

    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    /* check flash is free or not */
    ret = spi_flash_idle(spi, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("write spi flash idle fail,0 x%x.\n", ret);
        return ret;
    }

    ret = sfc_cmd_write_en(spi, SPI_CMD_WREN, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("enable sfc cmd write fail!\n");
        return ret;
    }

    /* write data into databuf */
    for (uint32_t i = 0; i < (len / sizeof(uint32_t)); i++) {
        src_addr = (uint32_t *)(buf_src + (i * sizeof(uint32_t)));
        write32(SFC_CMD_DATABUF_OFFSET + chip_offset + (uint64_t)(i * sizeof(uint32_t)), *src_addr);
    }

    write32(SFC_CMD_INS_OFFSET + chip_offset, SPI_CMD_PP);
    write32(SFC_CMD_ADDR_OFFSET + chip_offset, (offset & SFC_CMD_ADDR_MSK));

    temp.bits.rw = SFC_CMD_CFG_WRITE;
    temp.bits.addr_en = 1;
    temp.bits.data_en = 1;
    temp.bits.data_cnt = SFC_CMD_DATA_CNT(len);
    temp.bits.sel_cs = spi->cs;
    temp.bits.start = 1;
    write32(SFC_CMD_CONFIG_OFFSET + chip_offset, temp.u32);

    /* waiting operation to be finished */
    ret = check_cmd_execute_status(chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("Command execute, 0x%x.\n", ret);
        return ret;
    }

    /* waiting erasing to be finished */
    ret = spi_flash_idle(spi, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("SPI flash erase timeout!\n");
        return ret;
    }

    ret = sfc_cmd_write_en(spi, SPI_CMD_WRDISABLE, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("SFC write disable fail!\n");
    }

    return ret;
}

STATIC uint32_t sfc_cmd_one_byte_write(uint32_t offset, uint8_t *buf_src, uint32_t chip_id)
{
    uint32_t ret;
    UN_SFC_CMD_CONFIG temp = {.u32 = 0};
    SPI_FLASH *spi = &(g_Sfc.spi_flash[g_SpiFlashIndex]);
    uint32_t *src_addr = NULL;

    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    ret = spi_flash_idle(spi, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("check spi flash idle fail, 0x%x.\n", ret);
        return ret;
    }

    ret = sfc_cmd_write_en(spi, SPI_CMD_WREN, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("enable sfc cmd write fail!\n");
        return ret;
    }

    src_addr = (uint32_t *)buf_src;
    write32(SFC_CMD_DATABUF_OFFSET + chip_offset, *src_addr);
    write32(SFC_CMD_INS_OFFSET + chip_offset, SPI_CMD_PP);
    write32(SFC_CMD_ADDR_OFFSET + chip_offset, (offset & SFC_CMD_ADDR_MSK));

    temp.u32 = read32(SFC_CMD_CONFIG_OFFSET + chip_offset);
    temp.bits.rw = SFC_CMD_CFG_WRITE;
    temp.bits.addr_en = 1;
    temp.bits.data_en = 1;
    temp.bits.data_cnt = SFC_CMD_DATA_CNT(1);
    temp.bits.sel_cs = spi->cs;
    temp.bits.start = 1;
    write32(SFC_CMD_CONFIG_OFFSET + chip_offset, temp.u32);

    /* waiting operation to be finished */
    ret = check_cmd_execute_status(chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("check cmd execute status fail!\n");
        return ret;
    }

    ret = spi_flash_idle(spi, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("check spi flash idle fail!\n");
        return ret;
    }

    ret = sfc_cmd_write_en(spi, SPI_CMD_WRDISABLE, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("SFC write diable fail !\n");
    }

    return ret;
}

STATIC uint32_t sfc_cmd_write_program(uint32_t offset, uint8_t *src_temp, uint32_t bulk_cnt,
    uint32_t word_num, uint32_t byte_num, uint32_t chip_id)
{
    uint32_t ret = TEE_SUCCESS;

    while (bulk_cnt > 0) {
        ret = sfc_cmd_buf_write(offset, src_temp, SFC_CMD_MAX_WORD_WRITE_LEN * sizeof(uint32_t), chip_id);
        if (ret != TEE_SUCCESS) {
            tloge("sfc cmd write, bulk_cnt=0x%x failed!\n", bulk_cnt);
            return ret;
        }

        offset += SFC_CMD_MAX_WORD_WRITE_LEN * sizeof(uint32_t);
        src_temp += SFC_CMD_MAX_WORD_WRITE_LEN * sizeof(uint32_t);
        word_num -= SFC_CMD_MAX_WORD_WRITE_LEN;
        bulk_cnt--;
    }

    if (word_num % SFC_CMD_MAX_WORD_WRITE_LEN != 0) {
        ret = sfc_cmd_buf_write(offset, src_temp, word_num * sizeof(uint32_t), chip_id);
        if (ret != TEE_SUCCESS) {
            tloge("sfc cmd write, word_num=0x%x failed!\n", word_num);
            return ret;
        }
        offset += word_num * sizeof(uint32_t);
        src_temp += (uint64_t)(word_num * sizeof(uint32_t));
    }

    while (byte_num >= 1) {
        ret = sfc_cmd_one_byte_write(offset, src_temp, chip_id);
        if (ret != TEE_SUCCESS) {
            tloge("sfc cmd write, byte_num=0x%x failed!\n", byte_num);
            return ret;
        }
        offset += 1;
        src_temp += 1;
        byte_num--;
    }

    return ret;
}

STATIC uint32_t sfc_cmd_erase_sector(uint32_t offset, uint32_t chip_id)
{
    uint32_t ret;
    UN_SFC_CMD_CONFIG temp = {.u32 = 0};
    SPI_FLASH *spi = &(g_Sfc.spi_flash[g_SpiFlashIndex]);

    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    ret = spi_flash_idle(spi, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("erase spi flash idle fail, 0x%x.\n", ret);
        return ret;
    }

    ret = sfc_cmd_write_en(spi, SPI_CMD_WREN, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("enable sfc cmd write fail!\n");
        return ret;
    }

    write32(SFC_CMD_INS_OFFSET + chip_offset, SPI_CMD_SE);
    write32(SFC_CMD_ADDR_OFFSET + chip_offset, (offset & SFC_CMD_ADDR_MSK));

    temp.u32 = read32(SFC_CMD_CONFIG_OFFSET + chip_offset);
    temp.bits.addr_en = 1;
    temp.bits.data_en = 0;
    temp.bits.sel_cs = spi->cs;
    temp.bits.start = 1;
    write32(SFC_CMD_CONFIG_OFFSET + chip_offset, temp.u32);

    /* waiting operation be finished */
    ret = check_cmd_execute_status(chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("check cmd execute status fail!\n");
        goto err;
    }

    /* waiting operation to be finished */
    ret = spi_flash_idle(spi, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("wait spi flash idle fail!\n");
        goto err;
    }

err:
    if (sfc_cmd_write_en(spi, SPI_CMD_WRDISABLE, chip_id) != TEE_SUCCESS) {
        ret = TEE_ERROR_BAD_STATE;
        tloge("sfc cmd write disable fail!\n");
    }

    return ret;
}

STATIC uint32_t sfc_cmd_erase_write_sector_cnt(uint32_t rel_addr, uint32_t offset, uint32_t len)
{
    SPI_FLASH *spi = &g_Sfc.spi_flash[g_SpiFlashIndex];
    uint32_t sector_cnt;

    if ((len % (spi->sector_size)) != 0) {
        if (((offset - rel_addr + len) % (spi->sector_size)) != 0) {
            sector_cnt = (offset - rel_addr + len) / (spi->sector_size);
            sector_cnt++;
        } else {
            sector_cnt = (offset - rel_addr + len) / (spi->sector_size);
        }
    } else {
        sector_cnt = len / (spi->sector_size);
        if (offset % (spi->sector_size) != 0) { // not lie in boundary, should erase one more sector
            sector_cnt++;
        }
    }

    return sector_cnt;
}

STATIC uint32_t sfc_cmd_erase_write_real_addr(uint32_t offset)
{
    SPI_FLASH *spi = &g_Sfc.spi_flash[g_SpiFlashIndex];
    uint32_t rel_addr;

    if (offset % (spi->sector_size) != 0) {
        uint32_t sector_cnt = offset / (spi->sector_size);
        rel_addr = sector_cnt * (spi->sector_size);
    } else {
        rel_addr = offset;
    }

    return rel_addr;
}


STATIC uint32_t sfc_cmd_erase_write_operate(uint32_t sector_start_addr, uint32_t chip_id, uint32_t sector_size,
    uint8_t *src_start_addr)
{
    uint32_t ret;
    uint32_t bulk_cnt, word_num;

    ret = sfc_cmd_erase_sector(sector_start_addr, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("sfc cmd erase sector failed, addr=0x%x\n", sector_start_addr);
        return ret;
    }

    word_num = sector_size / sizeof(uint32_t);
    bulk_cnt = word_num / SFC_CMD_MAX_WORD_WRITE_LEN;

    ret = sfc_cmd_write_program(sector_start_addr, src_start_addr, bulk_cnt, word_num, 0, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("sfc cmd write sector failed!\n");
    }

    return ret;
}

STATIC uint32_t sfc_cmd_write_one_sector(uint32_t offset, uint8_t *buffer, uint32_t len,
    uint32_t sec_id, uint32_t sector_cnt, uint32_t chip_id)
{
    uint8_t *src_start_addr = NULL;
    SPI_FLASH *spi = &g_Sfc.spi_flash[g_SpiFlashIndex];
    uint32_t sector_start_addr;
    uint32_t copy_len;
    uint32_t first_sectorAddr = (offset / spi->sector_size) * spi->sector_size;
    uint32_t left = offset - first_sectorAddr;

    sector_start_addr = first_sectorAddr + (sec_id * (spi->sector_size));
    if (sec_id == 0) {
        /* first sector */
        if (sfc_bus_read(sector_start_addr, (uint8_t *)(uintptr_t)g_flash_buff[chip_id], spi->sector_size, chip_id) !=
            TEE_SUCCESS) {
            tloge("first sfc cmd write, bus read failed!\n");
            return TEE_ERROR_BAD_STATE;
        }

        copy_len = (len > (spi->sector_size - left)) ? (spi->sector_size - left) : len;
        if (memcpy_s((void *)(uintptr_t)(g_flash_buff[chip_id] + left), spi->sector_size - left,
            (const void *)buffer, copy_len) != TEE_SUCCESS) {
            tloge("memcpy_s failed!\n");
            return TEE_ERROR_BAD_STATE;
        }

        src_start_addr = (uint8_t *)(uintptr_t)g_flash_buff[chip_id];
    } else if (sec_id == (sector_cnt - 1)) {
        /* last sector */
        if (sfc_bus_read(sector_start_addr, (uint8_t *)(uintptr_t)g_flash_buff[chip_id], spi->sector_size, chip_id) !=
            TEE_SUCCESS) {
            tloge("last sfc cmd write, bus read failed!\n");
            return TEE_ERROR_BAD_STATE;
        }

        src_start_addr = buffer + (sec_id * (spi->sector_size)) - left;
        copy_len = len + left - (sec_id * (spi->sector_size));
        if (memcpy_s((void *)(uintptr_t)g_flash_buff[chip_id], spi->sector_size,
            (const void *)src_start_addr, copy_len) != TEE_SUCCESS) {
            tloge("memcpy_s failed!\n");
            return TEE_ERROR_BAD_STATE;
        }
        src_start_addr = (uint8_t *)(uintptr_t)g_flash_buff[chip_id];
    } else {
        /* middle sector */
        src_start_addr = buffer + (sec_id * (spi->sector_size)) - left;
    }

    return sfc_cmd_erase_write_operate(sector_start_addr, chip_id, spi->sector_size, src_start_addr);
}

uint32_t sfc_cmd_write(uint32_t offset, uint8_t *buffer, uint32_t len, uint32_t chip_id)
{
    uint32_t sector_cnt;
    uint32_t rel_addr;
    uint32_t sec_id;

    rel_addr = sfc_cmd_erase_write_real_addr(offset);
    sector_cnt = sfc_cmd_erase_write_sector_cnt(rel_addr, offset, len);

    for (sec_id = 0; sec_id < sector_cnt; sec_id++) {
        uint32_t ret = sfc_cmd_write_one_sector(offset, buffer, len, sec_id, sector_cnt, chip_id);
        if (ret != TEE_SUCCESS) {
            tloge("sfc cmd write failed, sec id = %u\n", sec_id);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

STATIC void set_cmd_ins_reg(uint32_t chip_id)
{
    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    write32(SFC_CMD_INS_OFFSET + chip_offset, SPI_CMD_READ);
}

uint32_t get_device_id(uint32_t *id, uint8_t cs, uint32_t chip_id)
{
    uint32_t ret;
    UN_SFC_CMD_CONFIG temp = {.u32 = 0};

    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    write32(SFC_CMD_INS_OFFSET + chip_offset, SPI_CMD_RDID);
    temp.bits.rw = SFC_CMD_CFG_READ;
    temp.bits.addr_en = 0;
    temp.bits.data_en = 1;
    temp.bits.data_cnt = SFC_CMD_DATA_CNT(CURR_DATA_CON);
    temp.bits.sel_cs = cs;
    temp.bits.start = 1;
    write32(SFC_CMD_CONFIG_OFFSET + chip_offset, temp.u32);

    ret = check_cmd_execute_status(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *id = read32(SFC_CMD_DATABUF_OFFSET + chip_offset);

    tlogw("sfc id, 0x%x.\n", *id);

    return TEE_SUCCESS;
}

STATIC uint32_t sfc_cmd_buf_read_cfg_set(uint32_t offset, uint32_t len, uint32_t chip_id)
{
    uint32_t ret;
    UN_SFC_CMD_CONFIG temp = {.u32 = 0};
    SPI_FLASH *spi = &g_Sfc.spi_flash[g_SpiFlashIndex];

    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    /* config regs reading way */
    set_cmd_ins_reg(chip_id);

    write32(SFC_CMD_ADDR_OFFSET + chip_offset, (offset & SFC_CMD_ADDR_MSK));
    temp.bits.rw = SFC_CMD_CFG_READ;
    temp.bits.addr_en = 1;
    temp.bits.data_en = 1;
    temp.bits.data_cnt = SFC_CMD_DATA_CNT(len);
    temp.bits.sel_cs = spi->cs;
    temp.bits.start = 1;
    write32(SFC_CMD_CONFIG_OFFSET + chip_offset, temp.u32);

    /* waiting execution finished */
    ret = check_cmd_execute_status(chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("read cfg set failed!\n");
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t sfc_cmd_buf_read_one_piece(uint32_t offset, uint8_t *buffer,
    uint32_t word_num, uint32_t chip_id)
{
    uint32_t ret;
    uint32_t i;
    uint32_t len;
    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    len = word_num * sizeof(uint32_t);
    ret = sfc_cmd_buf_read_cfg_set(offset, len, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("sfc cmd buffer read config set fail!\n");
        return ret;
    }

    for (i = 0; i < word_num; i++) {
        *(uint32_t *)(buffer + (i * sizeof(uint32_t))) =
            read32((uint64_t)(SFC_CMD_DATABUF_OFFSET + chip_offset + (i * sizeof(uint32_t))));
    }

    return TEE_SUCCESS;
}

STATIC uint32_t sfc_cmd_buf_read(uint32_t offset, uint8_t *buffer, uint32_t bulk_cnt,
    uint32_t left_word_num, uint32_t byte_num, uint32_t chip_id)
{
    uint32_t ret = TEE_SUCCESS;
    uint32_t j;
    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    for (j = 0; j < bulk_cnt; j++) {
        ret = sfc_cmd_buf_read_one_piece(offset, buffer, SFC_CMD_MAX_WORD_WRITE_LEN, chip_id);
        if (ret != TEE_SUCCESS) {
            tloge("sfc cmd buffer read one piece fail!\n");
            return ret;
        }

        offset += (SFC_CMD_MAX_WORD_WRITE_LEN * sizeof(uint32_t));
        buffer += (SFC_CMD_MAX_WORD_WRITE_LEN * sizeof(uint32_t));
    }

    if (left_word_num != 0) {
        ret = sfc_cmd_buf_read_one_piece(offset, buffer, left_word_num, chip_id);
        if (ret != TEE_SUCCESS) {
            tloge("sfc cmd buffer read one piece fail!\n");
            return ret;
        }

        offset += left_word_num * sizeof(uint32_t);
        buffer += left_word_num * sizeof(uint32_t);
    }

    if (byte_num > 0) {
        ret = sfc_cmd_buf_read_cfg_set(offset, byte_num, chip_id);
        if (ret != TEE_SUCCESS) {
            tloge("sfc cmd buffer read config set fail!\n");
            return ret;
        }

        j = read32((uintptr_t)(SFC_CMD_DATABUF_OFFSET + chip_offset));
        for (uint32_t i = 0; i < byte_num; i++) {
            *(uint8_t *)(buffer + i) = (uint8_t)(j & FLASH_INDEX_INITIAL_VALUE);
            j = (j >> BITS_PER_BYTE);
        }
    }

    return ret;
}

uint32_t sfc_cmd_read(uint32_t offset, uint8_t *buffer, uint32_t len, uint32_t chip_id)
{
    uint32_t bulk_cnt;
    uint32_t word_num;
    uint32_t left_word_num;
    uint32_t byte_num;

    word_num = len / sizeof(uint32_t);
    bulk_cnt = word_num / SFC_CMD_MAX_WORD_WRITE_LEN;
    left_word_num = word_num % SFC_CMD_MAX_WORD_WRITE_LEN;
    byte_num = len % sizeof(uint32_t);

    return sfc_cmd_buf_read(offset, buffer, bulk_cnt, left_word_num, byte_num, chip_id);
}

uint32_t sfc_bus_read(uint32_t offset, uint8_t *buffer, uint32_t len, uint32_t chip_id)
{
    uint64_t chip_offset = get_sfc_chip_offset(chip_id);

    read_from_io((void *)buffer, (const void *)(uintptr_t)(FLASH_BASE_ADDR + chip_offset + offset), len);

    return TEE_SUCCESS;
}

STATIC uint32_t id_compare(uint32_t id)
{
    uint32_t flash_num;
    uint32_t i;

    flash_num = sizeof(g_SpiFlashInstance) / sizeof(SPI_FLASH);
    for (i = 0; i < flash_num; i++) {
        uint32_t dev_id = (uint32_t)g_SpiFlashInstance[i].deviceID;
        uint32_t manufacture_id = g_SpiFlashInstance[i].manufactureID;

        if ((id & SPI_DEVID_MASK) == ((dev_id << BITS_PER_BYTE) + manufacture_id)) {
            g_SpiFlashIndex = g_SpiFlashInstance[i].Index;
            return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

void get_manu_device_id(uint32_t id, uint32_t *out_manu_id, uint32_t *out_device_id)
{
    uint32_t flash_num;
    uint32_t i;

    flash_num = sizeof(g_SpiFlashInstance) / sizeof(SPI_FLASH);

    for (i = 0; i < flash_num; i++) {
        uint32_t dev_id = (uint32_t)g_SpiFlashInstance[i].deviceID;
        if ((id & SPI_DEVID_MASK) == ((dev_id << BITS_PER_BYTE) + (g_SpiFlashInstance[i].manufactureID))) {
            *out_manu_id = (uint32_t)g_SpiFlashInstance[i].manufactureID;
            *out_device_id = (uint32_t)g_SpiFlashInstance[i].deviceID;
        }
    }
}

uint32_t get_spi_flash_index(uint32_t chip_id)
{
    uint32_t ret;
    uint32_t id = SPI_DEFAULT_ID;

    ret = get_device_id(&id, 0, chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("get device id failed, 0x%x.\n", id);
        return ret;
    }

    ret = id_compare(id);
    if (ret != TEE_SUCCESS) {
        tloge("flash id not found, 0x%x.\n", id);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t sfc_cmd_erase_sectors(uint32_t offset, uint32_t length, uint32_t chip_id)
{
    SPI_FLASH *spi = &(g_Sfc.spi_flash[g_SpiFlashIndex]);
    volatile uint32_t sector_id;
    uint32_t sector_start_addr = (offset / spi->sector_size) * spi->sector_size;
    uint32_t sector_cnt = length / (spi->sector_size);

    for (sector_id = 0; sector_id < sector_cnt; sector_id++) {
        uint32_t ret = sfc_cmd_erase_sector(sector_start_addr, chip_id);
        if (ret != TEE_SUCCESS) {
            tloge("sfc cmd erase sector id: %u failed!\n", sector_id);
            return ret;
        }
        sector_start_addr += spi->sector_size;
    }

    return TEE_SUCCESS;
}

uint32_t sfc_cmd_erase(uint32_t offset, uint32_t length, uint32_t chip_id)
{
    return sfc_cmd_erase_sectors(offset, length, chip_id);
}
