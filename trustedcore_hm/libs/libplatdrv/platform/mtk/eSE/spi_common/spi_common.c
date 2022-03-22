/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: eSE SPI comon opration.
 * Author: w00271044
 * Create: 2020-07-28
 */

#include <stddef.h>
#include <errno.h>
#include "spi.h"
#include "tee_log.h"
#include <memory.h>
#include "securec.h"
#include "sre_syscall.h"
#include "spi_common.h"

struct mt_chip_conf g_ese_spi_chip_config;
struct spi_user_conf g_ese_spi_user_conf;

static void ese_spi_config(struct mt_chip_conf *chip_config)
{
    // chip select setup time = (CS_SETUP_COUNT + 1) * CLK_PERIOD
    // where CLK_PERIOD is the cycle time of the clock the spi engine adopts.
    // CLK_PERIOD = 1 / get_spi_speed(), the min setup time for ese = 20us
    chip_config->setup_time = 115;
    chip_config->hold_time = 10;
    chip_config->high_time = 12;
    chip_config->low_time = 12;
    chip_config->cs_idle_time = 2;
    chip_config->ulthgh_thrsh = 0;
    chip_config->cpol = SPI_CPOL_0;
    chip_config->cpha = SPI_CPHA_0;
    chip_config->rx_mlsb = SPI_MSB;
    chip_config->tx_mlsb = SPI_MSB;
    chip_config->tx_endian = SPI_LENDIAN;
    chip_config->rx_endian = SPI_LENDIAN;
    chip_config->com_mod = DMA_TRANSFER;
    chip_config->pause = PAUSE_MODE_DISABLE;
    chip_config->finish_intr = FINISH_INTR_EN;
    chip_config->deassert = DEASSERT_DISABLE;
    chip_config->ulthigh = ULTRA_HIGH_DISABLE;
    chip_config->tckdly = TICK_DLY0;
}

int init_ese_spi(uint8_t spi_bus)
{
    int ret;
    tloge("init_ese_spi enter");
    memset_s(&g_ese_spi_chip_config, sizeof(g_ese_spi_chip_config),
        0, sizeof(g_ese_spi_chip_config));
    memset_s(&g_ese_spi_user_conf, sizeof(g_ese_spi_user_conf),
        0, sizeof(g_ese_spi_user_conf));
    ese_spi_config(&g_ese_spi_chip_config);
    enable_spi5_clk();
    uint64_t spi_dma_phy_addr = get_spi_dma_addr();
    if (spi_dma_phy_addr == INVALID_DMA_ADDRESS) {
        tloge("se dummy get spi_dma_phy_addr failed\n");
        return ESE_RET_FAIL;
    }
    ret = spi_init(spi_bus, spi_dma_phy_addr + 0x80000, &g_ese_spi_user_conf);
    disable_spi5_clk();
    tloge("init_ese_spi exit, ret = %d", ret);
    return ret;
}

int ese_spi_driver_value_init(void **tx_buff, void **rx_buff, uint32_t align_buff_size)
{
    if (align_buff_size <= 0) {
        tloge("malloc size do not is 0\n");
        return ESE_RET_FAIL;
    }

    *tx_buff = malloc(align_buff_size);
    if (*tx_buff == NULL) {
        tloge("tx_buff malloc failed\n");
        return ESE_RET_FAIL;
    }
    (void)memset_s(*tx_buff, align_buff_size, 0, align_buff_size);

    *rx_buff = malloc(align_buff_size);
    if (*rx_buff == NULL) {
        tloge("rx_buff malloc failed\n");
        return ESE_RET_FAIL;
    }
    (void)memset_s(*rx_buff, align_buff_size, 0, align_buff_size);
    return ESE_RET_SUCCESS;
}

int ese_set_spi_dma_permisson(enum devapc_master_req_type devapc_master_req,
    enum devapc_protect_on_off devapc_protect, enum spi_protect_index spi)
{
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6873) || \
    (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6853) || \
    (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6885)
    int ret;
    uint64_t smc_ret=0;
    struct hieps_smc_atf hieps_smc_data = {
        .x1 = devapc_master_req,
        .x2 = devapc_protect,
        .x3 = spi,
        .x4 = (uint64_t)&smc_ret,
    };
    ret = __smc_switch_to_atf(MTK_SIP_TEE_HAL_MASTER_TRANS_AARCH64, &hieps_smc_data);
    if (ret != ESE_RET_SUCCESS) {
        tloge("TEEOS to ATF spi dma failed! ret = 0x%x, smc_ret = 0x%x\n", ret, smc_ret);
        return ESE_RET_FAIL;
    }
    return ESE_RET_SUCCESS;
#else
    return ESE_RET_SUCCESS;
#endif
}

int ese_driver_spi_full_duplex(struct spi_transaction_info *write_info, struct spi_transaction_info *read_info)
{
    int ret;
    uint32_t tx_bytes;
    uint32_t rx_bytes = 0;
    void *tx_buff = NULL;
    void *rx_buff = NULL;
    uint32_t align_buff_size;
    /*
     * we use 4Byte align size to avoid memory occupied when spi copy-to-user
     * and copy-from-user.(spi copy must be 4B align)
     */
    if (write_info == NULL) {
        tloge("write_info not is NULL\n");
        return ESE_RET_FAIL;
    }
    tx_bytes = write_info->reg_len + write_info->buf_len;
    rx_bytes = (read_info != NULL) ? (read_info->reg_len + read_info->buf_len) : rx_bytes;

    align_buff_size = SPI_ALIGN_4_SIZE(tx_bytes + rx_bytes);

    ret = ese_spi_driver_value_init(&tx_buff, &rx_buff, align_buff_size); // init tx and rx
    if (ret != ESE_RET_SUCCESS)
        goto out;
    if (write_info->reg_addr != NULL) {
        ret = memcpy_s((uint8_t *)tx_buff, align_buff_size, write_info->reg_addr, write_info->reg_len);
        ese_check_ret(ret);
    } else if (write_info->reg_len != 0) {
        tloge("ese_driver_spi_full_duplex failed reg_len != 0\n");
        ret = ESE_RET_FAIL;
        goto out;
    }
    if (write_info->buf_addr == NULL)
        ret = memset_s((uint8_t *)tx_buff + write_info->reg_len,
                       align_buff_size - write_info->reg_len, 0, write_info->buf_len);
    else
        ret = memcpy_s((uint8_t *)tx_buff + write_info->reg_len,
                       align_buff_size - write_info->reg_len, write_info->buf_addr, write_info->buf_len);
    ese_check_ret(ret);
    ese_set_spi_dma_permisson(DEVAPC_MASTER_REQ_SPI, DEVAPC_PROTECT_ENABLE, SPI5);
    enable_spi5_clk();
    g_ese_spi_user_conf.flag = 1; // 1:end flag
    ret = spi_send(tx_buff, rx_buff, tx_bytes + rx_bytes, &g_ese_spi_chip_config, &g_ese_spi_user_conf);
    if (ret != ESE_RET_SUCCESS) {
        tloge("spi_send failed ret = %d\n", ret);
        ret = ESE_RET_FAIL;
        goto out;
    }
    if (read_info != NULL) {
        ret = memcpy_s(read_info->buf_addr, read_info->buf_len, (uint8_t *)rx_buff + tx_bytes, read_info->buf_len);
        ese_check_ret(ret);
    }
out:
    disable_spi5_clk();
    ese_set_spi_dma_permisson(DEVAPC_MASTER_REQ_SPI, DEVAPC_PROTECT_DISABLE, SPI5);
    pointer_free(tx_buff);
    pointer_free(rx_buff);
    return ret;
}
