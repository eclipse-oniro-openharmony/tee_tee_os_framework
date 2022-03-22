/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description:chip platform adapter driver for tui tp
 * Author: chenpuwang
 * Create: 2020-09-21
 */

#include "tui_touchscreen_platform.h"
#include <stdlib.h>
#include <stdio.h>
#include "securec.h"
#include "sre_hwi.h"
#include "drv_fwk.h"
#include <ipc_call.h>
#include "tui_touchscreen_panel.h"

static struct mt_chip_conf g_tp_spi_chip_config;
static struct spi_user_conf g_tp_spi_user_conf;
static void (*irq_handler)(void *) = NULL;
/*
 * irq
 */
static int32_t tui_tp_set_irq_to_secure(void)
{
    uint32_t gpio_num = tui_tp_get_cur_gpio_num();
    uint32_t irq_num = tui_tp_get_cur_irq_num();
    uint32_t smc_ret = 0;
    int32_t ret;

    ret = msee_smc_call(MTK_SIP_TEE_SEC_DEINT_CONFIGURE_AARCH32, gpio_num, irq_num, 0, &smc_ret);
    tloge("%s:ret = %d,gpio_num = %u,irq_num = %u, smc_ret =%u\n", __func__,
        ret, gpio_num, irq_num, smc_ret);
    return ret;
}

static uint32_t tui_tp_set_irq_to_unsecure(void)
{
    uint32_t gpio_num = tui_tp_get_cur_gpio_num();
    uint32_t irq_num = tui_tp_get_cur_irq_num();
    uint32_t smc_ret;
    int32_t ret;

    tloge("SRE_HwiDelete in\n");
    ret = (int32_t)SRE_HwiDisable(irq_num);
    if (ret != 0)
        tloge("SRE_HwiDelete error\n");
    ret = (int32_t)SRE_HwiDelete(irq_num);
    if (ret != 0)
        tloge("SRE_HwiDelete error\n");
    tlogi("SRE_HwiDelete out\n");

    ret = msee_smc_call(MTK_SIP_TEE_SEC_DEINT_RELEASE_AARCH32, gpio_num,
        irq_num, 0, &smc_ret);
    tloge("%s:ret = %d,gpio_num = %u,irq_num = %u, smc_ret =%u\n", __func__,
        ret, gpio_num, irq_num, smc_ret);

    return ret;
}

uint32_t tui_tp_get_cur_irq_flags(int32_t type)
{
    uint32_t irqflags = EINTF_TRIGGER_LEVEL_FALLING;

    switch (type) {
    case THP_GOODIX_DEVICE:
    case THP_SYNA_DEVICE:
        irqflags = EINTF_TRIGGER_LEVEL_LOW;
        break;
    default:
        irqflags = EINTF_TRIGGER_LEVEL_FALLING;
    }

    return irqflags;
}

uint32_t tui_tp_get_cur_irq_num(void)
{
    uint32_t irq_num = 0;

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6885)
    irq_num = 248; /* tp irq num for mt6885 */
#endif
    return irq_num;
}

void tui_tp_clear_irq(void)
{
    uint32_t gpio_num = tui_tp_get_cur_gpio_num();
    uint32_t smc_ret = 0;
    int32_t ret;

    ret = msee_smc_call(MTK_SIP_TEE_SEC_DEINT_ACK_AARCH32, gpio_num, 0, 0, &smc_ret);
    tloge("%s:ret = %d,smc_ret =%u\n", __func__, ret, smc_ret);
    return;
}

void tui_tp_irq_conctrl(int32_t enable)
{
    int32_t ret;
    uint32_t irq_num = tui_tp_get_cur_irq_num();

    tloge("%s: %u\n", __func__, enable);
    irq_lock();
    if (enable) {
        if (irq_handler == NULL) {
            tloge("irq_handler is null\n");
            return;
        }
        ret = (int)SRE_HwiCreate(irq_num, 0x0, 0, irq_handler, 0);
        if (ret != 0) {
            irq_unlock();
            tloge("SRE_HwiCreate error\n");
            return;
        }
        ret = (int)SRE_HwiEnable(irq_num);
        if (ret != 0)
            tloge("SRE_HwiEnable error\n");
    } else {
        ret = (int)SRE_HwiDisable(irq_num);
        if (ret != 0) {
            tloge("SRE_HwiDisable error\n");
            irq_unlock();
            return;
        }
        ret = (int)SRE_HwiDelete(irq_num);
        if (ret != 0)
            tloge("SRE_HwiDelete error\n");
    }
    irq_unlock();
    return;
}

int32_t tui_tp_irq_request(uint32_t gpio_id, void (*handler)(void *),
    uint32_t irqflags, void *data)
{
    uint32_t irq_num = tui_tp_get_cur_irq_num();
    int32_t ret;

    irq_handler = handler;
    tloge("%s: %u, %x\n", __func__, irqflags, data);
    irq_lock();
    ret = (int)SRE_HwiCreate(irq_num, 0, 0, handler, 0);
    if (ret != 0) {
        tloge("SRE_HwiCreate error\n");
        irq_unlock();
        return ret;
    }
    ret = (int)SRE_HwiEnable(irq_num);
    if (ret != 0) {
        tloge("SRE_HwiEnable error\n");
        irq_unlock();
        return ret;
    }
    tloge("%s: out\n", __func__);
    irq_unlock();
    return 0;
}

/*
 * GPIO
 */
uint32_t tui_tp_get_cur_gpio_num(void)
{
    uint32_t gpio_num = 0;

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6885)
    gpio_num = 21; /* tp gpio num for mt6885 */
#endif
    return gpio_num;
}

uint32_t tui_tp_get_gpio_value(uint32_t gpio_num)
{
    tlogd("%s: %u out\n", __func__, gpio_num);
    return 0;
}

/*
 * spi
 */
uint32_t tui_tp_get_cur_spi_num(void)
{
    uint32_t spi_num = 0xff; /* default spi num 0xff is invalid */

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6885)
    spi_num = 1;  /* tp spi num for mt6885 */
#endif
    return spi_num;
}

static int32_t tp_set_spi_dma_permisson(enum devapc_master_req_type devapc_master_req,
    enum devapc_protect_on_off devapc_protect, enum spi_protect_index spi)
{
    int32_t ret;
    uint64_t smc_ret = 0;
    struct hieps_smc_atf hieps_smc_data = {
        .x1 = devapc_master_req,
        .x2 = devapc_protect,
        .x3 = spi,
        .x4 = (uint64_t)&smc_ret,
    };

    ret = __smc_switch_to_atf(MTK_SIP_TEE_HAL_MASTER_TRANS_AARCH64,
        &hieps_smc_data);
    if (ret != 0) {
        tloge("TEEOS to ATF spi dma failed! ret = 0x%x, smc_ret = 0x%x\n", ret,
            smc_ret);
        return -1;
    }
    return 0;
}

static void tui_tp_spi_default_config(struct mt_chip_conf *chip_config)
{
    /* set spi default timeing config */
    chip_config->setup_time = 10;
    chip_config->hold_time = 10;
    chip_config->high_time = 12;
    chip_config->low_time = 12;
    chip_config->cs_idle_time = 2;
    chip_config->ulthgh_thrsh = 0;

    /* set spi default little endian */
    chip_config->rx_mlsb = 1;
    chip_config->tx_mlsb = 1;
    chip_config->tx_endian = 0;
    chip_config->rx_endian = 0;

    /* set spi default mode 0 */
    chip_config->cpol = 0;
    chip_config->cpha = 0;
    chip_config->com_mod = 0;
    chip_config->pause = 0;
    chip_config->finish_intr = 1;
    chip_config->deassert = 0;
    chip_config->ulthigh = 0;
    chip_config->tckdly = 0;
}

static int32_t ts_spi_enter_secure_os(uint32_t bus_id)
{
    int32_t ret;
    uint32_t smc_ret = 0;

    tloge("%s:bus_id = %u enter\n", __func__, bus_id);

    /* set spi to secure status */
    ret = msee_smc_call(MTK_SIP_TEE_HAL_APC_SET_AARCH32, DEVAPC_MODULE_REQ_SPI,
        DEVAPC_PROTECT_ENABLE, bus_id, &smc_ret);
    tloge("%s:ret = %d,smc_ret =%u\n", __func__, ret, smc_ret);

    /* init spi config */
    (void)memset_s(&g_tp_spi_chip_config, sizeof(g_tp_spi_chip_config), 0,
        sizeof(g_tp_spi_chip_config));
    (void)memset_s(&g_tp_spi_user_conf, sizeof(g_tp_spi_user_conf), 0,
        sizeof(g_tp_spi_user_conf));
    tui_tp_spi_default_config(&g_tp_spi_chip_config);

    ret = spi_init(bus_id, get_spi_dma_addr(), &g_tp_spi_user_conf);
    if (ret) {
        tloge("spi_init failed\n");
        return -1;
    }
    tloge("%s:success\n", __func__);
    return 0;
}

int32_t ts_spi_sync(uint16_t size, uint8_t *tx_buff, uint8_t *rx_buff)
{
    int32_t ret;

    tp_set_spi_dma_permisson(DEVAPC_MASTER_REQ_SPI, DEVAPC_PROTECT_ENABLE, 1);
    g_tp_spi_user_conf.flag = 1;
    ret = spi_send(tx_buff, rx_buff, size, &g_tp_spi_chip_config,
        &g_tp_spi_user_conf);
    if (ret)
        tloge("spi_send failed\n");
    tp_set_spi_dma_permisson(DEVAPC_MASTER_REQ_SPI, DEVAPC_PROTECT_DISABLE, 1);
    return 0;
}

int32_t tp_enter_secure_os_config(void)
{
    int32_t ret;

    /* irq config */
    ret = tui_tp_set_irq_to_secure();
    if (ret < 0) {
        tloge("tui_tp_set_irq_to_secure failed, ret =%u\n", ret);
        return ret;
    }
    /* spi config */
    ret = ts_spi_enter_secure_os(1);
    if (ret < 0) {
        tloge("ts_spi_enter_secure_os failed, ret =%d\n", ret);
        return ret;
    }
    tloge("%s:out\n", __func__);
    return ret;
}

static int32_t ts_spi_exit_secure_os(uint32_t bus_id)
{
    uint32_t ret;
    uint32_t smc_ret = 0;

    tloge("%s:bus_id = %u enter\n", __func__, bus_id);

    /* set spi to unsecure status */
    ret = msee_smc_call(MTK_SIP_TEE_HAL_APC_SET_AARCH32, DEVAPC_MODULE_REQ_SPI,
        DEVAPC_PROTECT_DISABLE, bus_id, &smc_ret);
    tloge("%s:ret= %u, smc_ret = %u\n", __func__, ret, smc_ret);
    spi_exit(&g_tp_spi_user_conf);
    return 0;
}

void tp_exit_secure_os_config(void)
{
    int32_t ret;
    int32_t bus_id = tui_tp_get_cur_spi_num();

    /* irq config */
    ret = tui_tp_set_irq_to_unsecure();
    if (ret < 0)
        tloge("%s: failed, ret =%u\n", __func__, ret);
    /* spi config */
    ts_spi_exit_secure_os(bus_id);
    if (ret < 0)
        tloge("%s: failed, ret =%u\n", __func__, ret);
}
