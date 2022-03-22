/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: Provides abstract seplat data_link interfaces for bl2.
 * Create: 2020/12/05
 */

#include "seplat_data_link.h"
#include "dl_init.h"
#include "seplat_common.h"
#include "dl_service.h"
#include <fdt_handler.h>
#include <libfdt.h>
#include <string.h>
#include "types.h"
#include "sre_typedef.h"
#include "seplat_hal_spi.h"
#include "seplat_hal_log.h"
#include "seplat_errno.h"
#include "seplat_dl_test_entry.h"

#define SEPLAT_THIS_MODULE SEPLAT_MODULE_DATA_LINK
#define SEPLAT_ERROR_TAG "[SEPLAT_DL]"

#define SEPLAT_DTS_INTERFACT           "interface"
#define SEPLAT_DTS_RST_GPIO            "reset_gpio"
#define SEPLAT_DTS_COMPATIBLE          "hisilicon,seplat"

#define RESET_GPIO         55
#define DL_SPI_0_CS_GPIO    7
#define SEPLAT_INTERFACE_IO_TYPE        24
#define SEPLAT_INTERFACE_IO_NUM         16
#define SEPLAT_INTERFACE_IO_2_ID        8
#define SEPLAT_INTERFACE_IO_1_ID        0
#define SEPLAT_INTERFACE_IO_MASK        0xFF

#define SEPLAT_INTERFACE_MAX_IO_NUM     2
#define SEPLAT_INTERFACE_IO_2           2
#define SEPLAT_INTERFACE_IO_1           1

struct seplat_dl_io_config {
    uint32_t type;
    uint32_t num;
    uint32_t id1;
    uint32_t id2;
};

enum seplat_dl_io_type {
    SEPLAT_DL_IO_I2C = 0x5A,
    SEPLAT_DL_IO_SPI = 0xA5,
};

static int32_t seplat_get_io_info(uint32_t *interface, uint32_t *rst_gpio)
{
    uintptr_t dtb_addr;
    int32_t offset;
    const struct fdt_property *property = NULL;
    const uint32_t *node_value = NULL;

    dtb_addr = get_fwdt_handler();
    if (!dtb_addr) {
        hal_print_error("%s:get fwdt addr failed!\n", __func__);
        return SEPLAT_ERRCODE(SEPLAT_ERRCODE_DATA_LINK_GET_FDT_HANDLE_ERR);
    }

    offset = fdt_node_offset_by_compatible((void *)dtb_addr, 0, SEPLAT_DTS_COMPATIBLE);
    if (offset < 0) {
        hal_print_error("%s:cannot find seplat node:%d!\n", __func__, offset);
        return SEPLAT_ERRCODE(SEPLAT_ERRCODE_DATA_LINK_FIND_NODE_ERR);
    }

    property = fdt_get_property((void *)dtb_addr, offset, SEPLAT_DTS_INTERFACT, NULL);
    if (!property) {
        hal_print_error("%s:cannot find seplat interface!\n", __func__);
        return SEPLAT_ERRCODE(SEPLAT_ERRCODE_DATA_LINK_FIND_INTERFACE_ERR);
    }

    node_value = (const uint32_t *)property->data;
    *interface = fdt32_to_cpu(*node_value);

    property = fdt_get_property((void *)dtb_addr, offset, SEPLAT_DTS_RST_GPIO, NULL);
    if (!property) {
        hal_print_error("%s:cannot find seplat rst gpio!\n", __func__);
        return SEPLAT_ERRCODE(SEPLAT_ERRCODE_DATA_LINK_FIND_RST_GPIO_ERR);
    }
    node_value = (const uint32_t *)property->data;
    *rst_gpio = fdt32_to_cpu(*node_value);

    return SEPLAT_OK;
}

static void seplat_dl_interface_decode(uint32_t interface, struct seplat_dl_io_config *io)
{
    io->type = (interface >> SEPLAT_INTERFACE_IO_TYPE) & SEPLAT_INTERFACE_IO_MASK;
    io->num = (interface >> SEPLAT_INTERFACE_IO_NUM) & SEPLAT_INTERFACE_IO_MASK;
    io->id1 = (interface >> SEPLAT_INTERFACE_IO_1_ID) & SEPLAT_INTERFACE_IO_MASK;
    io->id2 = (interface >> SEPLAT_INTERFACE_IO_2_ID) & SEPLAT_INTERFACE_IO_MASK;
}

static int32_t seplat_dl_get_init_strategy(uint32_t io_type, uint32_t io_num, uint32_t *strategy)
{
    if (io_type != SEPLAT_DL_IO_SPI) {
        hal_print_error("%s interface type err %x\n", __func__, io_type);
        return SEPLAT_ERRCODE(SEPLAT_ERRCODE_DL_INTERFACE_IO_TYPE_ERR);
    }
    if (io_num > SEPLAT_INTERFACE_MAX_IO_NUM) {
        hal_print_error("%s interface num err %x\n", __func__, io_num);
        return SEPLAT_ERRCODE(SEPLAT_ERRCODE_DL_INTERFACE_IO_NUM_ERR);
    }
    if (io_num == SEPLAT_INTERFACE_IO_1)
        *strategy = DL_INIT_STRATEGY_0;
    else
        *strategy = DL_INIT_STRATEGY_1;
    return SEPLAT_OK;
}

static int32_t seplat_data_link_common_init(struct seplat_dl_io_config *io)
{
    int32_t ret;
    uint32_t rst_gpio;
    uint32_t interface;

    ret = seplat_get_io_info(&interface, &rst_gpio);
    IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "seplat get io fail %x\n", ret);
    if (interface == 0) {
        hal_print_error("%s interface not init\n", __func__);
        return SEPLAT_ERRCODE(SEPLAT_ERRCODE_DL_INTERFACE_NOT_INITED);
    }

    dl_service_rst_io_init(rst_gpio);
    seplat_dl_interface_decode(interface, io);

    ret = hal_spi0_init(io->id1);
    IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "spi0 %u init fail %x\n", io->id1, ret);

    return SEPLAT_OK;
}

int32_t seplat_data_link_init(void)
{
    int32_t ret;
    struct seplat_dl_io_config dl_io = {0};
    uint32_t init_strategy;

    ret = seplat_data_link_common_init(&dl_io);
    IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "dl common init fail %x\n", ret);

    ret = seplat_dl_get_init_strategy(dl_io.type, dl_io.num, &init_strategy);
    IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "get init s fail %x\n", ret);

    if (dl_io.num == SEPLAT_INTERFACE_IO_2) {
        ret = hal_spi1_init(dl_io.id2);
        IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "spi0 %u init fail %x\n", dl_io.id1, ret);
    }
    ret = dl_channel_init(init_strategy);
    IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "channel init fail %x\n", ret);

    ret = dl_ctx_init();
    IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "ctx init fail %x\n", ret);

    ret = dl_service_init();
    IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "service init err %x\n", ret);

    if (dl_test_callback_init() != SEPLAT_OK)
        hal_print_error("%s test init err\n", __func__);

    hal_print_error("%s ok\n", __func__);
    return SRE_OK;
}

int32_t seplat_data_trans(uint8_t *cmd, uint32_t cmd_len, uint8_t *rsp, uint32_t rsp_len, uint32_t *data_len)
{
    struct dl_msg seplat_req = { .buf = cmd, .buf_len = cmd_len, .data_len = cmd_len };
    struct dl_msg seplat_rsp = { .buf = rsp, .buf_len = rsp_len, .data_len = 0 };
    struct dl_channel_index channel_id;
    int32_t ret;

    if (!data_len) {
        hal_print_error("%s data len is null\n");
        return SEPLAT_ERRCODE(SEPLAT_ERRCODE_DATA_LINK_DATA_TRANS_OUTLEN_NULL);
    }

    channel_id.service = DL_SYSTEM_SECURITY;
    channel_id.prior = DL_CHANNEL_NORMAL_LEVEL;

    hal_print_trace("seplat send %u\n", cmd_len);
    seplat_trace_hex(cmd, cmd_len);

    ret = dl_7816_data_trans(&seplat_req, &seplat_rsp, channel_id);
    IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "normal data trans err %x\n", ret);
    *data_len = seplat_rsp.data_len;

    hal_print_trace("seplat recv %u\n", *data_len);
    seplat_trace_hex(rsp, *data_len);

    return SRE_OK;
}

int32_t seplat_chip_reset(uint32_t type)
{
    struct dl_channel_index channel_id;
    int32_t ret;

    channel_id.service = DL_SYSTEM_SECURITY;
    channel_id.prior = DL_CHANNEL_NORMAL_LEVEL;

    ret = dl_chip_reset(type, channel_id);
    IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "%x reset err %x\n", type, ret);

    return SRE_OK;
}

int32_t seplat_power_save(uint8_t vote_id, uint8_t mode)
{
    struct dl_channel_index channel_id;
    int32_t ret;

    channel_id.service = DL_SYSTEM_SECURITY;
    channel_id.prior = DL_CHANNEL_NORMAL_LEVEL;

    ret = dl_power_save(vote_id, mode, channel_id);
    IF_TRUE_RETURN_WITHLOG((ret != SEPLAT_OK), ret, "%x %x power save err %x\n", vote_id, mode, ret);

    return SRE_OK;
}
