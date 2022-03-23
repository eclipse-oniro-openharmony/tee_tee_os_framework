/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Drivers for seplat dts parse.
 * Create: 2021/01/03
 */

#include "seplat_status.h"
#include "seplat_errno.h"
#include <fdt_handler.h>
#include <hmlog.h>
#include <libfdt.h>
#include <string.h>
#include <types.h>

#define SEPLAT_THIS_MODULE              SEPLAT_MODULE_STATUS

#define SEPLAT_STATUS_OK                "ok"

/* Define module err code */
enum {
    SEPLAT_STATUS_FWDT_ADDR_ERR           = SEPLAT_ERRCODE(0x00),
    SEPLAT_STATUS_FIND_NODE_ERR           = SEPLAT_ERRCODE(0x00),
    SEPLAT_STATUS_FIND_STATUS_ERR         = SEPLAT_ERRCODE(0x00),
};

uint32_t seplat_get_dts_status(void)
{
    uintptr_t dtb_addr;
    int32_t offset;
    uint32_t status = SEPLAT_DTS_ABSENCE;
    const struct fdt_property *property = NULL;
    const char *node_status = NULL;
    const char *property_string = "status";
    const char *compatible_string = "hisilicon,seplat";

    dtb_addr = get_fwdt_handler();
    if (!dtb_addr) {
        SEPLAT_PRINT("%s:get fwdt addr failed!\n", __func__);
        return SEPLAT_STATUS_FWDT_ADDR_ERR;
    }

    offset = fdt_node_offset_by_compatible((void *)dtb_addr,
                                            0,
                                            compatible_string);
    if (offset < 0) {
        SEPLAT_PRINT("%s:cannot find seplat node:%d!\n", __func__, offset);
        return SEPLAT_STATUS_FIND_NODE_ERR;
    }

    property = fdt_get_property((void *)dtb_addr, offset, property_string, NULL);
    if (!property) {
        SEPLAT_PRINT("%s:cannot find seplat status!\n", __func__);
        return SEPLAT_STATUS_FIND_STATUS_ERR;
    }

    node_status = (const char *)property->data;
    SEPLAT_PRINT("%s:status is %s\n", __func__, node_status);

    if (strncmp(node_status, SEPLAT_STATUS_OK, strlen(SEPLAT_STATUS_OK)) == 0)
        status = SEPLAT_DTS_EXIST;

    return status;
}
