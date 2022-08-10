/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file for driver params
 * Create: 2020-04-18
 */
#ifndef PLATDRV_INCLUDE_DRV_PARAM_TYPE_H
#define PLATDRV_INCLUDE_DRV_PARAM_TYPE_H

struct drv_param {
    uint64_t args; /* pointer to args addr */
    uint64_t data;
    uint64_t rdata;
    uint64_t rdata_len;
    uint32_t uid;
    uint32_t pid;
    uint64_t job_handler;
    uint32_t caller_pid;
};
#endif
