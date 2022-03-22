/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Call interface for TA, command register interface for msp
 * Create: 2020-10-27
 */

#ifndef MSP_TA_CHANNEL_H
#define MSP_TA_CHANNEL_H

#include <stdint.h>

#define PARMSIZE                64     /* Each parameter occupies 64 bytes */
#define PARMNUM                 6      /* num parameter is 5, The first one is the quantity */
#define PARMINFO_NUMS           8
#define MSP_TA_CHANNEL_OK       0x0

enum msp_chan_error_no {
    MSP_CHAN_CMD_ERROR        = 0xE0,
    MSP_CHAN_ECALL_CMD_ERROR  = 0xE1,
    MSP_CHAN_CPROC_CMD_ERROR  = 0xE2,
    MSP_CHAN_PARM_ERROR       = 0xE3,
    MSP_CHAN_DATA_ERROR       = 0xE4,
    MSP_CHAN_REGISTRY_ERROR   = 0xE5,
    MSP_CHAN_OVERFLOW_ERROR   = 0xE6,
};

/* sync with ca_code/msptest_main.h */
enum cmd_list {
    HIEPS_POWERON = 1,          /* hieps power on  */
    HIEPS_POWEROFF = 2,         /* hieps power off */
    HIEPS_LOOP_TEST = 3,        /* loop test */
    HIEPS_CA_TA_TEST = 4,       /* ca-->ta test */
    HIEPS_TA_DRIVES_TEST = 5,   /* ta-->teeos test */
    HIEPS_DRIVES_ATF_TEST = 6,  /* teeos-->atf test */
    HIEPS_ATF_KERNEL_TEST = 7,  /* atf-->kernel test */
    HIEPS_SECENG_TEST = 8,      /* seceng test */
    HIEPS_FACTORY_TEST = 9,     /* factory test */
    HIEPS_ECALL = 10,           /* hieps ecall test */
    HIEPS_HELP  = 11,           /* hieps help */
    COMMON_TEST = 12,           /* General test cmd */
};

struct msp_chan_parms {
    char parm[PARMNUM][PARMSIZE];
    uint32_t parm_info[PARMINFO_NUMS];
};

uint32_t msp_chan_rgst_callback(uint32_t cmd,
                                uint32_t (*cb_func)(char *iodata, const struct msp_chan_parms *chan_parms));
uint32_t msp_chan_rgst_cproc_func(const char *desc,
                                  uint32_t (*cproc_func)(const struct msp_chan_parms *chan_parms, char *iodata));
uint32_t msp_chan_rgst_ecall_func(const char *desc,
                                  uint32_t (*ecall_func)(const struct msp_chan_parms *chan_parms));

#endif /* MSP_TA_CHANNEL_H */
