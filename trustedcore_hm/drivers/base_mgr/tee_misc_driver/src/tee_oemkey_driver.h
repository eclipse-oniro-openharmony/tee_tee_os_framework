/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: get oemkey from shared mem

 * Create: 2022-01-13
 */
#ifndef KUNPENG_DRV_SECUREBOOT_H
#define KUNPENG_DRV_SECUREBOOT_H

#include "tee_driver_module.h"
#define OEMKEY_MAGIC_NUM        0x55AA55AA
#define RES_NUM                 52
#define OEMKEY_SIZE             16
#define SHARED_MEM_OEMKEY       "oemkey"

#define DATA_SIZE_MAX           512

int32_t get_oemkey_info(unsigned long args, uint32_t args_len);

struct tee_oemkey_info {
    uint32_t  head_magic;   /* magic number: 4 */
    uint8_t   provision_key[OEMKEY_SIZE]; /* provision key: 1*16 */
    uint8_t   reserved[RES_NUM]; /* reserved bytes 52 */
    uint32_t  tail_magic; /* magic number: 4 */
} __attribute__((__packed__));

#endif
