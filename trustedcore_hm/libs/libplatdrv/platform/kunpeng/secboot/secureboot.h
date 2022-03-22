/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secboot for get oemkey on kunpeng platform
 * Author: zhanglinhao zhanglinhao@huawei.com
 * Create: 2020-06
 */
#ifndef KUNPENG_DRV_SECUREBOOT_H
#define KUNPENG_DRV_SECUREBOOT_H

#include <sre_typedef.h>

#define SECBOOT_RET_SUCCESS     0
#define SECBOOT_RET_PARAM_ERROR 0xFFFFFF02
#define SECBOOT_RET_FAILURE     0xFFFFFFFF
#define SECBOOT_MAGIC_NUM       0x55AA55AA
#define RES_NUM                 52
#define OEMKEY_SIZE             16
#define SGLIST_MAX_LEN          16
#define SHARED_MEM_SECBOOT       "tasksecboot"
#define SHARED_MEM_MEMORY_SGLIST "tasksiglist"
struct tee_secureinfo {
    uint32_t  head_magic;   /* magic number: 4 */
    uint8_t   provision_key[OEMKEY_SIZE]; /* provision key: 1*16 */
    uint8_t   reserved[RES_NUM]; /* reserved bytes 52 */
    uint32_t  tail_magic; /* magic number: 4 */
} __attribute__((__packed__));

struct memory_block {
    uint64_t start;
    uint64_t size;
};

struct memory_sglist {
    uint32_t magic;
    uint64_t num;
    struct memory_block memory[SGLIST_MAX_LEN];
};

#endif
