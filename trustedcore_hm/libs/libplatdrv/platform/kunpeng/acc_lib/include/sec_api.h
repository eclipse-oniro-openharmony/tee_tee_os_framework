/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: the head file of sec api function
* Author: chenyao
* Create: 2019/12/30
*/
#ifndef __SEC_API_H__
#define __SEC_API_H__

#include <sys/hm_types.h>

/* Test addr */
#define SEC_BD_SIZE                     128

#define SEC_HAS_INITIALIZED             0x5A5A5A5A
#define SHIFT_LEN_32                    32
#define HUK_INPUT_KEY_LEN               32
#define HUK_OUTPUT_KEY_LEN              16
#define HUK_CNT_NUMBER                  10000
#define MAX_HUK_KEY_LEN                 16
#define IMGK2_INPUT_KEY_LEN             32
#define IMGK2_OUTPUT_KEY_LEN            16
#define IMGK2_INPUT_SALT_LEN            32
#define IMGK2_CNT_NUMBER                10000
#define MAX_HUK_KEY_LEN                 16

#define MAX_SALT_LEN                    256
#define SEC_HASH_BLOCK_MASK             0x3F
#define SEC_AES_BLOCK_MASK              0x0F
#define SEC_SUSPEND_TIMEOUT             3
#define SEC_SUSPEND_DELAT_1MS           1
#define SEC_INDEX2                      2
#define SEC_INDEX3                      3
#define SEC_INDEX4                      4
#define SEC_INDEX5                      5

#define SEC_PRO_KEY_LEN                 8
#define SEC_PROV_KEY_LEN                16

#define SEC_SUCCESS                     0
#define SEC_FAIL                        -1

typedef struct {
    uint8_t sec_bd[SEC_BD_SIZE];
} __attribute__((aligned(64)))TEE_SEC_BD;

struct memref_t;

uint32_t sec_init(void);
int32_t sec_suspend(void);
int32_t sec_resume(void);
/* DERIVE KEY */
uint32_t sec_huk_pbkdf2(uint32_t derive_type, const struct memref_t *data_in, struct memref_t *data_out);

#endif
