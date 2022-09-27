/* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Make gtask be compatible to handle 64bit TA and 32bit TA.
 * Create: 2019-04-12
 */

#ifndef __TEE_TA2TA_H_
#define __TEE_TA2TA_H_

#include <dlist.h>
#include "ta_framework.h"
#include "tee_init.h"

/* change according to ta_framework.h */
typedef union {
    struct {
        unsigned int buffer;
        unsigned int size;
    } memref;
    struct {
        unsigned int a;
        unsigned int b;
    } value;
} tee_param_comp;

struct smc_operation {
    uint32_t types;
    tee_param_comp params[TEE_PARAM_NUM];
    uint32_t p_h_addr[TEE_PARAM_NUM]; /* add for aarch64 TA, store buffer high addr bit[32:63] */
};

struct tls_info {
    struct dlist_node list;
    struct running_info *info;
};

void add_tls_info(struct running_info *info);
void delete_tls_info(uint32_t session_id);

void delete_all_ta2ta_session(uint32_t tid);
#endif
