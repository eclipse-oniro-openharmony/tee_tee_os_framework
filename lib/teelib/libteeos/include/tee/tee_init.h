/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: Init base property header file for tee
 * Create: 2012-01-20
 */
#ifndef TEE_INIT_H
#define TEE_INIT_H

#include "tee_defines.h"
#include "ta_framework.h"

#define INVALID_DEV_ID 0xFFFFFFFFU

struct running_info {
    TEE_UUID uuid;
    uint32_t dev_id;
    uint32_t session_id;
    uint32_t global_handle;
    uint32_t session_type;
};

void tee_pre_init(int init_build, const struct ta_init_msg *init_msg);
TEE_Result tee_init(const struct ta_init_msg *init_msg);
void tee_exit(void);
void tee_session_init(uint32_t session_id);
void tee_session_exit(uint32_t session_id);
void tee_init_context(uint32_t session_id, uint32_t dev_id);
TEE_UUID *get_current_uuid(void);
uint32_t get_current_session_id(void);
uint32_t get_current_dev_id(void);
void set_global_handle(uint32_t handle);
uint32_t get_global_handle(void);
void set_running_uuid(void);
void set_current_session_type(uint32_t session_type);
uint32_t get_current_session_type(void);
struct running_info *get_tls_running_info(void);
TEE_UUID *get_running_uuid(void);
#endif
