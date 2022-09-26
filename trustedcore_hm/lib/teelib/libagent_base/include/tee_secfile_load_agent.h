/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Tee-secfile load agent base function declaration.
 * Create: 2019-04-04
 */
#ifndef LIBAGENT_BASE_SECFILE_LOAD_AGENT_H
#define LIBAGENT_BASE_SECFILE_LOAD_AGENT_H

#include <stdint.h>
#include <stdbool.h>
#include <tee_defines.h>

#define LIB_NAME_MAX 64

struct ta_unlink_lib_msg {
    char lib_name[LIB_NAME_MAX];
    bool is_drvlib;
};

struct tee_srvc_recv_msg {
    TEE_Result ret_val;
    uint32_t srvc_pid;
    bool is_already_run;
};

int32_t tee_load_sec_lib(const char *lib_name, bool is_drvlib);
int32_t tee_load_sec_ta(const TEE_UUID *uuid);
void tee_unlink_lib(const char *lib_name, bool is_drvlib);
TEE_Result tee_bind_tee_service(const char *srvc_name, uint32_t *srvc_pid, bool *is_already_run);
void tee_unbind_tee_service(const char *srvc_name);

#endif
