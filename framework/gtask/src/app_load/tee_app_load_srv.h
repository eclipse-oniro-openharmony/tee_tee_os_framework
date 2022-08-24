/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: tee app image load service head file
 * Author: Lu Chenggang luchenggang@huawei.com
 * Create: 2012.5.20
 */
#ifndef GTASK_TEE_APP_LOAD_SRV_H
#define GTASK_TEE_APP_LOAD_SRV_H

#include <ta_lib_img_unpack.h>
#include "tee_defines.h"
#include "ta_framework.h"
#include <openssl/rsa.h>

TEE_Result load_secure_file_image(const smc_cmd_t *cmd, bool *async);
TEE_Result need_load_app(const smc_cmd_t *cmd);
void free_img_load_buf(void);
TEE_Result rename_tmp_file(const char *new_name, uint32_t len);
int32_t process_register_elf_req(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size);
void elf_verify_crash_callback(void);
TEE_Result load_elf_to_tee(const char *file_buffer, int32_t file_size, uint32_t stack_size,
                           uint32_t task_amount, uint32_t heap_size, const TEE_UUID *uuid,
                           const char *task_name, bool buildin, bool dyn_conf_registed,
                           tee_img_type_t img_type);
#endif
