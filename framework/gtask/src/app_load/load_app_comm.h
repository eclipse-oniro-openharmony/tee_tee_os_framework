/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description:  load app common interface.
 * Create: 2022-08-10
 */
#ifndef APP_LOAD_SRV_SUPPORT_COMMON_H
#define APP_LOAD_SRV_SUPPORT_COMMON_H

#include "tee_elf_verify.h"

struct image_version_info {
    uint32_t img_version;
    TEE_Result (*secure_img_permission_check)(elf_verify_reply *verify_reply);
    tee_img_type_t (*get_img_type)(const elf_verify_reply *verify_reply, uint32_t img_version);
    TEE_Result (*get_img_size)(const uint8_t *share_buf, uint32_t buf_len, uint32_t *size);
};

TEE_Result load_secure_app_image(tee_img_type_t img_type, const elf_verify_reply *verify_reply);
TEE_Result tee_secure_img_permission_check(uint32_t img_version, elf_verify_reply *verify_reply);
tee_img_type_t tee_secure_get_img_type(const elf_verify_reply *verify_reply, uint32_t img_version);
TEE_Result tee_secure_get_img_size(uint32_t img_version, uint8_t *share_buf, uint32_t buf_len, uint32_t *img_size);
void set_load_ta_mode_global_ptr(void);
elf_image_info *get_img_info_ptr(void);

#endif