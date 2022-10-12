/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee app image load service head file
 * Create: 2022.04.15
 */
#ifndef TEE_COMM_ELF_VERIFY_H
#define TEE_COMM_ELF_VERIFY_H

#include "tee_defines.h"
#include "tee_elf_verify.h"

TEE_Result tee_secure_img_header_check(uint32_t img_version);
TEE_Result tee_secure_img_unpack_v2(uint32_t rsa_algo_byte_len,
    uint32_t ta_hd_len, uint8_t *img_buf, uint32_t img_size, elf_hash_data *hash_data);
TEE_Result secure_img_copy_rsp_v2(elf_verify_reply *rep);
void free_verify_v2(void);

#endif

