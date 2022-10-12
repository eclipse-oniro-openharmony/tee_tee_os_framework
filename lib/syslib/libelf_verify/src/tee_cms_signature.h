/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee app image load service head file
 * Create: 2022.04.15
 */
#ifndef TEE_CMS_SIGNATURE_H
#define TEE_CMS_SIGNATURE_H

#include "tee_defines.h"
#include "tee_elf_verify.h"

uint32_t get_cms_signature_size(const uint8_t *signature_buff, uint32_t signature_max_size);

#endif

