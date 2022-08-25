/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description:  load app version3 interface.
 * Create: 2022-08-10
 */
#ifndef APP_LOAD_SRV_SUPPORT_V3_H
#define APP_LOAD_SRV_SUPPORT_V3_H

#include "tee_elf_verify.h"
#ifdef DYN_TA_SUPPORT_V3
TEE_Result tee_secure_get_img_size_v3(const uint8_t *share_buf, uint32_t buf_len, uint32_t *size);
#endif
#endif