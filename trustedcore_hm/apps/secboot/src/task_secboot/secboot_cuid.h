/*
 *Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 *Description: get cuid
 *Create: 2021/02/07
 */
#ifndef __SECBOOT_CUID_H__
#define __SECBOOT_CUID_H__

#include "tee_defines.h"

#define SECBOOT_CUID_BYTES   32

TEE_Result seb_get_cuid(uint8_t *cuid, uint32_t len);

#endif
