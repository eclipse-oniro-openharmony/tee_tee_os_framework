/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: permission service cms signature api
 * Create: 2022-04-01
 */
#ifndef __PERMSRV_API_CMS_H__
#define __PERMSRV_API_CMS_H__

#include "tee_defines.h"

TEE_Result permsrv_crl_update(const uint8_t *buffer, uint32_t size);

#endif /* __PERMSRV_API_CMS_H__ */
