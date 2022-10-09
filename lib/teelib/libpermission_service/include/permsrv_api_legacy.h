/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Create: 2022-04-17
 * Description: Functions in this header file are deprecated. Do not use
 */

#ifndef __PERMSRV_API_LEGACY_H__
#define __PERMSRV_API_LEGACY_H__

#include "tee_defines.h"

TEE_Result TEE_EXT_crl_cert_process(const char *crl_cert, uint32_t crl_cert_size);
TEE_Result TEE_EXT_ta_ctrl_list_process(const char *ctrl_list, uint32_t ctrl_list_size);
#endif
