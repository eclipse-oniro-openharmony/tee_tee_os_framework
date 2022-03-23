/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secboot TA
 * Author: modem-mcd
 * Create: 2020/12/04
 */
#ifndef __SECBOOT_MODEM_CALL_H__
#define __SECBOOT_MODEM_CALL_H__
#include "tee_defines.h"
#include "secboot_verify.h"

TEE_Result seb_bsp_modem_call(uint32_t paramtypes, TEE_Param params[PARAMS_COUNT]);
TEE_Result seb_bsp_modem_call_ext(uint32_t paramTypes, TEE_Param params[PARAMS_COUNT]);
#endif
