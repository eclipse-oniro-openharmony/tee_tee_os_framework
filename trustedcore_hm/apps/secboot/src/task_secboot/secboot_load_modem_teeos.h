/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secboot TA
 * Author: modem-dev
 * Create: 2020/11/19
 */
#ifndef __SECBOOT_LOAD_MODEM_TEEOS_H__
#define __SECBOOT_LOAD_MODEM_TEEOS_H__
#include "tee_defines.h"
#include "secboot_verify.h"

TEE_Result seb_modem_load_modem_teeos(uint32_t paramtypes, TEE_Param params[PARAMS_COUNT]);
TEE_Result seb_modem_unload_modem_teeos(uint32_t paramtypes, TEE_Param params[PARAMS_COUNT]);
#endif
