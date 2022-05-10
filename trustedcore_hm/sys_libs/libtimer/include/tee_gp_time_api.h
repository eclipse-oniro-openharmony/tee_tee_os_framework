/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Header of gp time api
 * Create: 2022-04-22
 */

#ifndef SYS_LIBS_LIBTIMER_GP_TIME_API_H
#define SYS_LIBS_LIBTIMER_GP_TIME_API_H
#include <tee_defines.h>

void TEE_GetSystemTime(TEE_Time *time);
void TEE_GetREETime(TEE_Time *time);
TEE_Result TEE_Wait(uint32_t mill_second);
TEE_Result TEE_SetTAPersistentTime(TEE_Time *time);
TEE_Result TEE_GetTAPersistentTime(TEE_Time *time);

#endif