/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: l00492120 & c00414356
* Create: 2017-01-20
* Notes: this file's api is for debug
*/
#ifndef __THP_AFE_DEBUG_H_
#define __THP_AFE_DEBUG_H_
#include <stdint.h>
#include <stdbool.h>

#define FALSE    -1

void show_mem_usage(const char* func);
void tsa_creat_log_file(void);
unsigned long long thp_get_time(void);
int afe_save_rawdata(uint16_t* buffer);
void log_append_tsa(char const c);
void debug_free_memory(void);

#endif
