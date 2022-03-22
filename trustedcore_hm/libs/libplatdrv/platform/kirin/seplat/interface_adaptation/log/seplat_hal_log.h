/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: provide log function.
 * Create: 2020/12/21
 */
#ifndef HAL_LOG_H
#define HAL_LOG_H

void seplat_external_log(const char *fmt, ...);
void seplat_trace_hex(const unsigned char *buf, const unsigned int buflen);

#define hal_print_error(...) seplat_external_log(__VA_ARGS__)

#ifdef HAL_PRINT_DEBUG_ENABLE
#define hal_print_trace(...) seplat_external_log(__VA_ARGS__)
#else
#define hal_print_trace(...)
#endif

#endif
