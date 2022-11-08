/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef DRIVERS_SRE_LOG_H
#define DRIVERS_SRE_LOG_H
#include <stdio.h>
#include <lib_timer.h>

#define VERB_TAG  "[verb]"
#define DEBUG_TAG "[debug]"
#define INFO_TAG  "[info]"
#define WARN_TAG  "[warn]"
#define ERROR_TAG "[error]"

typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN  = 1,
    LOG_LEVEL_INFO  = 2,
    LOG_LEVEL_DEBUG = 3,
    LOG_LEVEL_VERBO = 4,
    LOG_LEVEL_ON    = 5,
} log_level;

#define LOG_LEVEL_MAX 4

int printf(const char *__restrict, ...);
void tee_print(log_level log_l, const char *fmt, ...);
void tee_print_driver(log_level log_l, const char *log_tag, const char *fmt, ...);
extern const char *g_debug_prefix;

#ifdef LOG_ON
#ifdef DRIVER_LOG_TAG
#define tlogv(fmt, args...) \
    tee_print_driver(LOG_LEVEL_VERBO, DRIVER_LOG_TAG, "%s %d:" fmt "", VERB_TAG, __LINE__, ##args)
#define tlogd(fmt, args...) \
    tee_print_driver(LOG_LEVEL_DEBUG, DRIVER_LOG_TAG, "%s %d:" fmt "", DEBUG_TAG, __LINE__, ##args)
#define tlogi(fmt, args...) \
    tee_print_driver(LOG_LEVEL_INFO, DRIVER_LOG_TAG, "%s %d:" fmt "", INFO_TAG, __LINE__, ##args)
#define tlogw(fmt, args...) \
    tee_print_driver(LOG_LEVEL_WARN, DRIVER_LOG_TAG, "%s %d:" fmt "", WARN_TAG, __LINE__, ##args)
#else
#define tlogv(fmt, args...) tee_print(LOG_LEVEL_VERBO, "%s %d:" fmt "", VERB_TAG, __LINE__, ##args)
#define tlogd(fmt, args...) tee_print(LOG_LEVEL_DEBUG, "%s %d:" fmt "", DEBUG_TAG, __LINE__, ##args)
#define tlogi(fmt, args...) tee_print(LOG_LEVEL_INFO, "%s %d:" fmt "", INFO_TAG, __LINE__, ##args)
#define tlogw(fmt, args...) tee_print(LOG_LEVEL_WARN, "%s %d:" fmt "", WARN_TAG, __LINE__, ##args)
#endif
#else
#define tlogv(fmt, args...) \
    do {                    \
    } while (0)
#define tlogd(fmt, args...) \
    do {                    \
    } while (0)
#define tlogi(fmt, args...) \
    do {                    \
    } while (0)
#define tlogw(fmt, args...) \
    do {                    \
    } while (0)
#endif

void uart_printf_func(const char *fmt, ...);

#ifdef DRIVER_LOG_TAG
#define tloge(fmt, args...) tee_print_driver(LOG_LEVEL_ERROR, DRIVER_LOG_TAG, "%s %d:" fmt " ", ERROR_TAG, \
                                             __LINE__, ##args)
#else
#define tloge(fmt, args...) tee_print(LOG_LEVEL_ERROR, "%s %d:" fmt " ", ERROR_TAG, __LINE__, ##args)
#endif
#endif /* DRIVERS_SRE_LOG_H */
