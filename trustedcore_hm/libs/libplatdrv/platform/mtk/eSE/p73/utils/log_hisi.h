/*
 * Copyright 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 /******************************************************************************
 *
 *  The original Work has been changed by NXP Semiconductors.
 *
 *  Copyright (C) 2019 NXP Semiconductors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#ifndef __ESE_LOG_HISI_H__
#define __ESE_LOG_HISI_H__

#include <sre_sys.h>

extern void uart_printf_func(const char *fmt, ...);
#define HISI_PRINT_FLAG 1
#define P61_DEBUG 0
#define P61_INFO 1

#if (HISI_PRINT_FLAG & P61_DEBUG)
#define HISI_PRINT_DEBUG uart_printf_func
#else
#define HISI_PRINT_DEBUG(exp, ...)
#endif

#if (HISI_PRINT_FLAG & P61_INFO)
#define HISI_PRINT_INFO uart_printf_func
#else
#define HISI_PRINT_INFO(exp, ...)
#endif

#if (HISI_PRINT_FLAG)
#define HISI_PRINT_WARRING uart_printf_func
#else
#define HISI_PRINT_WARRING(exp, ...)
#endif

#if (HISI_PRINT_FLAG)
#define HISI_PRINT_ERROR uart_printf_func
#else
#define HISI_PRINT_ERROR(exp, ...)
#endif

#define LOG_TAG "P73"
#define CONDITION(cond) (true)
#define ALOGD HISI_PRINT_INFO
#define ALOGE HISI_PRINT_ERROR

#endif
