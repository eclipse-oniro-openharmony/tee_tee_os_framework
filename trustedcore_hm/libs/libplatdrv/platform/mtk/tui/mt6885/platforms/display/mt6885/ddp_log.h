/*
 * Copyright (C) 2015 MediaTek Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef _H_DDP_LOG_
#define _H_DDP_LOG_

#ifndef LOG_TAG
#define LOG_TAG "DDP"
#endif

#include "drStd.h"
#include "dr_api/dr_api.h"
#include "ddp_debug.h"
#include "log.h"

#define DISP_LOG_RAW(fmt, args...)	TUI_LOGV(fmt, ##args)

#define DISP_LOG_V(fmt, args...)	TUI_LOGV("["LOG_TAG"]"fmt, ##args)
#define DISP_LOG_D(fmt, args...)	TUI_LOGD("["LOG_TAG"]"fmt, ##args)
#define DISP_LOG_I(fmt, args...)	TUI_LOGI("["LOG_TAG"]"fmt, ##args)
#define DISP_LOG_W(fmt, args...)	TUI_LOGW("["LOG_TAG"]"fmt, ##args)
#define DISP_LOG_E(fmt, args...)	TUI_LOGE("["LOG_TAG"]error:"fmt, ##args);

#define DDPIRQ(fmt, args...)		DISP_LOG_E(fmt, ##args)
#define DDPDUMP(fmt, args...)		DISP_LOG_E(fmt, ##args)
#define DDPDBG(fmt, args...)		DISP_LOG_E(fmt, ##args)
#define DDPDEBUG_D(fmt, args...)	DISP_LOG_E(fmt, ##args)
#define DDPMSG(fmt, args...)		DISP_LOG_E(fmt, ##args)
#define DDPERR(fmt, args...)		DISP_LOG_E(fmt, ##args)

#ifndef ASSERT
#define ASSERT(expr)                             \
    do {                                         \
        if(expr) break;                          \
		while(1) {								\
			DISP_LOG_E("ASSERT FAILED %s, %d\n", __FILE__, __LINE__);\
		}\
    }while(0)
#endif

#define DDPAEE(fmt, args...)                        \
    do {\
		DISP_LOG_E(fmt, ##args);\
		DISP_LOG_E("AEE %s, %d\n", __FILE__, __LINE__);\
     }while(1)

#define DISPFUNC() DISP_LOG_I("[DISP]func|%s\n", __func__)

//Common result type
typedef uint32_t drApiResult_t;

#endif
