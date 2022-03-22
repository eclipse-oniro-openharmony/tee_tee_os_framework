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

#ifndef __LOG__H__H__
#define __LOG__H__H__
#include "drStd.h"
#include "dr_api/dr_api.h"
#include "mtk_log.h"

#if !defined(TAG)
#define TAG "DRTUI"
#endif

#define VALUE_64(value) \
	(unsigned int)(value >> (8*sizeof(uint32_t))), (unsigned int)value

#define TUI_LOGV(fmt, args...)					\
	do {							\
		if (tui_get_log_level() >= MTKLOG_LOGV)			\
			drDbgPrintf(TAG fmt, ##args);	\
	} while (0)

#define TUI_LOGD(fmt, args...)					\
	do {							\
		if (tui_get_log_level() >= MTKLOG_LOGD)			\
			drDbgPrintf(TAG fmt, ##args);	\
	} while (0)

#define TUI_LOGI(fmt, args...)					\
	do {							\
		if (tui_get_log_level() >= MTKLOG_LOGI)			\
			drDbgPrintf(TAG fmt, ##args);	\
	} while (0)

#define TUI_LOGW(fmt, args...)					\
	do {							\
		drDbgPrintf(TAG fmt, ##args);	\
	} while (0)

#define TUI_LOGE(fmt, args...)					\
	do {							\
		drDbgPrintf(TAG fmt, ##args);	\
	} while (0)

#define printf(fmt, args...)  drDbgPrintLnf("[DRTUI]"TAG fmt, ##args)
#endif
