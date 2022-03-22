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

#include "mtk_log.h"

//#if defined (TUI_USER_BUILD)
static enum MTK_LOG_LEVEL log_level = MTKLOG_LOGI;
//#else
//static enum MTK_LOG_LEVEL log_level = MTKLOG_LOGV;
//#endif

void tui_set_log_level(enum MTK_LOG_LEVEL level)
{
	if (level >= MTKLOG_LOGI || level <= MTKLOG_LOGV)
		log_level = level;
}

enum MTK_LOG_LEVEL tui_get_log_level(void)
{
	return MTKLOG_LOGI;
}
