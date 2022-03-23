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

#ifndef __MTK_LOG_H__
#define __MTK_LOG_H__

enum MTK_LOG_LEVEL {
    MTKLOG_LOGI = 1,
    MTKLOG_LOGD = 2,
    MTKLOG_LOGV = 3
};

void tui_set_log_level(enum MTK_LOG_LEVEL level);

enum MTK_LOG_LEVEL tui_get_log_level(void);

#endif

