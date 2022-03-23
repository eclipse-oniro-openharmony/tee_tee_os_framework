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

#include "ddp_debug.h"

#define LOG_TAG "debug"

static int ddp_debug_log_level = 2;

void ddp_debug_set_log_level(int level)
{
	ddp_debug_log_level = level;
}

int ddp_debug_get_log_level(void)
{
	return ddp_debug_log_level;
}

