/*
 * npu_log.h
 *
 * about npu log
 *
 * Copyright (c) 2012-2019 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */
#ifndef __NPU_LOG_H__
#define __NPU_LOG_H__

void uart_printf_func(const char *fmt, ...);

#define NPU_DRV_ERR(string, arg...)		uart_printf_func("[NPU_E] %s:%d " string "\n", __func__, __LINE__, ##arg)
#define NPU_DRV_WARN(string, arg...)	uart_printf_func("[NPU_W] %s:%d " string "\n", __func__, __LINE__, ##arg)
#define NPU_DRV_INFO(string, arg...)
#define NPU_DRV_DEBUG(string, arg...)

#define COND_RETURN_ERROR(COND, ERRCODE, ...) \
			COND_RETURN_((COND), ERRCODE, ##__VA_ARGS__)

#define COND_RETURN_VOID(COND, ...) \
			COND_RETURN_((COND), , ##__VA_ARGS__)

// Do NOT use this Marco directly
#define COND_RETURN_(COND, ERRCODE, ...) \
			if ((COND)) { \
				NPU_DRV_ERR(__VA_ARGS__); \
				return ERRCODE; \
			}

#define COND_GOTO_ERROR(COND, LABEL, ERROR, ERRCODE, ...) \
			COND_GOTO_WITH_ERRCODE_((COND), LABEL, ERROR, ERRCODE, ##__VA_ARGS__)

#define COND_GOTO_DEBUG(COND, LABEL, ERROR, ERRCODE, ...) \
			COND_GOTO_WITH_ERRCODE_DEBUG_((COND), LABEL, ERROR, ERRCODE, ##__VA_ARGS__)

#define COND_GOTO_NOLOG(COND, LABEL, ERROR, ERRCODE) \
			COND_GOTO_WITH_ERRCODE_NOLOG_((COND), LABEL, ERROR, ERRCODE)

// Do NOT use this Marco directly
#define COND_GOTO_WITH_ERRCODE_(COND, LABEL, ERROR, ERRCODE, ...) \
			if (COND) { \
				NPU_DRV_ERR(__VA_ARGS__); \
				ERROR = (ERRCODE); \
				goto LABEL; \
			}

// Do NOT use this Marco directly
#define COND_GOTO_WITH_ERRCODE_DEBUG_(COND, LABEL, ERROR, ERRCODE, ...) \
			if (COND) { \
				NPU_DRV_DEBUG(__VA_ARGS__); \
				ERROR = (ERRCODE); \
				goto LABEL; \
			}

// Do NOT use this Marco directly
#define COND_GOTO_WITH_ERRCODE_NOLOG_(COND, LABEL, ERROR, ERRCODE) \
			if (COND) { \
				ERROR = (ERRCODE); \
				goto LABEL; \
			}

#endif /* __NPU_LOG_H__ */
