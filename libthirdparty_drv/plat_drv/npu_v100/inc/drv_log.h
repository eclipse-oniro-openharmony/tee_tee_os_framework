/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about drv log
 */

#ifndef _DRV_LOG_H_
#define _DRV_LOG_H_

void uart_printf_func(const char *fmt, ...);

#define NPU_ERR(string, arg...)		uart_printf_func("[NPU_E] %s:%d " string "\n", __func__, __LINE__, ##arg)
#define NPU_WARN(string, arg...)	uart_printf_func("[NPU_W] %s:%d " string "\n", __func__, __LINE__, ##arg)
#define NPU_INFO(string, arg...)	//uart_printf_func("[NPU_I] %s:%d " string "\n", __func__, __LINE__, ##arg)
#define NPU_DEBUG(string, arg...)

#define COND_RETURN_ERROR(COND, ERRCODE, ...) \
	COND_RETURN_((COND), ERRCODE, ##__VA_ARGS__)
#define COND_RETURN_VOID(COND, ...) \
	COND_RETURN_((COND), , ##__VA_ARGS__)

#define COND_RETURN_(COND, ERRCODE,  ...) \
	if ((COND)) {                \
		NPU_ERR( __VA_ARGS__); \
		return ERRCODE;                 \
	}
#define COND_GOTO_ERROR(COND, LABEL, ERROR, ERRCODE, ...) \
	COND_GOTO_WITH_ERRCODE_((COND), LABEL, ERROR, ERRCODE, ##__VA_ARGS__)

// Do NOT use this Marco directly
#define COND_GOTO_WITH_ERRCODE_(COND, LABEL, ERROR, ERRCODE, ...) \
	if (COND) {                \
		NPU_ERR(__VA_ARGS__); \
		ERROR = (ERRCODE);                \
		goto LABEL;                     \
	}

#endif /* _DRV_LOG_H_ */
