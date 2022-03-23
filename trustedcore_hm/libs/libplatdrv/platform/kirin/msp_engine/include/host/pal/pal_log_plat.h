/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.
 * Description: log platform adapter
 * Create     : 2018/08/15
 */
#ifndef __PAL_LOG_PLAT_H__
#define __PAL_LOG_PLAT_H__
#include <pal_errno.h>

#define PAL_LOG_DEFAULT PAL_LOG_INFO /* set default log level */

/* set seceng module allow to debug */
#ifdef FEATURE_DFT_ENABLE
#define PAL_MODULE_VALID(mod) (1)
#else
#define PAL_MODULE_VALID(mod) (0)
#endif /* FEATURE_DFT_ENABLE */

#define PAL_FMT_PTR "0x%08X"

void hieps_log(const char *fmt, ...);

/* entry of debug output */
#define PAL_LOG(level, fmt, ...) do { \
	const char *__pfmt = (const char *)(fmt); \
	hieps_log(__pfmt, ##__VA_ARGS__); \
} while (0)

#define PAL_PRINTF(fmt, ...) PAL_LOG(PAL_LOG_INFO, fmt, ##__VA_ARGS__)

#endif /* __PAL_LOG_PLAT_H__ */
