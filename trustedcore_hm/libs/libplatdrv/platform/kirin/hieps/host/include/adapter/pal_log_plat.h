/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: declare of log api
 * Author: l00370476
 * Create: 2018/08/15
 */

#ifndef __PAL_LOG_PLAT_H__
#define __PAL_LOG_PLAT_H__

#define PAL_LOG_DEFAULT              PAL_LOG_INFO /* set default log level */

/* set seceng module allow to debug */
#ifdef FEATURE_DFT_ENABLE
#define PAL_MODULE_VALID(mod)        1
#else
#define PAL_MODULE_VALID(mod)        0
#endif /* FEATURE_DFT_ENABLE */

#define PAL_FMT_PTR                 "0x%08X"

int printf(const char *fmt, ...);

/* entry of debug output */
#define PAL_PRINTF(level, fmt, ...) ((void)printf((fmt), ##__VA_ARGS__))

#endif /* __PAL_LOG_PLAT_H__ */
