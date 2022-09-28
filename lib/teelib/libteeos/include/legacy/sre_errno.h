/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: arm error info api interface
 * Create: 2020-01-08
 */
#ifndef LIBTEEOS_SRE_ERRNO_H
#define LIBTEEOS_SRE_ERRNO_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

/* 0x00 means OS, 0xFF means DRV, 1-254 means sub system */
/* OS errno */
#define SRE_ERRNO_OS_ID ((uint32_t)0x00 << 16)

/* error level: prompt */
#define SRE_ERRTYPE_NORMAL ((uint32_t)0x00 << 24)

/* error level: warn */
#define SRE_ERRTYPE_WARN ((uint32_t)0x01 << 24)

/* error level: serious */
#define SRE_ERRTYPE_ERROR ((uint32_t)0x02 << 24)

/* error level: fatal */
#define SRE_ERRTYPE_FATAL ((uint32_t)0x03 << 24)

/* mid: module ID */
#define SRE_ERRNO_OS_FATAL(mid, err_no) (SRE_ERRTYPE_FATAL | SRE_ERRNO_OS_ID | ((uint32_t)(mid) << 8) | (err_no))

#define SRE_ERRNO_OS_ERROR(mid, err_no) (SRE_ERRTYPE_ERROR | SRE_ERRNO_OS_ID | ((uint32_t)(mid) << 8) | (err_no))

#define SRE_ERRNO_OS_WARN(mid, err_no) (SRE_ERRTYPE_WARN | SRE_ERRNO_OS_ID | ((uint32_t)(mid) << 8) | (err_no))

#define SRE_ERRNO_OS_NORMAL(mid, err_no) (SRE_ERRTYPE_NORMAL | SRE_ERRNO_OS_ID | ((uint32_t)(mid) << 8) | (err_no))

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif
