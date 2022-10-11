/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: task definition used by gtask and platdrv
 * Create: 2022-05-12
 */
#ifndef LIBTEEOS_SRE_TASK_H
#define LIBTEEOS_SRE_TASK_H

#include <stdint.h>
#include "sre_errno.h" /* SRE_ERRNO_OS */

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#define OS_MID_TSK 0x8 /* old macro definition */

/* val: 0x03000800 errno info: alloc mem failed */
#define OS_ERRNO_TSK_NO_MEMORY SRE_ERRNO_OS_FATAL(OS_MID_TSK, 0x00)

/* val: 0x02000801 errno info: ptr param is NULL */
#define OS_ERRNO_TSK_PTR_NULL SRE_ERRNO_OS_ERROR(OS_MID_TSK, 0x01)

/* val: 0x02000803 errno info: illegal prior level */
#define OS_ERRNO_TSK_PRIOR_ERROR SRE_ERRNO_OS_ERROR(OS_MID_TSK, 0x03)

/* val: 0x02000807 errno info: invalid task id */
#define OS_ERRNO_TSK_ID_INVALID SRE_ERRNO_OS_ERROR(OS_MID_TSK, 0x07)

/* val: 0x02000813 errno info: task hook is full */
#define OS_ERRNO_TSK_HOOK_IS_FULL SRE_ERRNO_OS_ERROR(OS_MID_TSK, 0x13)

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif
