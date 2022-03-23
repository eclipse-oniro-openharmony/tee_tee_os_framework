/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Provide interfaces of syscall and TA crash audit module
 * Create: 2019-05-10
 */

#ifndef _SRE_AUDIT_DRV_H
#define _SRE_AUDIT_DRV_H

#include <stdint.h>
#include <sys/usrsyscall_ext.h>

#ifdef SRE_AUDIT
#include <uidgid.h>
void kill_audit_task(uint32_t task_handle, cref_t teesmc_hdlr);
#endif
#endif
