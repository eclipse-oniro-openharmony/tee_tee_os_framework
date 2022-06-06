/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: symbles export for use
 * Create: 2020-03-20
 */
#include <stdbool.h>
#include <tee_defines.h>
#include <stdint.h>
#include "internal.h"
#include "sre_task.h"
#include "tamgr_ext.h" /* get_selfpid */
#include "ipclib.h" /* SRE_PID_ERR */
#include "hm_mman.h" /* dump_free_mem */

#define MEM_USAGE_OK 1
/*
 * DO NOT CHANGE THE NAME OF _cfi_disabled VARIABLE
 * THE SYMBOL OF THIS VARIABLE HAS ALREADY BEEN EXPORTED TO RELEASE VERSION SDK
 * RENAMING WOULD DEFINITELY LEAD TO A "SYMBOL NOT FOUND" ERROR
 */
const unsigned int g_cfi_disabled = 1;

uint32_t get_mem_usage(bool show)
{
    /* Heap is uncommited lazily, cannot use heap size to judge mem leak; for backward compatibility */
    (void)show;
    return MEM_USAGE_OK;
}
void hm_yield()
{
    hmapi_yield();
}

void __dump_backtraces()
{
}

int __bsp_efuse_read()
{
    return -1;
}

int __driver_dep_test()
{
    return 0;
}

bool tee_get_usermode()
{
#ifdef DEF_BUILDUSERMODE
    return true;
#else
    return false;
#endif
}

unsigned int g_dx_content_path_addr()
{
    return 0;
}

unsigned int __SRE_HwiMsgCreateEnable()
{
    return -1U;
}

unsigned int get_value()
{
    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * ARG:
 *   - puwTaskPID: NULL checked
 * RET:
 *   - hm_getpid() return value checked
 * CODEREVIEW CHECKLIST by Jiuyue Ma <majiuyue@huawei.com>
 */
uint32_t __SRE_TaskSelf(uint32_t *puwTaskPID)
{
    uint32_t self;

    if (puwTaskPID == NULL)
        return OS_ERRNO_TSK_PTR_NULL;

    self = get_selfpid();
    if (self == SRE_PID_ERR)
        return OS_ERRNO_TSK_ID_INVALID;

    *puwTaskPID = self;

    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * ARG:
 *   - ucPtNo: unused parameter
 * RET:
 *   - dump_free_mem() return value checked
 *   - return value semantics changed: usage -> total free
 * CODEREVIEW CHECKLIST by Jiuyue Ma <majiuyue@huawei.com>
 */
uint32_t __SRE_MemUsageGet(uint8_t ucPtNo)
{
    (void)ucPtNo;

    size_t freemem = 0;
    if (dump_free_mem(&freemem) != 0)
        return 0;
    return (uint32_t)freemem;
}

void cinit00(void)
{
}

bool is_support_tui(void)
{
    return false;
}

#ifdef __aarch64__
const char *g_debug_prefix = "libtee_shared";
#else
const char *g_debug_prefix = "libtee_shared_a32";
#endif
