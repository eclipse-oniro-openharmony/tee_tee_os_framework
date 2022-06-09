/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: timer drv call header
 * Create: 2020-08-21
 */

#ifndef HMDRV_STUB_H
#define HMDRV_STUB_H

#include <procmgr_ext.h> /* for hm_getpid() */
#include <api/mm_common.h>
#include <malloc.h>  /* for malloc() */
#include <tee_log.h>
#include <securec.h>
#include <tee_mem_ext.h>
#include <mem_drv_map.h>
#include <mem_ops_ext.h> /* __task_unmap_from_ns_page */
#include <drv_pal.h>

#ifdef HANDLE_SYSCALL
#undef HANDLE_SYSCALL
#endif

#ifdef SYSCALL_PERMISSION
#undef SYSCALL_PERMISSION
#endif

#ifdef SYSCALL_END
#undef SYSCALL_END
#endif

#ifdef ACCESS_CHECK
#undef ACCESS_CHECK
#endif

#ifdef ACCESS_READ_RIGHT_CHECK
#undef ACCESS_READ_RIGHT_CHECK
#endif

#ifdef ACCESS_WRITE_RIGHT_CHECK
#undef ACCESS_WRITE_RIGHT_CHECK
#endif

#ifndef SYSCALL_DATA_MAX
#define SYSCALL_DATA_MAX 512
#endif

#define ACCESS_READ_RIGHT_CHECK(addr, size)

cref_t get_teesmc_hdlr(void);
#define AUDIT_CHECK_FAIL()

#define ACCESS_WRITE_RIGHT_CHECK(addr, size)                                                        \
    {                                                                                               \
        if (__mapped_ptr_cnt > 0) {                                                                 \
            void *tmp = &(addr);                                                                    \
            for (int i = 0; i < __mapped_ptr_cnt; i++) {                                            \
                if (tmp == __mapped_ptr[i].pptr) {                                                  \
                    if (((unsigned)__mapped_ptr[i].prot & PROT_WRITE) != PROT_WRITE) {              \
                        tloge("swi_id %x, param %d, do not have write permission\n", swi_id, i);    \
                        AUDIT_CHECK_FAIL();                                                         \
                        goto out;                                                                   \
                    }                                                                               \
                    __mapped_ptr[i].need_cp = 1;                                                    \
                    if (__mapped_ptr[i].len && ((size) != __mapped_ptr[i].len))                       \
                        tloge("weird , read and write length don't match, swi_id is %d\n", swi_id); \
                    break;                                                                          \
                }                                                                                   \
            }                                                                                       \
        }                                                                                           \
    }

#define DRV_TIMER_SYSCALL(swi_id)           \
    pid_t __pid             = get_g_caller_pid(); \
    static pid_t __self_pid = 0;            \
    if (__self_pid == 0)                    \
        __self_pid = hm_getpid();           \
    switch (swi_id)

#define HANDLE_SYSCALL(swi_id)      \
    pid_t __pid = (pid_t)params->pid; \
    (void)__pid;                    \
    static pid_t __self_pid = 0;    \
    if (__self_pid == 0)            \
        __self_pid = hm_getpid();   \
    switch (swi_id)

#define SYSCALL_PERMISSION(swi_id, current_permissions, permission) \
    case (swi_id): {                                                \
        __label__ out;                                              \
        __attribute__((unused)) int prot;                           \
        params->rdata_len = 0;                                      \
        if (((permission) & (current_permissions)) == (permission)) {     \
            struct {                                                \
                void *ptr;                                          \
                uint32_t len;                                       \
                void *l_ptr;                                        \
                void *pptr;                                         \
                char need_cp;                                       \
                char need_lo;                                       \
                uint8_t type_len;                                   \
                uint64_t ori_ptr;                                   \
                int prot;                                           \
            } __mapped_ptr[16]   = { {0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0} }; \
            int __mapped_ptr_cnt = 0;

#define SYSCALL_END                                                                                   \
    out:                                                                                              \
    __attribute__((unused));                                                                    \
    for (int i = __mapped_ptr_cnt - 1; i >= 0; i--) {                                                 \
        if (__mapped_ptr[i].pptr != (&args[0]) && __mapped_ptr[i].pptr != NULL) {                    \
            if (__mapped_ptr[i].type_len == sizeof(uint32_t))                                         \
                *(uint32_t *)__mapped_ptr[i].pptr = (uint32_t)__mapped_ptr[i].ori_ptr;                \
            else                                                                                      \
                *(uint64_t *)__mapped_ptr[i].pptr = (uint64_t)__mapped_ptr[i].ori_ptr;                \
        }                                                                                             \
    }                                                                                                 \
    for (int i = 0; i < __mapped_ptr_cnt; i++) {                                                      \
        if ((uintptr_t)__mapped_ptr[i].ptr && __mapped_ptr[i].need_lo && __mapped_ptr[i].l_ptr &&     \
            ((unsigned)__mapped_ptr[i].prot & PROT_WRITE)) {                                          \
            (void)memcpy_s(__mapped_ptr[i].ptr,                                                       \
                           __mapped_ptr[i].len,                                                       \
                           __mapped_ptr[i].l_ptr,                                                     \
                           __mapped_ptr[i].len);                                                      \
        }                                                                                             \
        if (__mapped_ptr[i].ptr)                                                                      \
            task_unmap((uint32_t)__self_pid, (uintptr_t)__mapped_ptr[i].ptr, \
                                      (uint32_t)__mapped_ptr[i].len);                                 \
        if (__mapped_ptr[i].l_ptr && __mapped_ptr[i].need_lo) {                                       \
            free(__mapped_ptr[i].l_ptr);                                                              \
            __mapped_ptr[i].l_ptr = NULL;                                                             \
        }                                                                                             \
    }                                                                                                 \
    break;                                                                                            \
    }                                                                                                 \
    else                                                                                              \
    {                                                                                                 \
        args[0] = OS_ERROR;                                                                           \
        tloge("permission denied to access swi_id 0x%x.\n", swi_id);                                  \
        AUDIT_CHECK_FAIL();                                                                           \
        break;                                                                                        \
    }                                                                                                 \
    }

#define _ACCESS_CHECK_STEP1(addr, sz, need_copy)                           \
    {                                                                      \
        char need_local;                                                   \
        uint64_t __hmdrv_size = sz;                                        \
        if ((addr) == 0 || __hmdrv_size == 0) {                              \
            /* nothing to map if "addr == 0" or "size == 0" */             \
        } else {                                                           \
            uint64_t temp_addr = 0;                                        \
            if (__mapped_ptr_cnt > 15) {                                   \
                args[0] = OS_ERROR;                                        \
                tloge("\n\nBUGs: %d: __mapped_ptr overflow.\n", __LINE__); \
                goto out;                                                  \
            }                                                              \
            int err;

#define _ACCESS_CHECK_STEP2_A64(addr)                                                                              \
    err = drv_map_from_task_under_tbac_handle((uint32_t)__pid, (uint64_t)(uintptr_t)(addr), __hmdrv_size,          \
                                              (uint32_t)__self_pid, (uint64_t *)&(temp_addr), &prot,               \
                                              params->job_handler);

#define _ACCESS_CHECK_STEP2_A32(addr)                                                              \
    err = drv_map_from_task_under_tbac((uint32_t)__pid, (uint32_t)(uintptr_t)(addr), __hmdrv_size, \
                                       (uint32_t)__self_pid, (uint32_t *)&(temp_addr), &prot, params->job_handler);

#define _ACCESS_CHECK_STEP3(addr, sz, need_copy)                                                 \
    if (err != 0) {                                                                              \
        tloge("cmd %x: ACCESS_READ_CHECK failed: %d.", swi_id, err);                             \
        args[0] = OS_ERROR;                                                                      \
        AUDIT_CHECK_FAIL();                                                                      \
        goto out;                                                                                \
    }                                                                                            \
    __mapped_ptr[__mapped_ptr_cnt].pptr    = (void *)(&(addr));                                  \
    __mapped_ptr[__mapped_ptr_cnt].ori_ptr = (uint64_t)(uintptr_t)(addr);                        \
    __mapped_ptr[__mapped_ptr_cnt].type_len = sizeof(typeof(addr));                              \
    __mapped_ptr[__mapped_ptr_cnt].ptr     = (void *)(uintptr_t)(temp_addr);                     \
    __mapped_ptr[__mapped_ptr_cnt].len     = (uint32_t)(__hmdrv_size);                           \
    __mapped_ptr[__mapped_ptr_cnt].prot    = prot;                                               \
    if (((uint32_t)prot & PROT_EXEC) == PROT_EXEC) {                                             \
        tloge("ERROR: the buffer passed points to code area\n");                                 \
        goto out;                                                                                \
    }                                                                                            \
    if (!(need_copy) && __hmdrv_size > 0x100000) {                                                 \
        tloge("INFO:buffer size too long, swi_id is %x, size is %llx\n", swi_id, __hmdrv_size);  \
    }                                                                                            \
    if (!(need_copy))                                                                              \
        need_local = 0;                                                                          \
    else                                                                                         \
        need_local = 1;                                                                          \
    __mapped_ptr[__mapped_ptr_cnt].need_lo = need_local;                                         \
    if (!__mapped_ptr[__mapped_ptr_cnt].l_ptr) {                                                 \
        if (need_local)                                                                          \
            __mapped_ptr[__mapped_ptr_cnt].l_ptr = (void *)malloc((size_t)__hmdrv_size);         \
        else                                                                                     \
            __mapped_ptr[__mapped_ptr_cnt].l_ptr = (void *)(uintptr_t)temp_addr;                 \
        (addr) = (typeof(addr))(uintptr_t)__mapped_ptr[__mapped_ptr_cnt].l_ptr;                  \
        if (__mapped_ptr[__mapped_ptr_cnt].l_ptr == NULL) {                                      \
            tloge("cmd %x: malloc size 0x%llx) failed.", swi_id, __hmdrv_size);                  \
            args[0] = OS_ERROR;                                                                  \
            __mapped_ptr_cnt++;                                                                  \
            goto out;                                                                            \
        }                                                                                        \
        if (need_local) {                                                                        \
            (void)memcpy_s(__mapped_ptr[__mapped_ptr_cnt].l_ptr,                                 \
                           (size_t)__hmdrv_size,                                                         \
                           (void *)(uintptr_t)(temp_addr),                                                  \
                           (size_t)__hmdrv_size);                                                        \
        }                                                                                        \
    }                                                                                            \
    __mapped_ptr_cnt++;                                                                          \
    }                                                                                            \
    }

#define ACCESS_CHECK(addr, size)       \
    _ACCESS_CHECK_STEP1(addr, size, 1) \
    _ACCESS_CHECK_STEP2_A32(addr)      \
    _ACCESS_CHECK_STEP3(addr, size, 1)

#define ACCESS_CHECK_NOCPY(addr, size) \
    _ACCESS_CHECK_STEP1(addr, size, 0) \
    _ACCESS_CHECK_STEP2_A32(addr)      \
    _ACCESS_CHECK_STEP3(addr, size, 0)

#define ACCESS_CHECK_A64(addr, size)   \
    _ACCESS_CHECK_STEP1(addr, size, 1) \
    _ACCESS_CHECK_STEP2_A64(addr)      \
    _ACCESS_CHECK_STEP3(addr, size, 1)

#define ACCESS_CHECK_NOCPY_A64(addr, size) \
    _ACCESS_CHECK_STEP1(addr, size, 0)     \
    _ACCESS_CHECK_STEP2_A64(addr)          \
    _ACCESS_CHECK_STEP3(addr, size, 0)
#endif
