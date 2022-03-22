/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cc driver stub.h
 * Create: 2020-04-13
 */
#ifndef CC_DRIVER_STUB_H
#define CC_DRIVER_STUB_H
#include <hmdrv_stub.h>
extern void* bgetz(size_t size);
extern void brel(void *buf);

#define _ACCESS_CHECK_STEP3_DMA(addr, sz, need_copy)                                                 \
    if (ret != 0) {                                                                              \
        tloge("cmd %x: ACCESS_READ_CHECK failed: %d.", swi_id, ret);                             \
        args[0] = OS_ERROR;                                                                     \
        AUDIT_CHECK_FAIL();                                                                      \
        goto out;                                                                                \
    }                                                                                            \
    __mapped_ptr[__mapped_ptr_cnt].pptr    = (void *)(&(addr));                                  \
    __mapped_ptr[__mapped_ptr_cnt].ori_ptr = (uint64_t)addr;                                     \
    __mapped_ptr[__mapped_ptr_cnt].type_len = sizeof(typeof(addr));                              \
    __mapped_ptr[__mapped_ptr_cnt].ptr     = (void *)(temp_addr);                                \
    __mapped_ptr[__mapped_ptr_cnt].len     = (size_t)(__hmdrv_size);                             \
    __mapped_ptr[__mapped_ptr_cnt].prot    = prot;                                               \
    if ((prot & PROT_EXEC) == PROT_EXEC) {                                                       \
        tloge("ERROR: the buffer passed points to code area\n");                                 \
        goto out;                                                                                \
    }                                                                                            \
    if (!need_copy && __hmdrv_size > 0x100000) {                                                 \
        tloge("INFO:buffer size too long, swi_id is %x, size is %x\n", swi_id, __hmdrv_size);    \
    }                                                                                            \
    if (!need_copy)                                                                              \
        need_local = 0;                                                                          \
    else                                                                                         \
        need_local = 1;                                                                          \
    __mapped_ptr[__mapped_ptr_cnt].need_lo = need_local;                                         \
    if (!__mapped_ptr[__mapped_ptr_cnt].l_ptr) {                                                 \
        if (need_local)                                                                          \
            __mapped_ptr[__mapped_ptr_cnt].l_ptr = (void *)malloc(__hmdrv_size);                  \
        else                                                                                     \
            __mapped_ptr[__mapped_ptr_cnt].l_ptr = (void *)temp_addr;                            \
        (addr) = (typeof(addr))(uintptr_t)__mapped_ptr[__mapped_ptr_cnt].l_ptr;                  \
        if (__mapped_ptr[__mapped_ptr_cnt].l_ptr == NULL) {                                      \
            tloge("cmd %x: malloc size 0x%lx) failed.", swi_id, __hmdrv_size);                   \
            args[0] = OS_ERROR;                                                                 \
            __mapped_ptr_cnt++;                                                                  \
            goto out;                                                                            \
        }                                                                                        \
        if (need_local) {                                                                        \
            (void)memcpy_s(__mapped_ptr[__mapped_ptr_cnt].l_ptr,                                 \
                           __hmdrv_size,                                                         \
                           (void *)(temp_addr),                                                  \
                           __hmdrv_size);                                                        \
        }                                                                                        \
    }                                                                                            \
    __mapped_ptr_cnt++;                                                                          \
    }                                                                                            \
    }

#define SYSCALL_END_DMA                                                                               \
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
            __task_unmap_from_ns_page((uint32_t)__self_pid, (uint32_t)(uintptr_t)__mapped_ptr[i].ptr, \
                                      (uint32_t)__mapped_ptr[i].len);                                 \
        if (__mapped_ptr[i].l_ptr && __mapped_ptr[i].need_lo) {                                       \
            (void)memset_s(__mapped_ptr[i].l_ptr, (uint32_t)__mapped_ptr[i].len, 0, (uint32_t)__mapped_ptr[i].len);   \
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

#define ACCESS_CHECK_DMA(addr, size)       \
    _ACCESS_CHECK_STEP1(addr, size, 1) \
    _ACCESS_CHECK_STEP2_A32(addr)      \
    _ACCESS_CHECK_STEP3_DMA(addr, size, 1)

#define ACCESS_CHECK_A64_DMA(addr, size)   \
    _ACCESS_CHECK_STEP1(addr, size, 1) \
    _ACCESS_CHECK_STEP2_A64(addr)      \
    _ACCESS_CHECK_STEP3_DMA(addr, size, 1)

#endif
