/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: memory functions are exported by libtee_shared
 * Create: 2021-11-08
 */
#ifndef TEE_SHAREMEM_OPS_H
#define TEE_SHAREMEM_OPS_H
#include <tee_defines.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */
void *tee_alloc_sharemem_aux(const struct tee_uuid *uuid, uint32_t size);
void *tee_alloc_coherent_sharemem_aux(const struct tee_uuid *uuid, uint32_t size);
uint32_t tee_free_sharemem(void *addr, uint32_t size);
int32_t copy_from_sharemem(uint32_t src_task, uint64_t src, uint32_t src_size, uintptr_t dst, uint32_t dst_size);
int32_t copy_to_sharemem(uintptr_t src, uint32_t src_size, uint32_t dst_task, uint64_t dst, uint32_t dst_size);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif /* MEM_OPS_EXT_H */
