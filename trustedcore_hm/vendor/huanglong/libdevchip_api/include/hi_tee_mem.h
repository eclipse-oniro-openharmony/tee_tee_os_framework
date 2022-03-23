/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sec mem api head file
 * Author: Hisilicon
 * Create: 2019-06-17
 */

#ifndef _HI_TEE_MEM_H
#define _HI_TEE_MEM_H

#include <stddef.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

/*
 * brief : alloc a sec-mmz type memory and map it into smmu sapce and map it into tee user cpu
 * @buf_name  : the name of buffer which will be allocate
 * @size      : the size of buffer
 * @virt      : the cpu address when the buffer map into tee user cpu
 * @handle    : the handle of buffer
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 */
int hi_tee_mmz_alloc_and_map(const char *buf_name, size_t size, void **virt, unsigned long long *handle);

/*
 * brief : free a sec-mmz type buffer which has benn allocated once
 * @virt     : the cpu address of the buffer
 * @handle   : the handle of the buffer
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 */
int hi_tee_mmz_unmap_and_free(void *virt, const unsigned long long handle);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
