/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2001-2020. All rights reserved.
 * Description: This program is used to test sec ion
 * Author: jianfujian
 * Create: 2001-1-1
 */

#include "legacy_mem_ext.h"
#include "dynion.h"
#include "drv_module.h"
#include "mem_ops.h"
#include "sion.h"
#include "list.h"
#include "sec_region_ops.h"
#include "secmem.h"
#include "secmem_priv.h"
#include "securec.h"
#include "mem_page_ops.h"
#include "sre_task.h"
#include "sre_typedef.h"
#include "tee_log.h"

#define TEST_PHYS 0xC0000000U
#define TEST_SIZE 0x200000U
#define TEST_IOVA 0x200000U
#define TEST_TA   1

static struct mem_chunk_list mem_chunk;
s32 __sion_ioctl(int ion_ta_tag, void *mcl);
struct smmu_domain *siommu_domain_grab(u32 protect_id);

static void mem_chunk_fill(unsigned int protect_id, unsigned int buff_id,
				unsigned int size, unsigned int cachep)
{
	(void)protect_id;
	mem_chunk.protect_id = SEC_TASK_MAX;
	mem_chunk.buff_id = buff_id;
	mem_chunk.buffer_addr = NULL;
	mem_chunk.size = size;
	mem_chunk.cache = cachep;
}

static int test_kernel_map(struct mem_chunk_list *mcl)
{
	int ret;

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, mcl->size, cache);
	ret = sion_map_kernel(&mem_chunk);
	if (ret) {
		tloge("%s Map Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s Map Succ.\n", __func__);

	mem_chunk_fill(mcl->protect_id, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_kernel(&mem_chunk);
	if (ret) {
		tloge("%s UnMap Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s UnMap Succ.\n", __func__);

	return 0;
}

static int test_user_map(struct mem_chunk_list *mcl)
{
	int ret;

	mem_chunk_fill(mcl->protect_id, mcl->buff_id, mcl->size, cache);
	ret = sion_map_user(&mem_chunk);
	if (ret) {
		tloge("%s Map Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s Map Succ.\n", __func__);

	mem_chunk_fill(mcl->protect_id, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_user(&mem_chunk);
	if (ret) {
		tloge("%s UnMap Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s UnMap Succ.\n", __func__);

	return 0;
}

static int test_get_pgtable(void)
{
	int ret;
	unsigned int protect_id = SEC_TASK_DRM;

	ret = hisi_sion_get_pgtable(protect_id);
	if (!ret) {
		tloge("%s Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s Succ.\n", __func__);

	protect_id = SEC_TASK_MAX;
	ret = hisi_sion_get_pgtable(protect_id);
	if (ret) {
		tloge("%s error path Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s error path Succ.\n", __func__);
	return 0;
}

static int test_iommu_map(struct mem_chunk_list *mcl)
{
	int ret;

	mem_chunk_fill(mcl->protect_id, mcl->buff_id, mcl->size, cache);
	ret = sion_map_iommu(&mem_chunk);
	if (ret) {
		tloge("%s Map Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s Map Succ.\n", __func__);

	sion_show_pte(mem_chunk.protect_id, mem_chunk.va, mem_chunk.size);

	mem_chunk_fill(mcl->protect_id, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_iommu(&mem_chunk);
	if (ret) {
		tloge("%s UnMap Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s UnMap Succ.\n", __func__);

	return 0;
}

static int test_iommu_err_path(struct mem_chunk_list *mcl)
{
	int ret;
	u32 size = mcl->size;

	mem_chunk_fill(SEC_TASK_MAX, mcl->buff_id, mcl->size, cache);
	ret = sion_map_iommu(&mem_chunk);
	if (!ret) {
		tloge("%s Err PRO ID Map Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_MAX, mcl->buff_id, 0, cache);
	ret = sion_map_iommu(&mem_chunk);
	if (!ret) {
		tloge("%s Err size Map Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, size, cache);
	ret = sion_map_iommu(&mem_chunk);
	if (ret) {
		tloge("%s Map Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_MAX, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_iommu(&mem_chunk);
	if (!ret) {
		tloge("%s Err PRO ID UnMap Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_MAX, mcl->buff_id, mcl->size, cache);
	ret = __sion_ioctl(ION_SEC_CMD_FREE, (void *)&mem_chunk);
	if (!ret) {
		tloge("%s Err PRO ID Free Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_iommu(&mem_chunk);
	if (ret) {
		tloge("%s Unmap Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_iommu(&mem_chunk);
	if (!ret) {
		tloge("%s Err ref UnMap Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s: iommu map test Succ.\n", __func__);

	return 0;
}

static int test_kernel_err_path(struct mem_chunk_list *mcl)
{
	int ret;
	u32 size = mcl->size;

	mem_chunk_fill(SEC_TASK_MAX, mcl->buff_id, mcl->size, cache);
	ret = sion_map_kernel(&mem_chunk);
	if (!ret) {
		tloge("%s Map Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, 0, cache);
	ret = sion_map_kernel(&mem_chunk);
	if (!ret) {
		tloge("%s Err size Map Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, size, cache);
	ret = sion_map_kernel(&mem_chunk);
	if (ret) {
		tloge("%s Map Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_MAX, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_kernel(&mem_chunk);
	if (!ret) {
		tloge("%s Err PRO ID UnMap Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_MAX, mcl->buff_id, mcl->size, cache);
	ret = __sion_ioctl(ION_SEC_CMD_FREE, (void *)&mem_chunk);
	if (!ret) {
		tloge("%s Err PRO ID Free Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_kernel(&mem_chunk);
	if (ret) {
		tloge("%s Unmap Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_kernel(&mem_chunk);
	if (!ret) {
		tloge("%s Err ref UnMap Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s: sion map kernel test Succ.\n", __func__);

	return 0;
}

static int test_user_err_path(struct mem_chunk_list *mcl)
{
	int ret;
	u32 size = mcl->size;

	mem_chunk_fill(SEC_TASK_MAX, mcl->buff_id, mcl->size, cache);
	ret = sion_map_user(&mem_chunk);
	if (!ret) {
		tloge("%s Err PRO ID Map Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, 0, cache);
	ret = sion_map_user(&mem_chunk);
	if (!ret) {
		tloge("%s Err size Map Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, size, cache);
	ret = sion_map_user(&mem_chunk);
	if (ret) {
		tloge("%s Map Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_MAX, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_user(&mem_chunk);
	if (!ret) {
		tloge("%s Err PRO ID UnMap Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_MAX, mcl->buff_id, mcl->size, cache);
	ret = __sion_ioctl(ION_SEC_CMD_FREE, (void *)&mem_chunk);
	if (!ret) {
		tloge("%s Err PRO ID Free Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_user(&mem_chunk);
	if (ret) {
		tloge("%s Unmap Fail.\n", __func__);
		return -EINVAL;
	}

	mem_chunk_fill(SEC_TASK_DRM, mcl->buff_id, mcl->size, cache);
	ret = sion_unmap_user(&mem_chunk);
	if (!ret) {
		tloge("%s Err ref UnMap Fail.\n", __func__);
		return -EINVAL;
	}
	tloge("%s: sion map user test Succ.\n", __func__);

	return 0;
}

static struct sglist *create_sglist(TEE_PAGEINFO *array, u32 nents)
{
	struct sglist *sglist = NULL;
	u64 sglist_size;
	u32 i;

	sglist_size = sizeof(TEE_PAGEINFO) * nents + sizeof(struct sglist);
	sglist = (struct sglist *)SRE_MemAlloc(
		OS_MID_SYS, OS_MEM_DEFAULT_FSC_PT, sglist_size);
	if (!sglist) {
		tloge("%s: alloc sglist fail!\n", __func__);
		return NULL;
	}
	(void)memset_s(sglist, sglist_size, 0, sglist_size);

	for (i = 0; i < nents; i++)
		sglist->info[i] = array[i];

	sglist->infoLength = nents;
	sglist->sglistSize = sglist_size;
	tloge("%s:sglist infoLength(0x%x) sglistSize(0x%llx)!\n", __func__,
		nents, sglist_size);

	return sglist;
}

static void destory_sglist(struct sglist *sglist)
{
	u64 sglist_size;

	sglist_size = sglist->sglistSize;
	(void)memset_s(sglist, sglist_size, 0, sglist_size);
	SRE_MemFree(OS_MID_SYS, sglist);
}

static struct sglist *create_sglist_sec_cfg(TEE_PAGEINFO *array, u32 nents)
{
	int ret;
	struct sglist *sglist = NULL;

	sglist = create_sglist(array, nents);
	if (!sglist) {
		tloge("%s: create sglist fail!\n", __func__);
		return NULL;
	}

	ret = ddr_sec_cfg(sglist, DDR_SEC_FACE, DDR_SET_SEC);
	if (ret) {
		tloge("%s: set sglist cfg fail!\n", __func__);
		destory_sglist(sglist);
		return NULL;
	}
	return sglist;
}

static int __test_siommu_map(struct sglist *sglist, u32 size)
{
	int ret;
	struct smmu_domain *sdomain = NULL;

	sdomain = siommu_domain_grab(SEC_TASK_SEC);
	if (!sdomain) {
		tloge("%s: create sdomain fail!\n", __func__);
		return -EINVAL;
	}

	ret = siommu_map(sdomain, sglist, TEST_IOVA, size,
		IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE | IOMMU_SEC, 0);
	if (ret) {
		tloge("%s: map iova fail!\n", __func__);
		destory_siommu_domain(sdomain);
		return ret;
	}

	ret = siommu_unmap(sdomain, sglist, TEST_IOVA, size, 0);
	if (ret) {
		tloge("%s: siommu_unmap iova:0x%x size:0x%x fail!\n",
			__func__, TEST_IOVA, size);
		destory_siommu_domain(sdomain);
	}
	return ret;
}

static int test_siommu_map(struct mem_chunk_list *mcl)
{
	int ret;
	u32 size = mcl->va;
	struct sglist *sglist = NULL;
	struct sglist *pg_sg = NULL;
	TEE_PAGEINFO *array = NULL;
	TEE_PAGEINFO tmp_array;

	array = (TEE_PAGEINFO *)SRE_MemAlloc(
		OS_MID_SYS, OS_MEM_DEFAULT_FSC_PT, mcl->size);
	if (!array) {
		tloge("array SRE_MemAlloc alloc fail, size 0x%x\n", mcl->size);
		return -EINVAL;
	}
	tloge("%s: mcl->buffer_addr 0x%x!\n", __func__, mcl->buffer_addr);
	(void)memcpy_s((void *)array, mcl->size, mcl->buffer_addr, mcl->size);

	sglist = create_sglist_sec_cfg(array, mcl->nents);
	if (!sglist) {
		tloge("%s: create sglist fail!\n", __func__);
		ret = -EINVAL;
		goto free_array;
	}
	/* use gcda reserved memory to test */
	tmp_array.phys_addr = TEST_PHYS;
	tmp_array.npages = TEST_SIZE / PAGE_SIZE;
	pg_sg = create_sglist_sec_cfg(&tmp_array, 1);
	if (!pg_sg) {
		tloge("%s: create pg_sg fail!\n", __func__);
		if (ddr_sec_cfg(pg_sg, DDR_SEC_FACE, DDR_UNSET_SEC))
			tloge("%s:pg_sg DDR_SEC_FACE UNSET ddr_sec_cfg fail!\n",
				__func__);
		ret = -EINVAL;
		goto destory_sglist;
	}

	ret = __test_siommu_map(sglist, size);
	if (ret) {
		tloge("%s: create sdomain fail!\n", __func__);
		ret = -EINVAL;
		goto free_dom;
	}
	tloge("%s: test siommu map/unmap succ!\n", __func__);

free_dom:
	if (ddr_sec_cfg(sglist, DDR_SEC_FACE, DDR_UNSET_SEC))
		tloge("%s:sglist DDR_SEC_FACE UNSET_SEC ddr_sec_cfg fail!\n",
			__func__);
	if (ddr_sec_cfg(pg_sg, DDR_SEC_PGTABLE, DDR_UNSET_SEC))
		tloge("%s:pg_sg DDR_SEC_PGTABLE UNSET_SEC ddr_sec_cfg fail!\n",
			__func__);
	destory_sglist(pg_sg);

destory_sglist:
	destory_sglist(sglist);
free_array:
	SRE_MemFree(OS_MID_SYS, array);

	return ret;
}

static int test_sion_mmap(struct mem_chunk_list *mcl)
{
	u32 i, va;
	int ret;
	u64 sglist_size;
	u32 size = mcl->va;
	struct sglist *sglist = NULL;
	TEE_PAGEINFO *array = NULL;

	sglist_size = (u64)(sizeof(*array) * (u64)mcl->nents +
				sizeof(struct sglist));

	sglist = (struct sglist *)SRE_MemAlloc(
		OS_MID_SYS, OS_MEM_DEFAULT_FSC_PT, sglist_size);
	if (!sglist) {
		tloge("%s: alloc sglist fail!\n", __func__);
		return -EINVAL;
	}

	tloge("%s: struct sglist:0x%x size:0x%x info[0]:0x%x!\n", __func__,
		sglist, sizeof(struct sglist), &sglist->info[0]);

	array = (TEE_PAGEINFO *)SRE_MemAlloc(OS_MID_SYS,
		OS_MEM_DEFAULT_FSC_PT, mcl->size);
	if (!array) {
		SRE_MemFree(OS_MID_SYS, sglist);
		tloge("array SRE_MemAlloc alloc fail, size 0x%x\n", mcl->size);
		return -EINVAL;
	}
	tloge("mcl->buffer_addr: 0x%x!\n", mcl->buffer_addr);
	(void)memcpy_s((void *)array, mcl->size, mcl->buffer_addr, mcl->size);

	for (i = 0; i < mcl->nents; i++)
		sglist->info[i] = array[i];

	sglist->infoLength = mcl->nents;
	sglist->sglistSize = sglist_size;
	tloge("sglist len:0x%x size:0x%x!\n", mcl->nents, sglist_size);

	if (ddr_sec_cfg(sglist, DDR_SEC_FACE, DDR_SET_SEC))
		tloge("%s:sglist DDR_SEC_FACE SET_SEC ddr_sec_cfg fail!\n",
			__func__);

	va = sion_mmap(sglist, size, SEC_TASK_SEC, secure, cache, TEST_TA);
	if (!va) {
		tloge("%s: map va fail!\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	ret = sion_munmap(sglist, va, size, SEC_TASK_SEC, secure, TEST_TA);
	if (ret) {
		tloge("sion_munmap va:0x%x size:0x%x fail\n", va, size);
		goto out;
	}

	tloge("%s: test sion mmap/munmap succ!\n", __func__);

out:
	if (ddr_sec_cfg(sglist, DDR_SEC_FACE, DDR_UNSET_SEC))
		tloge("%s:sglist DDR_SEC_FACE UNSET_SEC ddr_sec_cfg fail!\n",
			__func__);
	SRE_MemFree(OS_MID_SYS, sglist);
	SRE_MemFree(OS_MID_SYS, array);

	return ret;
}

int test_teeos_sion(struct mem_chunk_list *mcl)
{
	int ret;

	tloge("Test teeos sion begin!\n");

	tloge("Secbuf: id 0x%x, size 0x%x, task %u\n", mcl->buff_id, mcl->size,
		mcl->protect_id);

	if (mcl->protect_id == SEC_TASK_DRM) {
		ret = test_user_map(mcl); /* fail with no map permission */

		ret = test_user_err_path(mcl); /* fail with no map permission */
		if (ret)
			tloge("test_user_err_path fail!\n");

		ret = test_kernel_map(mcl);

		ret += test_get_pgtable();

		ret += test_iommu_map(mcl);

		ret += test_iommu_err_path(mcl);

		ret += test_kernel_err_path(mcl);
	} else {
		ret = test_sion_mmap(mcl);
		ret = test_siommu_map(mcl);
	}

	if (ret)
		tloge("Test teeos sion Fail.\n");
	else
		tloge("Test teeos sion Succ.\n");

	return ret;
}
