/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: ion recycle
 * Author: jianfujian
 * Create: 2019-11-04
 */

#include "sion_recycling.h"
#include <hm_msg_type.h>
#include "list.h"
#include "sec_region_ops.h"
#include "secmem.h"
#include "secmem_priv.h"
#include "sec_common.h"
#include "securec.h"
#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "sre_typedef.h"
#include "tee_log.h"
#include "mem_ops.h"
#include "legacy_mem_ext.h"
#include "sre_dev_relcb.h"
#include "drv_cache_flush.h"

#define UUID_NUM ARRAY_SIZE(uuid_array)

struct ta_task {
	struct list_head head;
	TEE_UUID uuid;
	u32 flag;
};

struct sglist_head {
	struct list_head sg_head;
	struct sglist *sglist;
	unsigned int protect_id;
};


static const TEE_UUID uuid_array[] = {
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
	HIAI_TINY_UUID,
#else
	HIAI_UUID,
#endif
	TUI_UUID,
	SEC_ISP_UUID,
	SEC_FACE_UUID,
	SECBOOT_UUID,
	EID1_UUID,
	EID3_UUID,
	ION_UUID,
	VLTMM_UUID,
	GTASK_UUID,
	SEC_IVP_UUID,
	SEC_FACE3D_AE_AC_UUID
};

static struct ta_task ta_task_list[UUID_NUM];
static TEE_UUID vltmm_uuid = VLTMM_UUID;

static struct ta_task *find_ta_task(const TEE_UUID *cur_uuid)
{
	u32 i;

	for (i = 0; i < UUID_NUM; i++) {
		if (!memcmp(&ta_task_list[i].uuid, cur_uuid, sizeof(TEE_UUID)))
			return &ta_task_list[i];
	}

	return NULL;
}

/* TA collapse execute */
static int sion_recycle(const void *data)
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct sglist_head *sg = NULL;
	struct ta_task *ta_task_find = NULL;
	TEE_UUID *cur_uuid = (TEE_UUID *)data;
	u32 va;
	int ret;

	/* release CB function register	*/
	SRE_TaskUnRegister_DevRelCb((DEV_RELEASE_CALLBACK)sion_recycle, data);
	ta_task_find = find_ta_task(cur_uuid);
	if (ta_task_find == NULL) {
		tloge("not find ta_task\n");
		return -EINVAL;
	}
	ta_task_find->flag = 0;

	list_for_each_safe(pos, next, &ta_task_find->head) {
		sg = list_entry(pos, struct sglist_head, sg_head);
		list_del(&sg->sg_head);

		/*
		 * sglist map get va,then flush cache ,
		 * do sglist unmap ,freememory
		 */
		va = sion_mmap(sg->sglist, sg->sglist->ion_size, sg->protect_id,
				secure, cache, USED_BY_SVC);
		(void)memset_s((void *)(uintptr_t)va, sg->sglist->ion_size, 0,
				sg->sglist->ion_size);
		v7_dma_flush_range(va, va + sg->sglist->ion_size);
		sion_munmap(sg->sglist, va, sg->sglist->ion_size,
			sg->protect_id, secure, USED_BY_SVC);

#ifdef CONFIG_SOC_WE_WORKAROUND
		va = sion_mmap(sg->sglist, sg->sglist->ion_size, sg->protect_id,
				secure, non_cache, USED_BY_SVC);
		v7_dma_flush_range(va, va + sg->sglist->ion_size);
		sion_munmap(sg->sglist, va, sg->sglist->ion_size,
			sg->protect_id, secure, USED_BY_SVC);
#endif

		/* unconfig sg list of dynamic secure region */
		ret = ddr_unset_sec_for_ta_crash(sg->sglist, (int)sg->protect_id);
		if (ret) {
			tloge("unconfig sec_region fail\n");
			return -EFAULT;
		}

		SRE_MemFree(OS_MID_SYS, sg->sglist);
		sg->sglist = NULL;
		SRE_MemFree(OS_MID_SYS, sg);
		sg = NULL;
	}

	return 0;
}

int sion_record_sglist(const struct sglist *sglist, const TEE_UUID *cur_uuid,
				unsigned int protect_id)
{
	struct sglist_head *sg = NULL;
	struct ta_task *ta_task_find = NULL;
	int ret;

	if (!sglist || !cur_uuid)
		return -EINVAL;

	/* vltmm no need record */
	if (!memcmp(&vltmm_uuid, cur_uuid, sizeof(TEE_UUID)))
		return 0;

	ta_task_find = find_ta_task(cur_uuid);
	if (!ta_task_find) {
		tloge("not find ta_task\n");
		return -EINVAL;
	}

	/* register CB function */
	if (!ta_task_find->flag) {
		SRE_TaskRegister_DevRelCb((DEV_RELEASE_CALLBACK)sion_recycle,
			(void *)&ta_task_find->uuid);
		ta_task_find->flag = 1;
	}
	/* add sglist to uuid list */
	sg = (struct sglist_head *)SRE_MemAlloc(OS_MID_SYS,
						OS_MEM_DEFAULT_FSC_PT,
						sizeof(struct sglist_head));
	if (!sg) {
		tloge("%s: alloc sg head fail\n", __func__);
		return -ENOMEM;
	}
	sg->protect_id = protect_id;

	sg->sglist = (struct sglist *)SRE_MemAlloc(OS_MID_SYS,
						   OS_MEM_DEFAULT_FSC_PT,
						   sglist->sglistSize);
	if (!sg->sglist) {
		tloge("%s: alloc sglist fail\n", __func__);
		SRE_MemFree(OS_MID_SYS, sg);
		return -ENOMEM;
	}

	ret = memcpy_s(sg->sglist, sglist->sglistSize, sglist,
		       sglist->sglistSize);
	if (ret) {
		tloge("memcpy sglist fail\n");
		SRE_MemFree(OS_MID_SYS, sg->sglist);
		SRE_MemFree(OS_MID_SYS, sg);
		return -EFAULT;
	}
	list_add(&sg->sg_head, &ta_task_find->head);

	return 0;
}

int sion_record_remove(const struct sglist *sglist, const TEE_UUID *cur_uuid)
{
	struct ta_task *ta_task_find = NULL;
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct sglist_head *sg = NULL;

	if (!sglist || !cur_uuid)
		return -EINVAL;

	/* vltmm no need record */
	if (!memcmp(&vltmm_uuid, cur_uuid, sizeof(TEE_UUID)))
		return 0;

	ta_task_find = find_ta_task(cur_uuid);
	if (!ta_task_find) {
		tloge("not find ta_task\n");
		return -EINVAL;
	}

	list_for_each_safe(pos, next, &ta_task_find->head) {
		sg = list_entry(pos, struct sglist_head, sg_head);
		if (sg->sglist->sglistSize != sglist->sglistSize)
			continue;

		/* remove sglist in TA task list */
		if (!memcmp(sg->sglist, sglist, sg->sglist->sglistSize)) {
			list_del(&sg->sg_head);
			SRE_MemFree(OS_MID_SYS, sg->sglist);
			sg->sglist = NULL;
			SRE_MemFree(OS_MID_SYS, sg);

			/*
			 * if sglist has deleted
			 * release CB function register
			 */
			if (list_empty(&ta_task_find->head)) {
				SRE_TaskUnRegister_DevRelCb(
					(DEV_RELEASE_CALLBACK)sion_recycle,
					(void *)&ta_task_find->uuid);
				ta_task_find->flag = 0;
			}

			return 0;
		}
	}

	return -ENOENT;
}

void sion_recycle_init(void)
{
	u32 i;

	for (i = 0; i < UUID_NUM; i++) {
		ta_task_list[i].uuid = uuid_array[i];
		ta_task_list[i].flag = 0;
		INIT_LIST_HEAD(&ta_task_list[i].head);
	}
}
