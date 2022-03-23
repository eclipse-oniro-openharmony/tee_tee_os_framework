/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: sion
 * Create: 2012-1-1
 */

#include "sion.h"
#include <legacy_mem_ext.h>
#include <register_ops.h>
#include <drv_mem.h>
#include <drv_cache_flush.h>
#include <dynion.h>
#include "drv_pal.h"
#include "drv_module.h"
#include "list.h"
#include "sec_region_ops.h"
#include "secmem.h"
#include "secmem_priv.h"
#include "securec.h"
#include "sre_access_control.h"
#include "mem_ops.h"
#include "mem_page_ops.h"
#include "sre_syscalls_id_ext.h"
#include "sre_task.h"
#include "sre_typedef.h"
#include "tee_log.h"
#include "sre_dev_relcb.h"
#include "hisi_isp.h"
#include "sion_recycling.h"
#include "sec_smmu_com.h"

#define MIN_SEC_ID 27
#define MAX_SEC_ID 1027
#define MAX_NUMS (MAX_SEC_ID - MIN_SEC_ID)
#define MAX_BUF_NENTS 512
#define MAX_MAP_CNT 127
#define USR_SP_OFFSET  8
#define SEC_MIN_ORDER  16
#define ISP_PGTABLE_BASE 0xBE000000
#define ISP_PGTABLE_SIZE 0x200000
#define PAGEINFO_NUM  1
#define MCL_NENTS     1

#define OK		0
#define ERROR		(-1)

static u16 sbuf_num;

struct sion_device {
	struct smmu_domain *sdomain;
	struct gen_pool *iova_pool;
	struct list_head sbuf_head;
	u32 protect_id;
};

struct sec_buf {
	u8 uva_refs;
	u8 kva_refs;
	u8 iova_refs;
	u16 id;
	u32 uva;
	u32 kva;
	u32 iova;
	u32 size;
	u32 nents;
	struct sglist *sg;
	struct list_head list;
};

struct sec_id {
	u16 id;
	u16 used;
};

/*
 * smmu for 3 tasks need to be inited
 * 0: stand for DRM
 * 1: stand for TUI or IRIS
 */
static u32 sion_pool_flag;

static struct sion_device sion_dev[SEC_TASK_MAX];
static struct sec_id id_array[MAX_NUMS];

static int sion_init;

/*
 * invalid input to return 0
 * valid input to return pgtable address
 */
unsigned int hisi_sion_get_pgtable(unsigned int protect_id)
{
	if (protect_id >= SEC_TASK_MAX) {
		tloge("protect_id incorret!\n");
		return 0;
	}

	if (!sion_dev[protect_id].sdomain) {
		tloge("iommu domain not init yet!\n");
		return 0;
	}

	return sion_dev[protect_id].sdomain->pgd_phys;
}

u64 *hisi_sion_get_pgd_virt(unsigned int protect_id)
{
	if (protect_id >= SEC_TASK_MAX) {
		tloge("protect_id incorret!\n");
		return NULL;
	}

	if (!sion_dev[protect_id].sdomain) {
		tloge("iommu domain not init yet!\n");
		return NULL;
	}

	return sion_dev[protect_id].sdomain->pgd;
}

static s32 addr_check(paddr_t addr, u32 size)
{
	if (!addr || (addr >= addr + size)) {
		tloge("illegal pa address,size:0x%x\n", size);
		return -EINVAL;
	}
	return 0;
}

s32 sion_flag_unset(u32 type)
{
	if (sion_pool_flag)
		sion_pool_flag--;

	tloge("SION_LOG:%s flag:%u type:%u\n", __func__, sion_pool_flag,
		type);
	return 0;
}

s32 sion_pool_flag_set(u32 type)
{
#ifdef TEE_SUPPORT_TZMP2
	sion_pool_flag++;
	/*
	 * if TA  exit abnormally,
	 * system will call sion_flag_unset to recycle
	 * resource,i.e flag
	 */
	(void)task_register_devrelcb(
		(DEV_RELEASE_CALLBACK)sion_flag_unset, NULL);

	tloge("SION_LOG:%s flag:%u type:%u\n", __func__, sion_pool_flag,
		type);
#endif
	return 0;
}

s32 sion_pool_flag_unset(u32 type)
{
#ifdef TEE_SUPPORT_TZMP2
	if (sion_pool_flag) {
		task_unregister_devrelcb((DEV_RELEASE_CALLBACK)sion_flag_unset, NULL);
		sion_pool_flag--;
	}

	tloge("SION_LOG:%s flag:%u type:%u\n", __func__, sion_pool_flag,
		type);
#endif
	return 0;
}

static u32 sion_pool_flag_get(void)
{
	tloge("SION_LOG:%s flag:%u\n", __func__, sion_pool_flag);
	return sion_pool_flag;
}

#ifndef CONFIG_PRODUCT_ARMPC
static s32 hisi_siommu_pgtable_init(void)
{
	u32 addr;
	u32 size;
	u32 task_id = SEC_TASK_DRM;
	int ret;

	addr = DRM_PGTABLE_BASE;
	size = DRM_PGTABLE_SIZE;
	ret = tzmp2_set_sec((u64)addr, size);
	if (ret) {
		tloge("set tzmp2 fail, addr 0x%x, size 0x%x\n", addr, size);
		return -EFAULT;
	}

	sion_dev[task_id].protect_id = SEC_TASK_DRM;
	sion_dev[task_id].sdomain = hisi_siommu_init(addr, size);
	if (!sion_dev[task_id].sdomain) {
		tloge("siommu init fail\n");
		return -ENODEV;
	}

	tloge("smmu init success for DRM\n");

	return 0;
}
#endif

static int val_sglist_buf_size(const struct sglist *sglist, u32 *buf_size)
{
	u64 total_size;
	u32 buffer_size = 0;
	u32 seg_size;
	u32 i;

	total_size = sizeof(TEE_PAGEINFO) * sglist->infoLength +
		     sizeof(struct sglist);

	if (sglist->sglistSize != total_size) {
		tloge("invalid sglist size:0x%llx, total_size:0x%llx\n",
			sglist->sglistSize, total_size);
		return -EINVAL;
	}

	for (i = 0; i < sglist->infoLength; i++) {
		seg_size = sglist->info[i].npages * PAGE_SIZE;
		if (!seg_size || seg_size < sglist->info[i].npages) {
			tloge("invalid sglist info[%u]! npages %u\n", i,
				sglist->info[i].npages);
			return -EINVAL;
		}

		buffer_size += seg_size;
		if (buffer_size < seg_size) {
			tloge("sglist info size:0x%x overflow\n", buffer_size);
			return -EINVAL;
		}
	}

	*buf_size = buffer_size;
	return 0;
}

#ifdef CONFIG_SOC_WE_WORKAROUND
static s32 secsg_dma_flush_nc(struct sec_buf *sbuf)
{
	u32 kva;

	if (sre_mmap_scatter(&sbuf->sg->info[0], sbuf->nents, &kva, sbuf->size,
			     secure, non_cache, USED_BY_SVC)) {
		tloge("%s: map failed\n", __func__);
		return -EFAULT;
	}

	v7_dma_flush_range(kva, kva + sbuf->size);
	if (sre_munmap_scatter(kva, sbuf->size, USED_BY_SVC)) {
		tloge("%s: unmap failed\n", __func__);
		return -EFAULT;
	}

	return 0;
}

int ddr_sec_cfg(struct sglist *sg,
				int feature_id, int ddr_cfg_type)
{
	u32 buffer_size;
	u32 va;
	int ret;

	if (!sg)
		return ERROR;

	if (ddr_cfg_type != DDR_UNSET_SEC) {
		ret = __ddr_sec_cfg(sg, feature_id, ddr_cfg_type);
		return ret;
	}

	if (val_sglist_buf_size(sg, &buffer_size)) {
		tloge("%s: invalid sglist\n", __func__);
		return ERROR;
	}

	if (check_sglist_pid(sg, feature_id)) {
		tloge("%s: check sglist feature:%d failed\n",
		      __func__, feature_id);
		return ERROR;
	}

	ret = sre_mmap_scatter(&sg->info[0], sg->infoLength,
				&va, buffer_size, secure,
				non_cache, USED_BY_SVC);
	if (ret) {
		tloge("%s: map failed, svc %d\n", __func__, feature_id);
		return ERROR;
	}

	v7_dma_flush_range(va, va + buffer_size);
	ret = sre_munmap_scatter(va, buffer_size, USED_BY_SVC);
	if (ret) {
		tloge("%s: unmap failed, svc %d\n", __func__, feature_id);
		return ERROR;
	}

	ret = __ddr_sec_cfg(sg, feature_id, ddr_cfg_type);
	return ret;
}

int ddr_sec_clean_for_feature(u64 start_addr,
			      u64 end_addr,
			      enum SEC_FEATURE feature_id)
{
	paddr_t base_addr;
	u32 map_size;
	u32 map_addr = 0;
	int ret = 0;

	if (start_addr >= end_addr) {
		tloge("%s: start_addr >= end_addr, svc %d\n",
			__func__, feature_id);
		return ERROR;
	}

	base_addr = (paddr_t)start_addr;
	map_size = end_addr - start_addr;

	/*
	 * double mmap/unmap and cache flush
	 * workaround for SoC WE func,
	 * only enabled for baltimore.
	 */
	ret = sre_mmap(base_addr, map_size, &map_addr, secure, non_cache);
	if (ret) {
		tloge("%s, map base_addr=0x%x size=0x%x error\n",
		      __func__,	base_addr, map_size);
		return ERROR;
	}

	v7_dma_flush_range(map_addr, map_addr + map_size);
	ret = sre_unmap(map_addr, map_size);
	if (ret) {
		tloge("%s, unmap base_addr=0x%x size=0x%x fail\n",
		      __func__,	base_addr, map_size);
		return ERROR;
	}

	ret = __ddr_sec_clean_for_feature(start_addr, end_addr,
					  feature_id);
	return ret;
}
#endif

static s32 buffer_data_clean(paddr_t addr, u32 size)
{
	u32 kva;
	u32 map_size;
	paddr_t tmp_addr = addr;
	paddr_t end_addr = addr + size;

	for (; tmp_addr < end_addr; tmp_addr += SZ_64K) {
		if ((tmp_addr + SZ_64K - 1) < end_addr)
			map_size = SZ_64K;
		else
			map_size = end_addr - tmp_addr;

		if (sre_mmap(tmp_addr, map_size, &kva, secure, cache)) {
			tloge("map failed addr:0x%llx, size:0x%x\n",
				tmp_addr, map_size);
			return -ENOMEM;
		}

		(void)memset_s((void *)(uintptr_t)kva, map_size, 0, map_size);

		/*
		 * flash cache since we map memory is cacheable,
		 * using dma cache flush in MP platform instead
		 */
		v7_dma_flush_range(kva, kva + map_size);

		if (sre_unmap(kva, map_size)) {
			tloge("unmap failed addr:0x%llx, size:0x%x, kva:0x%x\n",
				tmp_addr, map_size, kva);
			return -EFAULT;
		}
	}

	return 0;
}

static int __sion_mcl_check(const struct mem_chunk_list *mcl, u32 array_size)
{
	if (mcl->protect_id != SEC_TASK_SEC || !mcl->buffer_addr) {
		tloge("invalid task id:%u\n", mcl->protect_id);
		return -EINVAL;
	}

	if (mcl->size != array_size) {
		tloge("illegal size of chunk:%u, sg info sz:%u, nents:%u\n",
			mcl->size, array_size, mcl->nents);
		return -EINVAL;
	}
	return 0;
}

static struct sglist *__create_sglist(const TEE_PAGEINFO *array, u32 nents)
{
	u32 i;
	u64 sglist_size;
	struct sglist *sglist = NULL;

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

	return sglist;
}

static void destory_sglist(struct sglist *sglist)
{
	u64 sglist_size;

	sglist_size = sglist->sglistSize;
	(void)memset_s(sglist, sglist_size, 0, sglist_size);
	SRE_MemFree(OS_MID_SYS, sglist);
}

static struct sglist *create_sglist(const struct mem_chunk_list *mcl)
{
	u32 array_size;
	struct sglist *sglist = NULL;
	TEE_PAGEINFO *array = NULL;

	array_size = mcl->nents * sizeof(*array);
	if (mcl->size != array_size)
		return NULL;

	array = (TEE_PAGEINFO *)SRE_MemAlloc(
		OS_MID_SYS, OS_MEM_DEFAULT_FSC_PT, array_size);
	if (!array) {
		tloge("%s, mem alloc failed\n", __func__);
		return NULL;
	}
	if (memcpy_s((void *)array, array_size, mcl->buffer_addr, array_size)) {
		tloge("%s, mem cpy failed\n", __func__);
		SRE_MemFree(OS_MID_SYS, array);
		return NULL;
	}

	sglist = __create_sglist(array, mcl->nents);
	if (!sglist)
		tloge("%s, create sglist failed\n", __func__);

	SRE_MemFree(OS_MID_SYS, array);
	return sglist;
}

static int __sion_set_ddr_sec(struct sglist *sg, paddr_t phys_addr, u32 size)
{
	int ret;

	/*
	 * config secure region
	 * if SMMU init, please config a static secure region ==> 1M
	 * else config an dynamic secure region  ==> region==> tui/iris
	 */
	ret = ddr_sec_cfg(sg, DDR_SEC_SION, DDR_SET_SEC);
	if (ret) {
		tloge("config sec_region fail\n");
		return ret;
	}

	/*
	 * when set sec success
	 * it is memset zero.
	 * and maybe it is failed, but we will return ree with failed.
	 */
	if (!ret && buffer_data_clean(phys_addr, size)) {
		tloge("buffer clean failed phys = 0x%llx, size = 0x%x\n",
			phys_addr, size);
		(void)ddr_sec_cfg(sg, DDR_SEC_SION, DDR_UNSET_SEC);
		return ret;
	}
	return 0;
}

static int sion_config(struct mem_chunk_list *mcl)
{
	int ret;
	u32 size;
	struct sglist *sg = NULL;
	u32 array_size = (mcl->nents) * sizeof(struct tz_pageinfo);

	if (__sion_mcl_check(mcl, array_size) || mcl->nents != MCL_NENTS) {
		tloge("%s:invalid params\n", __func__);
		return -EINVAL;
	}

	sg = create_sglist(mcl);
	if (!sg) {
		tloge("%s:alloc sglist fail\n", __func__);
		return -ENOMEM;
	}
	/* check addr overflow */
	size = sg->info[0].npages * PAGE_SIZE;
	if (size <= sg->info[0].npages) {
		tloge("illegal npages 0x%x\n", sg->info[0].npages);
		ret = -EINVAL;
		goto out;
	}

	if (addr_check(sg->info[0].phys_addr, size)) {
		tloge("illegal address\n");
		ret = -EINVAL;
		goto out;
	}

	ret = __sion_set_ddr_sec(sg, sg->info[0].phys_addr, size);
	if (ret) {
		tloge("sion_ddr_sec_config fail\n");
		ret = -EFAULT;
		goto out;
	}

	tloge("config: phys = 0x%llx, size = 0x%x, task_id = %u\n",
		sg->info[0].phys_addr, size, mcl->protect_id);

out:
	destory_sglist(sg);
	return ret;
}

static int __sion_unset_ddr_sec(const struct mem_chunk_list *mcl,
				struct sglist *sg)
{
	int ret;
	u32 i;
	u32 size;
	paddr_t phys_addr;

	/* Check addr sec */
	ret = ddr_sec_cfg(sg, DDR_SEC_SION, DDR_CHECK_SEC);
	if (ret) {
		tloge("Addr isn't sec_addr!\n");
		return -EPERM;
	}

	/* check TA sec mode */
	if (sion_pool_flag_get()) {
		tloge("SION_LOG:sion_pool_flag_get flag !=0!!\n");
		return -EPERM;
	}

	/* check addr overflow, if not, we will clean buffer */
	for (i = 0; i < mcl->nents; i++) {
		phys_addr = sg->info[i].phys_addr;
		size = sg->info[i].npages * PAGE_SIZE;
		if (size <= sg->info[i].npages) {
			tloge("illegal npages 0x%x\n", sg->info[i].npages);
			return -EFAULT;
		}

		tloge("unconfig: phys[%u] = 0x%llx, size[%u] = 0x%x\n", i,
			phys_addr, i, size);
		if (addr_check(phys_addr, size)) {
			tloge("illegal address\n");
			return -EFAULT;
		}

		/* clean the secure/protect memory */
		if (buffer_data_clean(phys_addr, size)) {
			tloge("buffer clean failed!\n");
			return -EFAULT;
		}
	}

	/* unconfig sg list of dynamic secure region */
	ret = ddr_sec_cfg(sg, DDR_SEC_SION, DDR_UNSET_SEC);
	if (ret) {
		tloge("unconfig sec_region fail\n");
		return -EFAULT;
	}

	return ret;
}

static int sion_unconfig(struct mem_chunk_list *mcl)
{
	int ret;
	struct sglist *sg = NULL;
	u32 array_size = (mcl->nents) * sizeof(struct tz_pageinfo);

	if (__sion_mcl_check(mcl, array_size)) {
		tloge("%s:invalid params\n", __func__);
		return -EINVAL;
	}

	sg = create_sglist(mcl);
	if (!sg) {
		tloge("%s: alloc sg fail\n", __func__);
		return -ENOMEM;
	}

	ret = __sion_unset_ddr_sec(mcl, sg);
	if (ret)
		tloge("sion_ddr_sec_uncfg failed\n");

	destory_sglist(sg);
	return ret;
}

static struct sec_buf *find_sec_buf(u32 id, u32 protect_id)
{
	struct list_head *pos = NULL;
	struct sec_buf *temp_sec_buf = NULL;

	if (id < MIN_SEC_ID || id >= MAX_SEC_ID || protect_id >= SEC_TASK_MAX)
		return NULL;

	list_for_each(pos, &sion_dev[protect_id].sbuf_head) {
		temp_sec_buf = list_entry(pos, struct sec_buf, list);
		if (id == temp_sec_buf->id)
			return temp_sec_buf;
	}

	return NULL;
}

static void secbuf_id_init(void)
{
	int i;

	for (i = 0; i < MAX_NUMS; i++) {
		id_array[i].id = MIN_SEC_ID + i;
		id_array[i].used = 0;
	}
}

static u16 alloc_sec_id(void)
{
	int i;

	for (i = 0; i < MAX_NUMS; i++) {
		if (!id_array[i].used) {
			id_array[i].used = 1;
			return id_array[i].id;
		}
	}

	tloge("%s:Too many buff that sion can't find valid id!\n", __func__);
	return 0;
}

static void free_sec_id(u16 id)
{
	int i;

	if (id < MIN_SEC_ID || id >= MAX_SEC_ID)
		return;

	i = id - MIN_SEC_ID;
	id_array[i].used = 0;
}

static int mem_chunk_check(const struct mem_chunk_list *mcl)
{
	if (!sion_init || !mcl) {
		tloge("%s:invalid mcl or sion not init!\n", __func__);
		return -EINVAL;
	}

	if (mcl->protect_id >= SEC_TASK_MAX) {
		tloge("%s:invalid task id:%u\n", __func__, mcl->protect_id);
		return -EINVAL;
	}
	return 0;
}

static int __sion_map_check(const struct mem_chunk_list *mcl)
{
	int ret;

	ret = mem_chunk_check(mcl);
	if (ret) {
		tloge("%s:invalid mcl!\n", __func__);
		return -EINVAL;
	}

	if ((mcl->cache != cache) && (mcl->cache != non_cache)) {
		tloge("invalid cacheable prop:%u\n", mcl->cache);
		return -EINVAL;
	}

	return 0;
}

static int __sion_map_iommu_check(const struct mem_chunk_list *mcl)
{
	int ret;
	struct smmu_domain *sdomain = NULL;

	ret = mem_chunk_check(mcl);
	if (ret) {
		tloge("%s:invalid mcl!\n", __func__);
		return -EINVAL;
	}

	sdomain = sion_dev[mcl->protect_id].sdomain;
	if (!sdomain) {
		tloge("sdomain for task %u not init yet\n", mcl->protect_id);
		return -ENODEV;
	}
	return 0;
}

static int __check_alloc_para(const struct mem_chunk_list *mcl)
{
	TEE_PAGEINFO *array = NULL;
	u32 protect_id;
	u32 array_size;
	u32 nents;

	if (!sion_init || !mcl) {
		tloge("%s:mcl is NULL!\n", __func__);
		return -EINVAL;
	}

	if (sbuf_num >= MAX_NUMS) {
		tloge("%s:buff num over, sbuf_num:%u\n", __func__, sbuf_num);
		return -EINVAL;
	}

	protect_id = mcl->protect_id;
	if (protect_id >= SEC_TASK_MAX) {
		tloge("%s:invalid task id:%u\n", __func__, protect_id);
		return -EINVAL;
	}

	nents = mcl->nents;
	array_size = nents * sizeof(*array);
	if (mcl->size != array_size || !mcl->buffer_addr || !nents ||
		nents > MAX_BUF_NENTS) {
		tloge("illegal size of chunk:%u, array:%u, nents:%u\n",
			mcl->size, array_size, nents);
		return -EINVAL;
	}

	return 0;
}

int sion_ddr_sec_cfg(u16 buffer_id, unsigned int size,
				int cached, int feature_id,
				int ddr_cfg_type)
{
	int ret;
	struct sec_buf *sbuf = NULL;
	unsigned int va;

	sbuf = find_sec_buf(buffer_id, SEC_TASK_SEC);
	if (!sbuf) {
		tloge("%s buffer id %u\n", __func__, buffer_id);
		return -EINVAL;
	}

	if (ddr_cfg_type == DDR_UNSET_SEC) {
		va = sion_mmap(sbuf->sg, size,
			feature_id, secure, cached, false);
		if (va != 0) {
			(void)memset_s((void *)(uintptr_t)va, size, 0, size);
			v7_dma_flush_range(va, va + size);
			(void)sion_munmap(sbuf->sg, va,
				size, feature_id, secure, false);
		}
	}

	ret = ddr_sec_cfg(sbuf->sg, feature_id, ddr_cfg_type);
	if (ret)
		tloge("%s config sec_region fail\n", __func__);

	return ret;
}

static u32 __sion_protect_config(const struct mem_chunk_list *mcl,
				const struct sec_buf *sbuf)
{
	int ret;
	u32 i;
	u32 size;
	u32 nents;
	u32 total_size = 0;
	paddr_t phys_addr;
	struct sglist *sg = sbuf->sg;

	if (mcl->protect_id != SEC_TASK_DRM)
		return 0;

	for (i = 0; i < mcl->nents; i++) {
		phys_addr = sg->info[i].phys_addr;
		size = sg->info[i].npages * PAGE_SIZE;
		if (addr_check(phys_addr, size) ||
			(size <= sg->info[i].npages) ||
			(size % SZ_64K != 0) ||
			!tzmp2_check_sec((u64)phys_addr, size)) {
			tloge("illegal address 0x%llx, sz 0x%x\n", phys_addr,
				size);
			goto error_handle;
		}

		total_size += size;
		if (total_size >= IOVA_POOL_SZ) {
			tloge("size 0x%x too long!!\n", total_size);
			goto error_handle;
		}

		ret = tzmp2_set_sec(phys_addr, size);
		if (ret) {
			tloge("alloc mem config protect fail!!\n");
			goto error_handle;
		}
	}
	return 0;

error_handle:
	nents = i;
	for (i = 0; i < nents; i++) {
		phys_addr = sg->info[i].phys_addr;
		size = sg->info[i].npages * PAGE_SIZE;
		tzmp2_unset_sec(phys_addr, size);
	}
	return -EINVAL;
}

static void __sion_protect_unconfig(u32 protect_id, const struct sec_buf *sbuf)
{
	u32 i;
	u32 size;
	paddr_t phys_addr;
	struct sglist *sg = sbuf->sg;

	if (protect_id != SEC_TASK_DRM)
		return;

	for (i = 0; i < sbuf->nents; i++) {
		phys_addr = sg->info[i].phys_addr;
		size = sg->info[i].npages * PAGE_SIZE;
		tzmp2_unset_sec(phys_addr, size);
	}
}

static void __sion_sbuf_unmap_va(struct sec_buf *sbuf, u32 protect_id)
{
	if (sbuf->iova_refs) {
		tloge("Warn:buff has maps:iova 0x%x cnt %u\n", sbuf->iova,
			sbuf->iova_refs);
		(void)hisi_smmu_destory_map(sion_dev[protect_id].sdomain,
					    sbuf->iova, sbuf->size);
		gen_pool_free(sion_dev[protect_id].iova_pool, sbuf->iova,
			      sbuf->size);
		sbuf->iova = 0;
		sbuf->iova_refs = 0;
	}

	if (sbuf->kva_refs) {
		tloge("Warn:buff has maps:kva cnt %u\n", sbuf->kva_refs);
		(void)sre_munmap_scatter(sbuf->kva, sbuf->size, USED_BY_SVC);
		sbuf->kva = 0;
		sbuf->kva_refs = 0;
	}

	if (sbuf->uva_refs) {
		tloge("buff has maps:uva cnt %u\n", sbuf->uva_refs);
		(void)sre_munmap_scatter(sbuf->uva, sbuf->size, USED_BY_USR);
		sbuf->uva = 0;
		sbuf->uva_refs = 0;
	}
}

static int __sion_iommu_map_sbuf(const struct mem_chunk_list *mcl,
				const struct sec_buf *sbuf)
{
	int ret;
	u32 i, j;
	u32 size;
	paddr_t phys_addr;
	u32 iova = sbuf->iova;
	struct smmu_domain *sdomain = sion_dev[mcl->protect_id].sdomain;

	for (i = 0; i < sbuf->nents; i++) {
		phys_addr = sbuf->sg->info[i].phys_addr;
		size = sbuf->sg->info[i].npages * PAGE_SIZE;
		if (mcl->protect_id == SEC_TASK_DRM)
			ret = hisi_smmu_create_map(sdomain,
						phys_addr, iova, size, 0);
		else
			ret = smmu_handle_mapping(sdomain, iova,
						phys_addr, size, mcl->prot);
		if (ret) {
			tloge("iommu map sbuf fail\n");
			goto map_sbuf_fail;
		}
		iova += size;
	}

	return 0;

map_sbuf_fail:
	iova = sbuf->iova;
	for (j = 0; j < i; j++) {
		size = sbuf->sg->info[j].npages * PAGE_SIZE;
		if (mcl->protect_id == SEC_TASK_DRM)
			(void)hisi_smmu_destory_map(sdomain, iova, size);
		else
			(void)smmu_handle_unmapping(sdomain, iova, size);
		iova += size;
	}

	return -EINVAL;
}

static int __sion_iommu_destory_map(const struct mem_chunk_list *mcl,
				const struct sec_buf *sbuf)
{
	int ret;
	u32 unmapped_size;
	u32 protect_id = mcl->protect_id;
	struct smmu_domain *sdomain = sion_dev[protect_id].sdomain;

	if (protect_id == SEC_TASK_DRM) {
		ret = hisi_smmu_destory_map(sdomain, sbuf->iova, sbuf->size);
		if (ret) {
			tloge("%s fail\n", __func__);
			return ret;
		}
	} else {
		unmapped_size = smmu_handle_unmapping(sdomain,
						mcl->va, sbuf->size);
		if (unmapped_size != sbuf->size) {
			tloge("%s failed:iova:0x%x unmapped size:0x%x\n",
			__func__, mcl->va, unmapped_size);
			return -EFAULT;
		}
	}
#ifdef TEE_SUPPORT_SMMUV3
	secsmmu_tlb_inv_asid(mcl->smmuid, mcl->sid, mcl->ssid);
#endif
	return 0;
}

static int __sion_iommu_iova_alloc(const struct mem_chunk_list *mcl,
				const struct sec_buf *sbuf, u32 *iova)
{
	u32 va;
	u32 protect_id;

	protect_id = mcl->protect_id;
	switch (protect_id) {
	case SEC_TASK_DRM:
		va = gen_pool_alloc(sion_dev[protect_id].iova_pool,
					sbuf->size);
		if (!va) {
			tloge("%s,gen pool alloc failed in iommu\n", __func__);
			return -ENOMEM;
		}
		break;

	case SEC_TASK_SEC:
		va = mcl->va;
		break;

	default:
		return -ENOMEM;
	}
	*iova = va;
	return 0;
}

static void __sion_iommu_iova_free(const struct mem_chunk_list *mcl,
				const struct sec_buf *sbuf)
{
	u32 protect_id;

	protect_id = mcl->protect_id;
	switch (protect_id) {
	case SEC_TASK_DRM:
		gen_pool_free(sion_dev[protect_id].iova_pool,
			sbuf->iova, sbuf->size);
		break;
	default:
		return;
	}
}

static void __sion_ddrc_ca_rd_cfg(const struct mem_chunk_list *mcl)
{
	u32 protect_id;

	protect_id = mcl->protect_id;
	if (protect_id != SEC_TASK_DRM)
		return;

	if (list_empty(&sion_dev[protect_id].sbuf_head))
		ddrc_ca_rd_cfg(DIS_CA_RD);
}

static int __sion_sbuf_clean(u32 protect_id, struct sec_buf *sbuf)
{
	u32 kva;
	struct sglist *sg = sbuf->sg;

	if (protect_id != SEC_TASK_DRM)
		return 0;

	if (sre_mmap_scatter(&sg->info[0], sbuf->nents,
		&kva, sbuf->size, secure, cache, USED_BY_SVC)) {
		tloge("failed to map kva for clean buff\n");
		return -EFAULT;
	}

	(void)memset_s((void *)(uintptr_t)kva, sbuf->size, 0, sbuf->size);
	v7_dma_flush_range(kva, kva + sbuf->size);
	(void)sre_munmap_scatter(kva, sbuf->size, USED_BY_SVC);

#ifdef CONFIG_SOC_WE_WORKAROUND
	if (secsg_dma_flush_nc(sbuf)) {
		tloge("%s: failed to flush_nc\n", __func__);
		return -EFAULT;
	}
#endif
	return 0;
}

static void __sion_sbuf_fill(const struct mem_chunk_list *mcl, u16 id,
				struct sec_buf *sbuf)
{
	u32 i;

	sbuf->id = id;
	sbuf->nents = mcl->nents;
	list_add_tail(&sbuf->list, &sion_dev[mcl->protect_id].sbuf_head);

	for (i = 0; i < mcl->nents; i++)
		sbuf->size += sbuf->sg->info[i].npages * PAGE_SIZE;
}

static int sion_alloc(struct mem_chunk_list *mcl)
{
	u16 id;
	struct sec_buf *sbuf = NULL;

	if (__check_alloc_para(mcl)) {
		tloge("%s, __check_alloc_para fail\n", __func__);
		return -EINVAL;
	}

	if (mcl->protect_id != SEC_TASK_DRM)
		tloge("into:%s, protectid:%u\n", __func__, mcl->protect_id);

	id = alloc_sec_id();
	if (!id) {
		tloge("%s, alloc_sec_id fail\n", __func__);
		return -ENOMEM;
	}

	sbuf = (struct sec_buf *)SRE_MemAlloc(
		OS_MID_SYS, OS_MEM_DEFAULT_FSC_PT, sizeof(*sbuf));
	if (!sbuf) {
		tloge("%s, sbuf SRE_MemAlloc fail\n", __func__);
		free_sec_id(id);
		return -ENOMEM;
	}
	(void)memset_s((void *)sbuf, sizeof(*sbuf), 0, sizeof(*sbuf));

	sbuf->sg = create_sglist(mcl);
	if (!sbuf->sg) {
		tloge("%s, sglist SRE_MemAlloc fail\n", __func__);
		SRE_MemFree(OS_MID_SYS, sbuf);
		free_sec_id(id);
		return -ENOMEM;
	}
	if (__sion_protect_config(mcl, sbuf)) {
		tloge("%s, __ion_tzmp2_set_sec fail\n", __func__);
		goto error;
	}
	__sion_sbuf_fill(mcl, id, sbuf);

	mcl->buff_id = (u32)id;
	if (mcl->protect_id == SEC_TASK_TINY) {
		ddr_sec_cfg(sbuf->sg, DDR_SEC_TINY, DDR_SET_SEC);
		tloge("%s, ddr sec cfg\n", __func__);
	}
	sbuf_num++;

	if (mcl->protect_id != SEC_TASK_DRM)
		tloge("out:%s, protectid:%u\n", __func__, mcl->protect_id);

	return 0;
error:
	free_sec_id(id);
	destory_sglist(sbuf->sg);
	SRE_MemFree(OS_MID_SYS, sbuf);
	return -EINVAL;
}

static int sion_free(struct mem_chunk_list *mcl)
{
	int ret;
	u32 protect_id;
	struct sec_buf *sbuf = NULL;

	ret = mem_chunk_check(mcl);
	if (ret) {
		tloge("%s:invalid mcl!\n", __func__);
		return -EINVAL;
	}

	protect_id = mcl->protect_id;
	sbuf = find_sec_buf(mcl->buff_id, protect_id);
	if (!sbuf) {
		tloge("%s:incorrect buffer id\n", __func__);
		return -EINVAL;
	}

	__sion_sbuf_unmap_va(sbuf, protect_id);
	ret = __sion_sbuf_clean(protect_id, sbuf);
	if (ret) {
		tloge("failed to clean buff\n");
		return -EFAULT;
	}

	list_del(&sbuf->list);
	sbuf_num--;

	__sion_protect_unconfig(protect_id, sbuf);
	if (mcl->protect_id == SEC_TASK_TINY) {
		ddr_sec_cfg(sbuf->sg, DDR_SEC_TINY, DDR_UNSET_SEC);
		tloge("%s, ddr sec cfg unset\n", __func__);
	}
	free_sec_id(sbuf->id);
	destory_sglist(sbuf->sg);
	sbuf->sg = NULL;
	SRE_MemFree(OS_MID_SYS, sbuf);
	sbuf = NULL;

	__sion_ddrc_ca_rd_cfg(mcl);
	return 0;
}

int sion_map_iommu(struct mem_chunk_list *mcl)
{
	int ret;
	u32 iova, size, protect_id;
	struct sec_buf *sbuf = NULL;

	if (__sion_map_iommu_check(mcl)) {
		tloge("%s:invalid mcl!\n", __func__);
		return -EINVAL;
	}

	protect_id = mcl->protect_id;
	sbuf = find_sec_buf(mcl->buff_id, protect_id);
	if (!sbuf) {
		tloge("map_iommu:incorrect buffer id 0x%x\n", mcl->buff_id);
		return -EINVAL;
	}

	size = ALIGN(mcl->size, SZ_64K);
	if (protect_id == SEC_TASK_DRM) {
		if (!mcl->size || size > sbuf->size) {
			tloge("map_iommu:invalid map sz:0x%x buff sz:0x%x\n",
				mcl->size, sbuf->size);
			return -EINVAL;
		}
		if (sbuf->iova_refs >= MAX_MAP_CNT) {
			tloge("the buffer map iommu too many times\n");
			return -EINVAL;
		}
		if (sbuf->iova_refs) {
			mcl->va = sbuf->iova;
			sbuf->iova_refs++;
			return 0;
		}
	}

	ret = __sion_iommu_iova_alloc(mcl, sbuf, &iova);
	if (ret) {
		tloge("alloc iova failed in iommu\n");
		return -ENOMEM;
	}
	sbuf->iova = iova;
	if (__sion_iommu_map_sbuf(mcl, sbuf)) {
		tloge("%s: __sion_iommu_map_sbuf fail\n", __func__);
		goto map_fail;
	}
	mcl->va = sbuf->iova;

	if (protect_id == SEC_TASK_DRM)
		sbuf->iova_refs++;
	else
		mcl->size = sbuf->size;

	return 0;

map_fail:
	__sion_iommu_iova_free(mcl, sbuf);
	sbuf->iova = 0;

	return -EFAULT;
}

int sion_unmap_iommu(struct mem_chunk_list *mcl)
{
	int ret;
	u32 protect_id;
	struct sec_buf *sbuf = NULL;

	if (__sion_map_iommu_check(mcl)) {
		tloge("%s:invalid mcl!\n", __func__);
		return -EINVAL;
	}

	protect_id = mcl->protect_id;
	sbuf = find_sec_buf(mcl->buff_id, protect_id);
	if (!sbuf) {
		tloge("unmap_iommu:incorrect buffer id 0x%x\n", mcl->buff_id);
		return -EINVAL;
	}

	if (protect_id == SEC_TASK_DRM) {
		if (!sbuf->iova_refs) {
			tloge("buffer not map iommu yet\n");
			return -EINVAL;
		}
		sbuf->iova_refs--;
		if (sbuf->iova_refs) {
			tloge("there are %u tasks already map iommu\n",
				sbuf->iova_refs);
			return 0;
		}
	}

	ret = __sion_iommu_destory_map(mcl, sbuf);
	if (ret) {
		tloge("%s fail\n", __func__);
		return ret;
	}

	__sion_iommu_iova_free(mcl, sbuf);
	sbuf->iova = 0;
	return 0;
}

int sion_map_kernel(struct mem_chunk_list *mcl)
{
	int ret;
	u32 size;
	u32 kva;
	struct sec_buf *sbuf = NULL;

	ret = __sion_map_check(mcl);
	if (ret) {
		tloge("%s:invalid mcl!\n", __func__);
		return -EINVAL;
	}

	sbuf = find_sec_buf(mcl->buff_id, mcl->protect_id);
	if (!sbuf) {
		tloge("map_kernel:incorrect buffer id %u\n", mcl->buff_id);
		return -EINVAL;
	}

	size = ALIGN(mcl->size, SZ_64K);
	if (!mcl->size || size > sbuf->size) {
		tloge("map_kernel:invalid map sz:0x%x buff sz:0x%x\n",
			mcl->size, sbuf->size);
		return -EINVAL;
	}

	if (sbuf->kva_refs >= MAX_MAP_CNT) {
		tloge("the buffer map kernel so much times\n");
		return -EINVAL;
	}

	if (sbuf->kva_refs) {
		mcl->va = sbuf->kva;
		sbuf->kva_refs++;
		return 0;
	}

	ret = sre_mmap_scatter(&sbuf->sg->info[0], sbuf->nents,
		&kva, sbuf->size, secure, mcl->cache, USED_BY_SVC);
	if (ret) {
		tloge("map kernel failed, buff:%u\n", mcl->buff_id);
		return -ENOMEM;
	}

	sbuf->kva_refs++;
	sbuf->kva = kva;
	mcl->va = kva;
	return 0;
}

int sion_unmap_kernel(struct mem_chunk_list *mcl)
{
	int ret;
	struct sec_buf *sbuf = NULL;

	ret = mem_chunk_check(mcl);
	if (ret) {
		tloge("%s:invalid mcl!\n", __func__);
		return -EINVAL;
	}

	sbuf = find_sec_buf(mcl->buff_id, mcl->protect_id);
	if (!sbuf) {
		tloge("unmap_kernel:incorrect buffer id %u\n", mcl->buff_id);
		return -EINVAL;
	}

	if (!sbuf->kva_refs) {
		tloge("buffer not map kernel yet\n");
		return -EINVAL;
	}

	sbuf->kva_refs--;
	if (sbuf->kva_refs) {
		tloge("there are %u tasks already map kernel\n",
			sbuf->kva_refs);
		return 0;
	}

	ret = sre_munmap_scatter(sbuf->kva, sbuf->size, USED_BY_SVC);
	if (ret) {
		tloge("unmap kernel failed, buff:%u\n", mcl->buff_id);
		return -ENOMEM;
	}

	sbuf->kva = 0;
	return 0;
}

int sion_map_user(struct mem_chunk_list *mcl)
{
	u32 uva;
	int ret;
	u32 size;
	struct sec_buf *sbuf = NULL;

	ret = __sion_map_check(mcl);
	if (ret) {
		tloge("%s:invalid mcl!\n", __func__);
		return -EINVAL;
	}

	sbuf = find_sec_buf(mcl->buff_id, mcl->protect_id);
	if (!sbuf) {
		tloge("map_user:incorrect buffer id:%u\n", mcl->buff_id);
		return -EINVAL;
	}

	size = ALIGN(mcl->size, SZ_64K);
	if (!mcl->size || size > sbuf->size) {
		tloge("invalid map user sz:0x%x, buff sz:0x%x\n", mcl->size,
			sbuf->size);
		return -EINVAL;
	}

	if (sbuf->uva_refs >= MAX_MAP_CNT) {
		tloge("the buffer map user so much times\n");
		return -EINVAL;
	}

	if (sbuf->uva_refs) {
		mcl->va = sbuf->uva;
		sbuf->uva_refs++;
		return 0;
	}

	ret = sre_mmap_scatter(&sbuf->sg->info[0], sbuf->nents,
		&uva, sbuf->size, secure, mcl->cache, USED_BY_USR);
	if (ret) {
		tloge("map user failed, buff:%u\n", mcl->buff_id);
		return -ENOMEM;
	}

	sbuf->uva_refs++;
	sbuf->uva = uva;
	mcl->va = uva;
	return 0;
}

int sion_unmap_user(struct mem_chunk_list *mcl)
{
	int ret;
	struct sec_buf *sbuf = NULL;

	ret = mem_chunk_check(mcl);
	if (ret) {
		tloge("%s:invalid mcl!\n", __func__);
		return -EINVAL;
	}

	sbuf = find_sec_buf(mcl->buff_id, mcl->protect_id);
	if (!sbuf) {
		tloge("unmap_user:incorrect buffer id %u\n", mcl->buff_id);
		return -EINVAL;
	}

	if (!sbuf->uva_refs) {
		tloge("buffer not map user yet\n");
		return -EINVAL;
	}

	sbuf->uva_refs--;
	if (sbuf->uva_refs) {
		tloge("there are %u tasks already map user\n", sbuf->uva_refs);
		return 0;
	}

	ret = sre_munmap_scatter(sbuf->uva, sbuf->size, USED_BY_USR);
	if (ret) {
		tloge("unmap user failed, buff:%u\n", mcl->buff_id);
		return -ENOMEM;
	}

	sbuf->uva = 0;
	return 0;
}

s32 __sion_ioctl(int ion_ta_tag, void *mcl)
{
	s32 ret = -EINVAL;

	if (!mcl)
		return -EINVAL;

	switch (ion_ta_tag) {
	case ION_SEC_CMD_ALLOC:
		ret = sion_alloc((struct mem_chunk_list *)mcl);
		break;
	case ION_SEC_CMD_FREE:
		ret = sion_free((struct mem_chunk_list *)mcl);
		break;
	case ION_SEC_CMD_MAP_IOMMU:
		ret = sion_map_iommu((struct mem_chunk_list *)mcl);
		break;
	case ION_SEC_CMD_UNMAP_IOMMU:
		ret = sion_unmap_iommu((struct mem_chunk_list *)mcl);
		break;
	case ION_SEC_CMD_TABLE_CLEAN:
		ret = sion_unconfig((struct mem_chunk_list *)mcl);
		break;
	case ION_SEC_CMD_TABLE_SET:
		ret = sion_config((struct mem_chunk_list *)mcl);
		break;
#ifdef SECMEM_UT
	case ION_SEC_CMD_TEST:
		break;
#endif
	default:
		tloge("incorrect ion_ta_tag\n");
		return -EFAULT;
	}

	tlogd("__ion_ioctl ion_ta_tag = %d finish\n", ion_ta_tag);
	return ret;
}

/*
 * check [add, addr + size) is sec memory or not.
 * if it is sec memory, return 1, otherwise return 0.
 */
int hisi_sion_check_mem(paddr_t addr, unsigned int size,
				unsigned int protect_id)
{
	u32 id;
	int ret;
	u32 sg_size;
	struct sglist *sg = NULL;
	struct sec_buf *sbuf = NULL;

	if (!sion_init) {
		tloge("%s:sion is not init yet!\n", __func__);
		return 0;
	}

	if (protect_id == SEC_TASK_SEC) {
		if (addr_check(addr, size))
			return 0;

		sg_size = sizeof(struct sglist) + sizeof(struct tz_pageinfo);
		sg = (struct sglist *)SRE_MemAlloc(OS_MID_SYS,
			OS_MEM_DEFAULT_FSC_PT, sg_size);
		if (!sg) {
			tloge("sion_config alloc sglist fail\n");
			return -ENOMEM;
		}
		(void)memset_s((void *)sg, sg_size, 0, sg_size);

		sg->info[0].phys_addr = addr;
		sg->info[0].npages = size / PAGE_SIZE;
		sg->infoLength = 1;
		sg->sglistSize = sg_size;

		ret = ddr_sec_cfg(sg, DDR_SEC_SION, DDR_CHECK_SEC);

		SRE_MemFree(OS_MID_SYS, sg);

		if (ret)
			return 0; /* check fail */

		return 1; /* check succ */
	} else if (protect_id == SEC_TASK_DRM) {
		id = (u32)addr;
		if ((paddr_t)id != addr)
			return 0;

		sbuf = find_sec_buf(id, protect_id);
		if (!sbuf) {
			tloge("error id:%u\n", id);
			return 0;
		}

		if (!size || sbuf->size < ALIGN(size, SZ_64K)) {
			tloge("invalid check sz:0x%x buff sz:0x%x\n", size,
				sbuf->size);
			return 0;
		}

		return 1;
	}

	return 0;
}

static int validate_sglist(struct sglist *sglist, u32 size, u32 *buf_size,
				int feature_id, int mode)
{
	u32 buffer_size;

	if (val_sglist_buf_size(sglist, &buffer_size)) {
		tloge("%s: invalid sglist\n", __func__);
		return -EINVAL;
	}

	if (buffer_size < size) {
		tloge("invalid sglist total size:0x%x, input size:0x%x\n",
			buffer_size, size);
		return -EINVAL;
	}

	if (mode == secure) {
		if (check_sglist_pid(sglist, feature_id)) {
			tloge("check sglist feature:0x%x failed\n",
				feature_id);
			return -EINVAL;
		}
	} else {
#ifndef CONFIG_PRODUCT_ARMPC
		if (!is_isp_rdr_addr(sglist) && check_unsec_sglist(sglist)) {
			tloge("check non sec sglist fail\n");
			return -EINVAL;
		}
#endif
	}

	*buf_size = buffer_size;

	return 0;
}

int siommu_map(struct smmu_domain *sdomain, struct sglist *sglist, u32 iova,
				u32 size, int prot, int mode)
{
	(void)mode;
	paddr_t phys_addr;
	u32 seg_size;
	u32 tmp_va;
	u32 i, j;

	/* smmu can support iova = 0 */
	if (!sdomain || !sglist || !size) {
		tloge("%s:invalid input\n", __func__);
		return -EINVAL;
	}

	size = ALIGN(size, SZ_64K);
	tmp_va = iova;
	for (i = 0; i < sglist->infoLength; i++) {
		phys_addr = sglist->info[i].phys_addr;
		seg_size = sglist->info[i].npages * PAGE_SIZE;
		if (smmu_handle_mapping(sdomain, tmp_va, phys_addr, seg_size,
					prot)) {
			tloge("iommu map fail\n");
			goto map_fail;
		}
		tmp_va += seg_size;
	}

	return 0;

map_fail:
	tmp_va = iova;
	for (j = 0; j < i; j++) {
		seg_size = sglist->info[j].npages * PAGE_SIZE;
		(void)smmu_handle_unmapping(sdomain, tmp_va, seg_size);
		tmp_va += seg_size;
	}

	return -EFAULT;
}

int siommu_unmap(struct smmu_domain *sdomain, struct sglist *sglist,
				u32 iova, u32 size, int mode)
{
	(void)sglist;
	(void)mode;
	u32 unmapped_size;

	/* smmu can support iova = 0 */
	if (!sdomain || !size) {
		tloge("%s:invalid input\n", __func__);
		return -EINVAL;
	}

	unmapped_size = smmu_handle_unmapping(sdomain, iova, size);
	if (unmapped_size != size) {
		tloge("%s: unmap iova failed:secion:0x%x unmapped size:0x%x\n",
			__func__, iova, unmapped_size);
		return -EFAULT;
	}

	return 0;
}

#ifdef TEE_SUPPORT_SMMUV3
static void siommu_pgtbl_sec_cfg(u32 pgtable_addr, u32 pgtable_size)
{
	int ret;
	TEE_PAGEINFO array;
	struct sglist *sg = NULL;

	if (pgtable_addr + pgtable_size <= pgtable_addr)
		return;

	array.phys_addr = pgtable_addr;
	array.npages = pgtable_size >> PAGE_SHIFT;
	sg = __create_sglist(&array, PAGEINFO_NUM);
	if (!sg) {
		tloge("%s:alloc sglist fail\n", __func__);
		return;
	}

	ret = ddr_sec_cfg(sg, DDR_SEC_PGTABLE, DDR_SET_SEC);
	if (ret)
		tloge("config sec_region fail\n");

	destory_sglist(sg);
}

static int __create_siommu_domain(void)
{
	struct smmu_domain *sdomain = NULL;

	siommu_pgtbl_sec_cfg(ISP_PGTABLE_BASE, ISP_PGTABLE_SIZE);
	sdomain = siommu_domain_alloc(ISP_PGTABLE_BASE, ISP_PGTABLE_SIZE);

	if (!sdomain) {
		tloge("%s, alloc siommu domain failed\n", __func__);
		return -EFAULT;
	}

	sion_dev[SEC_TASK_SEC].sdomain = sdomain;
	return 0;
}
#endif

struct smmu_domain *create_siommu_domain(void)
{
	return sion_dev[SEC_TASK_SEC].sdomain;
}

void destory_siommu_domain(struct smmu_domain *sdomain)
{
	if (!sdomain) {
		tloge("invalid sdomain\n");
		return;
	}

	siommu_domain_free(sdomain);
	sion_dev[SEC_TASK_SEC].sdomain = NULL;
}

unsigned int sion_mmap(void *sglist, unsigned int size, unsigned int feature_id,
				int mode, int cached, int used_by_ta)
{
	int ret;
	u32 va;
	u32 buf_size;
	cache_mode_type cache_mode;
	user_mode_type user_mode;
	struct sglist *sg = (struct sglist *)sglist;

	if (!sglist || !size || feature_id >= DDR_SEC_MAX) {
		tloge("%s:invalid input\n", __func__);
		return 0;
	}

	if ((mode != secure) && (mode != non_secure)) {
		tloge("%s:invalid secure mode\n", __func__);
		return 0;
	}

	if (validate_sglist(sg, size, &buf_size, feature_id, mode)) {
		tloge("%s: invalid sglist\n", __func__);
		return 0;
	}

	cache_mode = cached ? cache : non_cache;
	user_mode = used_by_ta ? USED_BY_USR : USED_BY_SVC;

	size = ALIGN(size, SZ_4K);
	ret = sre_mmap_scatter(&sg->info[0], sg->infoLength, &va, buf_size,
		mode, cache_mode, user_mode);
	if (ret) {
		tloge("%s failed, svc %u, size 0x%x\n", __func__, feature_id,
			size);
		return 0;
	}

	return va;
}

int sion_munmap(void *sglist, unsigned int va, unsigned int size,
				unsigned int feature_id,
				int mode, int used_by_ta)
{
	int ret;
	u32 buf_size;
	user_mode_type user_mode;
	struct sglist *sg = (struct sglist *)sglist;

	if (!sglist || !va || !size || feature_id >= DDR_SEC_MAX) {
		tloge("%s:invalid input\n", __func__);
		return -EINVAL;
	}

	if ((mode != secure) && (mode != non_secure)) {
		tloge("%s:invalid secure mode\n", __func__);
		return -EINVAL;
	}

	if (validate_sglist(sg, size, &buf_size, feature_id, mode)) {
		tloge("%s: invalid sglist\n", __func__);
		return -EINVAL;
	}

	user_mode = used_by_ta ? USED_BY_USR : USED_BY_SVC;

	ret = sre_munmap_scatter(va, buf_size, user_mode);
	if (ret) {
		tloge("%s failed, svc %u, size 0x%x\n", __func__, feature_id,
			size);
		return -ENOMEM;
	}

	return 0;
}

static unsigned int featureid_to_protectid(unsigned int feature_id)
{
	switch (feature_id) {
	case DDR_SEC_TINY:
		return SEC_TASK_TINY;
	case DDR_SEC_FACE:
	case DDR_SEC_EID:
		return SEC_TASK_SEC;
	default:
		break;
	}

	return SEC_TASK_MAX;
}

struct sglist *sion_get_sglist_from_sfd(unsigned int sfd,
				unsigned int feature_id)
{
	struct sec_buf *sbuf = NULL;
	unsigned int protect_id = featureid_to_protectid(feature_id);

	sbuf = find_sec_buf(sfd, protect_id);
	if (!sbuf) {
		tloge("%s find sbuf failed, sfd:0x%x, feature:0x%x\n",
			__func__, sfd, feature_id);
		return NULL;
	}

	return sbuf->sg;
}

unsigned int sion_mmap_sfd(unsigned int sfd, unsigned int size,
				unsigned int feature_id, int mode,
				int cached, int used_by_ta)
{
	struct sec_buf *sbuf = NULL;
	unsigned int protect_id = featureid_to_protectid(feature_id);

	sbuf = find_sec_buf(sfd, protect_id);
	if (!sbuf) {
		tloge("%s find sbuf failed, sfd:0x%x\n", __func__, sfd);
		return 0;
	}
	return sion_mmap(sbuf->sg, size, feature_id, mode, cached, used_by_ta);
}

int sion_munmap_sfd(unsigned int sfd, unsigned int va,
				unsigned int size, unsigned int feature_id,
				int mode, int used_by_ta)
{
	struct sec_buf *sbuf = NULL;
	unsigned int protect_id = featureid_to_protectid(feature_id);

	sbuf = find_sec_buf(sfd, protect_id);
	if (!sbuf) {
		tloge("%s find sbuf failed, sfd:0x%x\n", __func__, sfd);
		return -EINVAL;
	}
	return sion_munmap(sbuf->sg, va, size, feature_id, mode, used_by_ta);
}

#ifdef SECMEM_UT
void sion_show_pte(u32 protect_id, u32 iova, u32 size)
{
	struct smmu_domain *sdomain = NULL;

	if (!sion_init || protect_id >= SEC_TASK_MAX) {
		tloge("invalid task id:%u\n", protect_id);
		return;
	}

	if (!iova || !size) {
		tloge("invalid input para\n");
		return;
	}

	sdomain = sion_dev[protect_id].sdomain;
	if (!sdomain) {
		tloge("smmu domain for task %u not init yet\n", protect_id);
		return;
	}

	(void)hisi_dump_pgtable(sdomain, iova, size);
}
#endif

s32 sion_client_init(void)
{
	if (tzmp2_init()) {
		tloge("tzmp2_init fail\n");
		return -EINVAL;
	}

	if (sec_region_init()) {
		tloge("sec_region_init fail\n");
		return -EINVAL;
	}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_MIAMICW)
	struct gen_pool *pool = NULL;
	int i, j;

	for (i = 0; i < SEC_TASK_MAX; i++) {
		pool = gen_pool_create(SZ_64K, IOVA_POOL_SZ, SEC_MIN_ORDER);
		if (!pool) {
			tloge("gen_pool[%d] create fail\n", i);
			goto detroy_pool;
		}

		sion_dev[i].iova_pool = pool;
		sion_dev[i].sdomain = NULL;
		INIT_LIST_HEAD(&sion_dev[i].sbuf_head);
	}

	secbuf_id_init();

#ifndef CONFIG_PRODUCT_ARMPC
	if (hisi_siommu_pgtable_init())
		goto detroy_pool;
#endif

#ifdef TEE_SUPPORT_SMMUV3
	int ret = __create_siommu_domain();
	if (ret) {
		tloge("%s, create siommu domain fail\n", __func__);
		goto detroy_pool;
	}
#endif

	sion_recycle_init();

	sion_init = 1;
#endif
	return 0;

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_MIAMICW)
detroy_pool:
	for (j = 0; j < i; j++)
		gen_pool_destory(sion_dev[j].iova_pool);

	return -ENOMEM;
#endif
}

/* hack for `HANDLE_SYSCALL` */
#include <hmdrv_stub.h>
#define sion_permission(t, p)  SYSCALL_PERMISSION(t, p, \
						SECMEM_GROUP_PERMISSION)
#define sion_sg_size(tmp) (((struct sglist *)(tmp))->sglistSize)

static int sion_second_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
	uint32_t ret;
	uint32_t tmp;
	uint64_t *args = NULL;
	if (params == NULL || params->args == 0)
		return -1;
	args = (uint64_t *)(uintptr_t)params->args;

	HANDLE_SYSCALL(swi_id) {
		sion_permission(SW_SYSCALL_SECMEM_DDR_CFG, permissions)
		tmp = args[0];
		if (!tmp) {
			args[0] = -EINVAL;
			return 0;
		}
		ACCESS_CHECK_A64(tmp, sizeof(struct sglist));
		ACCESS_CHECK_A64(args[0], sion_sg_size(tmp));
		ACCESS_READ_RIGHT_CHECK(args[0], sion_sg_size(args[0]));
		ret = (uint32_t)ddr_sec_cfg((struct sglist *)(uintptr_t)args[0],
				(int)args[1], (int)args[2]);
		args[0] = ret;
		SYSCALL_END

		sion_permission(SW_SYSCALL_SECMEM_ION_MMAP_SFD, permissions)
		ret = (uint32_t)sion_mmap_sfd((unsigned int)args[0],
			(unsigned int)args[1], (unsigned int)args[2],
			(int)args[3], (int)args[4], USED_BY_USR);
		args[0] = ret;
		SYSCALL_END

		sion_permission(SW_SYSCALL_SECMEM_ION_MUNMAP_SFD, permissions)
		ret = (uint32_t)sion_munmap_sfd((unsigned int)args[0],
			(unsigned int)args[1], (unsigned int)args[2],
			(unsigned int)args[3], (int)args[4], USED_BY_USR);
		args[0] = ret;
		SYSCALL_END

		sion_permission(SW_SYSCALL_SECMEM_DDR_CFG_SFD, permissions)
		ret = (uint32_t)sion_ddr_sec_cfg((uint16_t)args[0],
				(unsigned int)args[1], (int)args[2],
				(int)args[3], (int)args[4]);
		args[0] = ret;
		SYSCALL_END
	default:
		return -EINVAL;
	}
	return 0;
}

int sion_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
	uint32_t ret;
	uint32_t tmp;
	uint64_t *args = NULL;

	/*
	 * According to ARM AAPCS arguments from 5-> in a function call
	 * are stored on the stack, which in this case is pointer by
	 * user sp. Our own TrustedCore also push FP and LR on the stack
	 * just before SWI, so skip them
	 */

	if (params == NULL || params->args == 0)
		return -1;
	args = (uint64_t *)(uintptr_t)params->args;

	HANDLE_SYSCALL(swi_id) {
		sion_permission(SW_SYSCALL_SECMEM_ION_IOCTL_SECTA, permissions)
		if (!args[1]) {
			args[0] = -EINVAL;
			return 0;
		}
		ACCESS_CHECK_A64(args[1], sizeof(struct mem_chunk_list));
		ACCESS_CHECK_A64(((struct mem_chunk_list *)(uintptr_t)(args[1]))->buffer_addr,
			((struct mem_chunk_list *)(uintptr_t)(args[1]))->size);
		ACCESS_READ_RIGHT_CHECK(args[1],
			sizeof(struct mem_chunk_list));
		ret = (uint32_t)__sion_ioctl((int)args[0], (void *)(uintptr_t)args[1]);
		args[0] = ret;
		SYSCALL_END

		sion_permission(SW_SYSCALL_SECMEM_ION_MMAP, permissions)
		tmp = args[0];
		if (!tmp) {
			args[0] = 0;
			return 0;
		}
		ACCESS_CHECK_A64(tmp, sizeof(struct sglist));
		ACCESS_CHECK_A64(args[0], sion_sg_size(tmp));
		ACCESS_READ_RIGHT_CHECK(tmp, sion_sg_size(args[0]));
		ret = (uint32_t)sion_mmap((void *)(uintptr_t)args[0],
			(unsigned int)args[1], (unsigned int)args[2],
			(int)args[3], (int)args[4], USED_BY_USR);
		args[0] = ret;
		SYSCALL_END

		sion_permission(SW_SYSCALL_SECMEM_ION_MUNMAP, permissions)
		tmp = args[0];
		if (!tmp) {
			args[0] = -EINVAL;
			return 0;
		}
		ACCESS_CHECK_A64(tmp, sizeof(struct sglist));
		ACCESS_CHECK_A64(args[0], sion_sg_size(tmp));
		ACCESS_READ_RIGHT_CHECK(args[0], sion_sg_size(args[0]));
		ret = (uint32_t)sion_munmap((void *)(uintptr_t)args[0],
			(unsigned int)args[1], (unsigned int)args[2],
			(unsigned int)args[3], (int)args[4], USED_BY_USR);
		args[0] = ret;
		SYSCALL_END
	default:
		ret = sion_second_syscall(swi_id, params, permissions);
		if (ret != 0)
			return -EINVAL;
		break;
	}
	return 0;
}

DECLARE_TC_DRV(
	sion_driver,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	sion_client_init,
	NULL,
	sion_syscall,
	NULL,
	NULL
);
