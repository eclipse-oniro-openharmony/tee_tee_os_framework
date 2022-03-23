/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secure memory service.
 * Create: 2020-03-06
 * Notes:
 * History: 2020-03-06 create
 */

#include <list.h>
#include <pthread.h>
#include <product_uuid.h>
#include "product_uuid_public.h"
#include "securec.h"
#include "tee_common.h"
#include "tee_log.h"
#include "ta_framework.h"
#include "tee_service_public.h"
#include "tee_commom_public_service.h"
#include "tee_ext_api.h"
#include "tee_init.h"
#include "procmgr_ext.h"
#include "hm_mman_ext.h"
#include "sre_syscall.h"
#include "msg_ops.h"
#include "mem_ops_ext.h"
#include "sec_region_ops.h"
#include "tee_private_api.h"
#include "tee_internal_task_pub.h"
#include "tee_agent.h"
#include "global_ddr_map.h"
#include "genalloc.h"
#include "vltmm_service.h"
#include <secmem_drv.h>

struct domain_info {
	uint32_t fd;
	int refcnt;
};

struct domain_info g_domain_tables[SEC_TASK_MAX];
static struct vltmm_pool_t g_vltmm_pool;

#ifndef array_size
#define array_size(a)	(sizeof(a) / sizeof((a)[0]))
#endif
#define LOW_MASK_16BIT       0xffff

static inline void vltmm_domain_fdtable_init(void)
{
	unsigned i;

	for (i = 0; i < array_size(g_domain_tables); i++) {
		g_domain_tables[i].fd = MAX_BUFFER_ID;
		g_domain_tables[i].refcnt = 0;
	}
}

static inline void mutex_lock()
{
	if (pthread_mutex_lock(&g_vltmm_pool.pthread_lock))
		tloge("vltmm mutex lock fail\n");
}

static inline void mutex_unlock()
{
	if (pthread_mutex_unlock(&g_vltmm_pool.pthread_lock))
		tloge("vltmm mutex unlock fail\n");
}

static inline uint64_t get_time()
{
	TEE_Time t = {0};
	TEE_GetSystemTime(&t);
	return (t.seconds * 1000ull) + t.millis;
}

static inline uint64_t __print_u64(uint64_t addr)
{
#ifdef DEF_ENG
	return addr;
#else
	return 0ULL;
#endif
}

static void vltmm_fd_init(uint32_t size)
{
	int ret;
	ret = bitmap_create(&g_vltmm_pool.id_gen, ALIGN(size, SIZE_32), 0);
	if (ret != TEE_SUCCESS)
		return;

	bitmap_set_ll(&g_vltmm_pool.id_gen, 0, 1);
	g_vltmm_pool.id_max = ALIGN(size, SIZE_32);
}

static uint32_t vltmm_fd_alloc()
{
	int32_t index = bitmap_find_next_zero_area(&g_vltmm_pool.id_gen, 1);
	if (index == -1) {
		return 0;
	}
	bitmap_set_ll(&g_vltmm_pool.id_gen, index, 1);
	return (uint32_t)index;
}

static void vltmm_fd_free(uint32_t id)
{
	bitmap_clear_ll(&g_vltmm_pool.id_gen, id, 1);
}

static void vltmm_pool_init()
{
	(void)memset_s(&g_vltmm_pool, sizeof(g_vltmm_pool), 0, sizeof(g_vltmm_pool));
	init_list_head(&g_vltmm_pool.poollist);
	init_list_head(&g_vltmm_pool.usedlist);
	g_vltmm_pool.contig_size = VLTMM_CHUNK_SIZE;
	(void)pthread_mutex_init(&g_vltmm_pool.pthread_lock, NULL);
}

static int vltmm_pool_ddr_sec_cfg(uint64_t *addr, uint32_t num, int cfg_type)
{
	uint32_t i, npages, size;
	struct sglist *sg = NULL;
	int ret;

	if (num == 0)
		return -1;

	size = sizeof(struct sglist) + sizeof(TEE_PAGEINFO) * num;
	sg = (struct sglist *)TEE_Malloc(size, 0);
	if (!sg)
		return -1;
	sg->infoLength = num;
	sg->sglistSize = size;
	npages = SIZE_2M >> PAGE_SHIFT;
	for (i = 0; i < num; i++) {
		if (addr[i] < HISI_RESERVED_SMEM_CMA_BASE ||
			addr[i] + SIZE_2M > HISI_RESERVED_SMEM_CMA_BASE +
			HISI_RESERVED_SMEM_CMA_SIZE) {
			tloge("vltmm pool check failed, addr:%llx\n", addr[i]);
			TEE_Free(sg);
			return -1;
		}
		sg->info[i].phys_addr = addr[i];
		sg->info[i].npages = npages;
	}

	if (cfg_type == DDR_UNSET_SEC) {
		ret = ddr_sec_cfg(sg, DDR_SEC_FACE, DDR_CHECK_SEC);
		if (ret) {
			tloge("ddr check sec failed\n");
			TEE_Free(sg);
			return -1;
		}
	}

	ret = ddr_sec_cfg(sg, DDR_SEC_FACE, cfg_type);
	if (ret)
		tloge("vltmm ddr sec cfg ret %d type: %d\n", ret, cfg_type);

	TEE_Free(sg);
	return ret;
}

static void vltmm_pool_add_sg(struct vltmm_agent_msg_t *msg)
{
	struct vltmm_pool_node *node = NULL;
	uint32_t i, num, len;
	uint64_t *addr = NULL;

	if (msg->num == 0)
		return;

	num = msg->num;
	addr = msg->data;
	len = sizeof(struct vltmm_pool_node);

	if (vltmm_pool_ddr_sec_cfg(addr, num, DDR_SET_SEC) != 0)
		return;

	for (i = 0; i < num; i++) {
		node = TEE_Malloc(len, 0);
		if (!node)
			return;
		memset_s(node, len, 0, len);
		node->pa   = addr[i];
		node->size = SIZE_2M;
		list_add_tail(&node->list, &g_vltmm_pool.poollist);
		g_vltmm_pool.pool_avail += SIZE_2M;
	}
	tloge("vlt pool add, num: %u, avail: 0x%x, used: 0x%x\n",
		num, g_vltmm_pool.pool_avail, g_vltmm_pool.used_size);
}

static struct vltmm_used_node *vltmm_find_used(uint32_t fd)
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct vltmm_used_node *used = NULL;

	list_for_each_safe(pos, next, &g_vltmm_pool.usedlist) {
		used = list_entry(pos, struct vltmm_used_node, list);
		if (used->fd == fd) {
			return used;
		}
	}
	return NULL;
}

static void vltmm_free_used_node(struct vltmm_used_node *used)
{
	uint32_t len, i;
	struct vltmm_pool_node *node = NULL;

	len = sizeof(struct vltmm_pool_node);
	for (i = 0; i < used->nents; i++) {
		node = TEE_Malloc(len, 0);
		if (!node)
			return;
		memset_s(node, len, 0, len);
		node->pa   = used->array[i].paddr;
		node->size = used->array[i].npages << PAGE_SHIFT;

		list_add_tail(&node->list, &g_vltmm_pool.poollist);
		g_vltmm_pool.pool_avail += node->size;
		g_vltmm_pool.used_size  -= node->size;
	}
	list_del(&used->list);

	if (used->fd)
		vltmm_fd_free(used->fd);
	TEE_Free(used->array);
	TEE_Free(used);
}

static int vltmm_map_fd(uint32_t tid, uint32_t fd, uint32_t cached, uint64_t *vaddr)
{
	int ret;
	struct vltmm_used_node *node;
	struct page_info_buffer page_info_buf;
	unsigned int prot   = PROT_READ | PROT_WRITE;
	void *va = NULL;

	node = vltmm_find_used(fd);
	if (!node)
		return -1;

	page_info_buf.page_info = (struct page_info *)node->array;
	page_info_buf.page_info_num = node->nents;
	if (!cached)
		prot |= PROT_MA_NC;
	ret = hm_mmap_scatter_physical(tid, &va, node->size, prot,
				&page_info_buf);
	if (!ret) {
		*vaddr = (uint64_t)(uintptr_t)va;
		for (int i = 0; i < MAP_MAX; i++) {
			if (node->vainfo[i].va == 0) {
				node->vainfo[i].va  = *vaddr;
				node->vainfo[i].tid = tid;
				break;
			}
		}
	}

	return ret;
}

static int vltmm_map_node(uint32_t tid, struct vltmm_used_node *node,
				uint32_t cached, uint64_t *vaddr)
{
	int ret;
	struct page_info_buffer page_info_buf;
	unsigned int prot   = PROT_READ | PROT_WRITE;
	void *va = NULL;

	page_info_buf.page_info = (struct page_info *)node->array;
	page_info_buf.page_info_num = node->nents;
	if (!cached)
		prot |= PROT_MA_NC;
	ret = hm_mmap_scatter_physical(tid, &va, node->size, prot,
				&page_info_buf);
	if (!ret) {
		*vaddr = (uint64_t)(uintptr_t)va;
		for (int i = 0; i < MAP_MAX; i++) {
			if (node->vainfo[i].va == 0) {
				node->vainfo[i].va  = *vaddr;
				node->vainfo[i].tid = tid;
				break;
			}
		}
	}

	return ret;
}

static int vltmm_unmap_fd(uint32_t tid, uint32_t fd, uint64_t vaddr)
{
	int ret = 0;
	uint32_t i;
	struct vltmm_used_node *node;

	node = vltmm_find_used(fd);
	if (!node)
		return -1;

	for (i = 0; i < MAP_MAX; i++) {
		if ((node->vainfo[i].tid & LOW_MASK_16BIT) == (tid & LOW_MASK_16BIT) &&
			vaddr == node->vainfo[i].va) {
			ret = task_unmap(tid, node->vainfo[i].va, node->size);
			node->vainfo[i].va = 0;
			node->vainfo[i].tid = 0;
		}
	}

	return ret;
}

static struct vltmm_used_node *vltmm_create_used_node(uint32_t count)
{
	struct vltmm_used_node *used = NULL;

	used = TEE_Malloc(sizeof(struct vltmm_used_node), 0);
	if (!used)
		return NULL;
	(void)memset_s(used, sizeof(struct vltmm_used_node),
				0, sizeof(struct vltmm_used_node));
	used->array = TEE_Malloc(sizeof(struct page_info) * count, 0);
	if (!used->array) {
		TEE_Free(used);
		return NULL;
	}
	(void)memset_s(used, sizeof(struct page_info), 0, sizeof(struct page_info));

	return used;
}

static void __record_pid_and_ref_inc(struct vltmm_used_node *used, uint32_t tid)
{
	for (int i = 0; i < MAP_MAX; i++) {
		if (used->owner_pid[i] == 0) {
			used->owner_pid[i] = (tid & LOW_MASK_16BIT);
			used->refcount++;
			return;
		}
	}
	tloge("used node association reach max\n");
}

static void __remove_pid_and_ref_dec(struct vltmm_used_node *used, uint32_t tid)
{
	for (int i = 0; i < MAP_MAX; i++) {
		if (used->owner_pid[i] == (tid & LOW_MASK_16BIT)) {
			used->owner_pid[i] = 0;
			if (used->refcount)
				used->refcount--;
			return;
		}
	}
}

static int vltmm_pool_alloc(uint32_t tid, uint32_t size, uint32_t mapflag,
				uint32_t *pfd, uint64_t *uva)
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct vltmm_pool_node *node = NULL;
	struct vltmm_used_node *used = NULL;
	uint32_t fd;
	uint32_t count = ALIGN(size, SIZE_2M) / SIZE_2M;

	if (list_empty(&g_vltmm_pool.poollist))
		return -1;

	used = vltmm_create_used_node(count);
	if (!used)
		return -1;

	list_for_each_safe(pos, next, &g_vltmm_pool.poollist) {
		node = list_entry(pos, struct vltmm_pool_node, list);
		used->array[used->nents].paddr  = node->pa;
		used->array[used->nents].npages = node->size >> PAGE_SHIFT;
		used->size += node->size;
		used->nents++;
		list_del(&node->list);
		TEE_Free(node);
		if (used->nents >= count) {
			break;
		}
	}
	g_vltmm_pool.pool_avail -= used->size;
	g_vltmm_pool.used_size  += used->size;
	list_add_tail(&used->list, &g_vltmm_pool.usedlist);

	if (mapflag) {
		if (vltmm_map_node(tid, used, TRUE, uva) == 0) {
			used->vainfo[0].tid = tid;
			used->vainfo[0].va = *uva;
		} else {
			tloge("map failed\n");
			goto failed;
		}
	}

	fd = vltmm_fd_alloc();
	if (fd == 0)
		goto failed;
	__record_pid_and_ref_inc(used, tid);
	used->fd = fd;
	*pfd = fd;
	return 0;

failed:
	vltmm_free_used_node(used);
	return -1;
}

static void vltmm_pool_free(uint32_t tid, uint64_t addr, uint32_t size, uint32_t fd)
{
	struct vltmm_used_node *used = NULL;
	uint32_t i;
	(void)size;

	used = vltmm_find_used(fd);
	if (used == NULL)
		return;

	for (i = 0; i < MAP_MAX; i++) {
		if ((used->vainfo[i].tid & LOW_MASK_16BIT) == (tid & LOW_MASK_16BIT) &&
			used->vainfo[i].va != 0 &&
			(addr == used->vainfo[i].va || addr == 0)) {
			task_unmap(tid, used->vainfo[i].va, used->size);
			used->vainfo[i].va = 0;
			used->vainfo[i].tid = 0;
		}
	}

	__remove_pid_and_ref_dec(used, tid);
	if (used->refcount)
		return;

	vltmm_free_used_node(used);
}

static void vltmm_pool_recycle(uint32_t pid)
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct vltmm_used_node *used = NULL;
	uint32_t i;

	tlogi("into vltmm pool recycle\n");
	list_for_each_safe(pos, next, &g_vltmm_pool.usedlist) {
		used = list_entry(pos, struct vltmm_used_node, list);

		for (i = 0; i < MAP_MAX; i++) {
			if ((used->vainfo[i].tid & LOW_MASK_16BIT) == pid &&
				used->vainfo[i].va)
				(void)task_unmap(used->vainfo[i].tid,
					used->vainfo[i].va,
					used->size);
		}

		__remove_pid_and_ref_dec(used, pid);
		if (!used->refcount)
			vltmm_free_used_node(used);
	}
}


static uint32_t vltmm_pool_avail()
{
	return g_vltmm_pool.pool_avail;
}

static uint32_t vltmm__reversebits(uint32_t num)
{
	uint32_t value = 0;
	uint32_t i;

	for (i = 0; i < SIZE_32; i++) {
		value <<= 1;
		value |= num & 0x00000001;
		num >>= 1;
	}

	return value;
}

static void vltmm_pool_dump_usedlist()
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct vltmm_used_node *used = NULL;
	uint32_t i;

	tloge("------------------------------------------------------------\n");
	tloge("used list: used: 0x%x\n", g_vltmm_pool.used_size);
	list_for_each_safe(pos, next, &g_vltmm_pool.usedlist) {
		used = list_entry(pos, struct vltmm_used_node, list);

		tloge("fd: %u refcount: %u size: 0x%x\n",
				used->fd, used->refcount, used->size);
		for (i = 0; i < MAP_MAX; i++) {
			if (used->vainfo[i].va)
				tloge("vainfo: tid: %x va: 0x%llx\n",
					used->vainfo[i].tid, __print_u64(used->vainfo[i].va));
		}

		tloge("phyinfo: \n");
		for (i = 0; i < used->nents; i++)
			tloge("paddr:%llx npages:%x\n",
					used->array[i].paddr, used->array[i].npages);
	}
	tloge("------------------------------------------------------------\n");
}

static void vltmm_pool_dump_fd()
{
	uint32_t *map = NULL;
	uint32_t bits;
	char     out[POOL_DUMP_LEN];
	uint32_t i;
	int ret;
	int len = 0;

	map = g_vltmm_pool.id_gen.map;
	bits = g_vltmm_pool.id_gen.bits;
	tloge("sec fd dump: max_fd: %u\n", g_vltmm_pool.id_max);
	(void)memset_s(out, POOL_DUMP_LEN, 0, POOL_DUMP_LEN);
	for (i = 0; i < ALIGN(bits, SIZE_32) / SIZE_32; i++) {
		ret = snprintf_s(out + len, POOL_DUMP_LEN - len, POOL_DUMP_LEN - 1 - len, "%08x ",
							map[i] == 0 ? 0 : vltmm__reversebits(map[i]));
		if (ret < 0)
			break;
		len += ret;
		if (((i + 1) % SIZE_8) == 0) {
			tloge("%s\n", out);
			len = 0;
			(void)memset_s(out, POOL_DUMP_LEN, 0, POOL_DUMP_LEN);
		}
	}
	if (len > 0)
		tloge("%s\n", out);
}

static void vltmm_pool_dump()
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct vltmm_pool_node *node = NULL;

	tloge("====service info begin=====================================\n");
	tloge("pool list: avail: 0x%x\n", g_vltmm_pool.pool_avail);
	list_for_each_safe(pos, next, &g_vltmm_pool.poollist) {
		node = list_entry(pos, struct vltmm_pool_node, list);
		tloge("%llx  %x\n", node->pa, node->size);
	}

	vltmm_pool_dump_usedlist();

	vltmm_pool_dump_fd();

	tloge("====service info end========================================\n");
}

static inline int vltmm_agent_msg_check(struct vltmm_agent_msg_t *agentmsg)
{
	if (agentmsg->magic != (uint32_t)TEE_VLTMM_AGENT_ID)
		return -1;
	if (agentmsg->ret != 0 ||
		agentmsg->num == 0 ||
		agentmsg->num > VLTMM_GRAN_MAX)
		return -1;

	return 0;
}

static int vltmm_fill_pool(uint32_t minsize)
{
	uint32_t nsize;
	uint32_t length;
	struct vltmm_agent_msg_t *agentmsg = NULL;
	void *buffer = NULL;
	int ret;
	u64 start, end;

	if (minsize > g_vltmm_pool.pool_avail)
		nsize = ALIGN(minsize - g_vltmm_pool.pool_avail, SIZE_2M);
	else
		return 0;

	ret = tee_agent_lock(TEE_VLTMM_AGENT_ID);
	if (ret != TEE_SUCCESS) {
		tloge("vlt agent lock failed, ret=0x%x\n", ret);
		return -1;
	}
	ret = tee_get_agent_buffer(TEE_VLTMM_AGENT_ID, &buffer, &length);
	if (ret != TEE_SUCCESS ||
		(buffer == NULL) ||
		(length < sizeof(struct vltmm_agent_msg_t))) {
		tloge("get vlt agent buffer fail, ret=0x%x, length=%u\n", ret, length);
		(void)tee_agent_unlock(TEE_VLTMM_AGENT_ID);
		return -1;
	}

	agentmsg        = (struct vltmm_agent_msg_t *)(uintptr_t)buffer;
	agentmsg->magic = (uint32_t)TEE_VLTMM_AGENT_ID;
	agentmsg->cmd   = CMD_STOA_ALLOC;
	agentmsg->ret   = -1;
	agentmsg->cid   = SMEM_SECOS_2M;
	agentmsg->num   = nsize / SIZE_2M;
	start = get_time();
	ret = tee_send_agent_cmd(TEE_VLTMM_AGENT_ID);
	end = get_time();
	if (end > start && end - start > VLTMM_MALLOC_INTERVAL)
		tloge("vltmm alloc cost %llu size: %lx\n", end - start, nsize);
	if (ret != TEE_SUCCESS || vltmm_agent_msg_check(agentmsg) != 0) {
		tloge("send agent cmd failed, cmd: %u ret: %d\n",
			agentmsg->cmd,
			agentmsg->ret);
		ret = agentmsg->ret;
		vltmm_pool_dump();
		(void)tee_agent_unlock(TEE_VLTMM_AGENT_ID);
		return ret;
	}

	vltmm_pool_add_sg(agentmsg);

	(void)tee_agent_unlock(TEE_VLTMM_AGENT_ID);

	return 0;
}

static void vltmm_clean_sec_mem(uint64_t *addr, uint32_t num)
{
	int ret;
	struct page_info_buffer page_info_buf;
	unsigned int prot   = PROT_READ | PROT_WRITE | PROT_MA_NC;
	void *va = NULL;
	uint32_t size;
	uint32_t tid = 0;
	struct page_info *pg = NULL;

	if (num == 0)
		return;

	pg = TEE_Malloc(num * sizeof(struct page_info), 0);
	if (!pg)
		return;
	size = 0;
	for (uint32_t i = 0; i < num; i++) {
		pg[i].paddr = addr[i];
		pg[i].npages = SIZE_2M >> PAGE_SHIFT;
		size += SIZE_2M;
	}
	__SRE_TaskSelf(&tid);
	page_info_buf.page_info = pg;
	page_info_buf.page_info_num = num;
	ret = hm_mmap_scatter_physical(-1, &va, size, prot,
				&page_info_buf);
	if (!ret) {
		(void)memset_s(va, size, 0, size);
		(void)hm_munmap(va, size);
	}
	TEE_Free(pg);
}

static inline uint32_t get_protect_id(uint32_t sid)
{
	if (sid == SEC_ISP || sid == SEC_IVP)
		return SEC_TASK_SEC;
	else
		return SEC_TASK_MAX;
}

static inline bool domain_is_ready(uint32_t protect_id)
{
	return g_domain_tables[protect_id].fd != MAX_BUFFER_ID;
}

static void vltmm_free_pgtable_memory(uint32_t fd)
{
	struct vltmm_used_node *node = NULL;

	node = vltmm_find_used(fd);
	if (node == NULL)
		return;

	(void)vltmm_free_used_node(node);
}

static inline void vltmm_pgtable_memsize_check(uint32_t *size)
{
	if (*size != SIZE_2M) {
		tloge("%s, unsupported size %u\n", __func__, *size);
		*size = SIZE_2M;
	}
}

static int __vltmm_create_domain(uint32_t sender, uint32_t protect_id, uint32_t size)
{
	struct vltmm_used_node *node = NULL;
	uint32_t fd = 0;
	int ret;

	if (vltmm_pool_avail() < size) {
		ret = vltmm_fill_pool(size);
		if (ret != 0)
			return -1;
	}

	ret = vltmm_pool_alloc(sender, size, false, &fd, NULL);
	if (ret)
		return -1;

	node = vltmm_find_used(fd);
	if (node == NULL || node->array == NULL) {
		tloge("Something error with vlt service\n");
		return -1;
	}

	tlogi("create smmu domain paddr: %llx, size: %u\n",
					node->array->paddr, node->size);
	ret = sion_create_smmu_domain(protect_id, node->array->paddr, node->size);
	if (ret) {
		(void)vltmm_free_pgtable_memory(fd);
		return -1;
	}

	g_domain_tables[protect_id].fd = fd;
	g_domain_tables[protect_id].refcnt++;

	return 0;
}

static void vltmm_create_domain(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	int ret;
	uint32_t size;
	uint32_t protect_id;
	struct domain_msg_t *pmsg = (struct domain_msg_t *)(uintptr_t)msg;

	if (pmsg == NULL || rsp == NULL)
		return;

	protect_id = get_protect_id(pmsg->sid);
	if (protect_id == SEC_TASK_MAX) {
		rsp->ret = TEE_ERROR_BAD_PARAMETERS;
		return;
	}

	rsp->ret = TEE_SUCCESS;
	size = pmsg->size;
	vltmm_pgtable_memsize_check(&size);

	mutex_lock();
	if (!domain_is_ready(protect_id)) {
		ret = __vltmm_create_domain(sender, protect_id, size);
		if (ret < 0) {
			tlogi("create smmu domain failed sid: %u, size: %u\n",
							pmsg->sid, size);
			rsp->ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	} else {
		if (!g_domain_tables[protect_id].refcnt) {
			tloge("refcnt mismatch protect id:%u\n", protect_id);
		}

		tlogi("get smmu domain refcnt sid: %u, ref: %d\n", pmsg->sid, g_domain_tables[protect_id].refcnt);
		g_domain_tables[protect_id].refcnt++;
	}
out:
	mutex_unlock();
}

static void vltmm_destroy_domain(const tee_service_ipc_msg *msg,
				 uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	int ret;
	uint32_t protect_id;
	struct domain_msg_t *pmsg = (struct domain_msg_t *)(uintptr_t)msg;

	if (pmsg == NULL || rsp == NULL)
		return;

	rsp->ret = TEE_SUCCESS;
	protect_id = get_protect_id(pmsg->sid);
	if (protect_id == SEC_TASK_MAX) {
		rsp->ret = TEE_ERROR_BAD_PARAMETERS;
		return;
	}

	mutex_lock();
	if (!domain_is_ready(protect_id)) {
		tloge("destroy smmu domain sid:%u, domain is not ready\n", pmsg->sid);
		rsp->ret = TEE_ERROR_OUT_OF_MEMORY;
		mutex_unlock();
		return;
	}

	tlogi("put smmu domain refcnt sid: %u, ref: %d\n", pmsg->sid, g_domain_tables[protect_id].refcnt);
	g_domain_tables[protect_id].refcnt--;
	if (!g_domain_tables[protect_id].refcnt) {
		ret = sion_destroy_smmu_domain(protect_id);
		if (!ret) {
			tlogi("destroy smmu domain sid:%u\n", pmsg->sid);
			(void)vltmm_free_pgtable_memory(g_domain_tables[protect_id].fd);
			g_domain_tables[protect_id].fd = MAX_BUFFER_ID;
		} else {
			tloge("destroy smmu domain sid:%u failed\n", pmsg->sid);
			g_domain_tables[protect_id].refcnt++;
			rsp->ret = TEE_ERROR_OUT_OF_MEMORY;
		}
	}
	mutex_unlock();
}

static void vltmm_alloc_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	TEE_Result ret;
	struct alloc_msg_t *pmsg;
	uint32_t size;
	uint64_t uva = 0;
	struct alloc_msg_t rspdata;
	uint32_t fd = 0;

	pmsg = (struct alloc_msg_t *)(uintptr_t)msg;

	size = PAGE_ALIGN_UP(pmsg->size);

	mutex_lock();
	rsp->ret = TEE_ERROR_OUT_OF_MEMORY;
	if (vltmm_pool_avail() < size) {
		ret = vltmm_fill_pool(size);
		if (ret != 0) {
			mutex_unlock();
			return;
		}
	}

	ret = vltmm_pool_alloc(sender, size, TRUE, &fd, &uva);
	mutex_unlock();
	if (ret == 0) {
		tlogi("vltmm pool alloc succ: pid: %u uva: %llx size: %u fd: %u \n",
			sender, __print_u64(uva), size, fd);
		(void)memset_s(&rspdata, sizeof(rspdata), 0, sizeof(rspdata));
		rspdata.fd =  fd;
		rspdata.addr = uva;
		rspdata.size = size;
		ret = memcpy_s(&rsp->msg.args_data,
			sizeof(rsp->msg.args_data),
			&rspdata.head.buf_start,
			sizeof(struct alloc_msg_t) - sizeof(struct vltmm_msg_t));
		if (ret)
			rsp->ret = -1;
		else
			rsp->ret = TEE_SUCCESS;
		return;
	}
}

static void vltmm_free_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	struct free_msg_t *pmsg;

	pmsg = (struct free_msg_t *)(uintptr_t)msg;

	mutex_lock();
	vltmm_pool_free(sender, pmsg->addr, pmsg->size, pmsg->fd);
	mutex_unlock();
	rsp->ret = TEE_SUCCESS;
}

static void vltmm_openfd_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	struct sharemem_msg_t *shmmsg = NULL;
	uint32_t fd;
	uint32_t size;
	uint64_t uva;
	int ret;

	shmmsg = (struct sharemem_msg_t *)(uintptr_t)msg;

	size = PAGE_ALIGN_UP(shmmsg->size);
	mutex_lock();
	if (vltmm_pool_avail() < size) {
		ret = vltmm_fill_pool(size);
		if (ret != 0) {
			rsp->ret = TEE_ERROR_OUT_OF_MEMORY;
			mutex_unlock();
			return;
		}
	}

	ret = vltmm_pool_alloc(sender, size, FALSE, &fd, &uva);
	mutex_unlock();
	tlogi("vltmm open, ret: %d size: %d magic: %x fd:%u\n",
		ret, shmmsg->size, shmmsg->head.magic, fd);
	if (ret == 0) {
		shmmsg->fd = (uint32_t)fd;
		ret = memcpy_s(&rsp->msg.args_data,
			sizeof(rsp->msg.args_data),
			shmmsg->head.buf_start,
			sizeof(struct sharemem_msg_t) - sizeof(struct vltmm_msg_t));
		if (ret)
			rsp->ret = -1;
		else
			rsp->ret = TEE_SUCCESS;
	}

	return;
}

static void vltmm_closefd_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	struct sharemem_msg_t *shmmsg;

	shmmsg = (struct sharemem_msg_t *)(uintptr_t)msg;
	tlogi("vltmm close fd: magic: %x tid:%x fd:%u\n", shmmsg->head.magic, sender, shmmsg->fd);
	mutex_lock();
	vltmm_pool_free(sender, 0, 0, shmmsg->fd);
	mutex_unlock();
	rsp->ret = TEE_SUCCESS;
}

static void vltmm_importfd_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	struct sharemem_msg_t *shmmsg = NULL;
	struct vltmm_used_node *used = NULL;

	shmmsg = (struct sharemem_msg_t *)(uintptr_t)msg;
	mutex_lock();
	used = vltmm_find_used(shmmsg->fd);
	if (used) {
		__record_pid_and_ref_inc(used, sender);
		rsp->ret = TEE_SUCCESS;
		tlogi("vltmm import fd succ, tid:%x fd:%u\n",
			sender, shmmsg->fd);
	} else {
		rsp->ret = -1;
		tloge("vltmm import fd, ret: %d tid:%x fd:%u\n",
			rsp->ret, sender, shmmsg->fd);
	}
	mutex_unlock();
}

static void vltmm_mapfd_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	int ret;
	struct sharemem_msg_t *shmmsg = NULL;
	uint64_t vaddr = 0;

	shmmsg = (struct sharemem_msg_t *)(uintptr_t)msg;
	mutex_lock();
	ret = vltmm_map_fd(sender, shmmsg->fd, shmmsg->cached, &vaddr);
	mutex_unlock();
	if (!ret && vaddr) {
		shmmsg->va = vaddr;
		shmmsg->head.ret = TEE_SUCCESS;
		ret = memcpy_s(&rsp->msg.args_data,
			sizeof(rsp->msg.args_data),
			shmmsg->head.buf_start,
			sizeof(struct sharemem_msg_t) - sizeof(struct vltmm_msg_t));
		if (ret)
			rsp->ret = -1;
		else
			rsp->ret = TEE_SUCCESS;
		tlogi("vltmm map fd, ret: %d, tid:%x fd:%u va:%llx\n",
					ret, sender, shmmsg->fd, __print_u64(vaddr));
	} else {
		rsp->ret = -1;
		tloge("vltmm map fd failed, tid:%x fd:%u va:%llx ret: %d\n",
					sender, shmmsg->fd, __print_u64(vaddr), ret);
	}
}

static void vltmm_unmapfd_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	int ret;
	struct sharemem_msg_t *shmmsg = NULL;

	shmmsg = (struct sharemem_msg_t *)(uintptr_t)msg;

	mutex_lock();
	ret = vltmm_unmap_fd(sender, shmmsg->fd, shmmsg->va);
	mutex_unlock();
	if (!ret) {
		shmmsg->head.ret = TEE_SUCCESS;
		rsp->ret = TEE_SUCCESS;
		tlogi("vltmm unmap fd tid: %x fd: %u va: %llx\n",
				sender, shmmsg->fd, __print_u64(shmmsg->va));
	} else {
		rsp->ret = -1;
		tloge("vltmm unmap fd tid: %x fd: %u va: %llx\n",
				sender, shmmsg->fd, __print_u64(shmmsg->va));
	}
}

static void vltmm_dump_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	(void)msg;
	(void)sender;

	vltmm_pool_dump();

	rsp->ret = TEE_SUCCESS;
}

static void vltmm_shrinker_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct vltmm_pool_node *node = NULL;
	struct shrinker_msg_t *sh_msg = NULL;
	(void)msg;
	(void)sender;

	sh_msg = (struct shrinker_msg_t *)(uintptr_t)&rsp->msg.args_data;
	sh_msg->magic = TEE_VLTMM_AGENT_ID;
	sh_msg->num = 0;
	mutex_lock();
	list_for_each_safe(pos, next, &g_vltmm_pool.poollist) {
		node = list_entry(pos, struct vltmm_pool_node, list);
		sh_msg->addr[sh_msg->num++] = node->pa;
		list_del(&node->list);
		if (g_vltmm_pool.pool_avail >= node->size)
			g_vltmm_pool.pool_avail -= node->size;
		TEE_Free(node);
		if (sh_msg->num >= SHRINKER_CNT_MAX)
			break;
	}
	vltmm_clean_sec_mem(sh_msg->addr, sh_msg->num);
	vltmm_pool_ddr_sec_cfg(sh_msg->addr, sh_msg->num, DDR_UNSET_SEC);
	tloge("shrinker memory, num: %u\n", sh_msg->num);
	mutex_unlock();

	rsp->ret = TEE_SUCCESS;
}


static struct ta_task_t ta_array[] = {
	{0, TEE_SERVICE_AI_TINY},
	{0, TEE_SERVICE_AI},
	{0, TEE_SERVICE_FACE_REC},
	{0, TEE_SERVICE_SECMEM},
};
#define UUID_NUM array_size(ta_array)

static struct ta_task_t *find_ta_task(TEE_UUID *cur_uuid)
{
	u32 i;

	for (i = 0; i < UUID_NUM; i++) {
		if (!memcmp(&ta_array[i].uuid, cur_uuid, sizeof(TEE_UUID)))
			return (struct ta_task_t *)(uintptr_t)&ta_array[i];
	}

	return NULL;
}

static void vltmm_tacreate_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	(void)msg;
	(void)sender;
	(void)rsp;
	struct ta_task_t *task = NULL;

	tloge("recv ta create msg, pid: %x uuid: %08x-%04x-%04x",
			msg->reg_ta.taskid,
			msg->reg_ta.uuid.timeLow,
			msg->reg_ta.uuid.timeMid,
			msg->reg_ta.uuid.timeHiAndVersion);
	task = find_ta_task((TEE_UUID *)&msg->reg_ta.uuid);
	if (task)
		task->pid = msg->reg_ta.taskid;
}

static void vltmm_tadestroy_process(const tee_service_ipc_msg *msg,
				uint32_t sender, tee_service_ipc_msg_rsp *rsp)
{
	(void)msg;
	(void)sender;
	(void)rsp;
	struct ta_task_t *task = NULL;

	tlogi("recv ta destroy msg, uuid: %08x-%04x-%04x",
			msg->reg_ta.uuid.timeLow,
			msg->reg_ta.uuid.timeMid,
			msg->reg_ta.uuid.timeHiAndVersion);

	task = find_ta_task((TEE_UUID *)&msg->reg_ta.uuid);
	if (task && task->pid)
		vltmm_pool_recycle(task->pid);
}

static tee_service_cmd g_cmd_tbl[] = {
	{ CMD_CTOS_CREATE,           NULL },
	{ CMD_CTOS_DESTROY,          NULL },
	{ CMD_CTOS_ALLOC,            vltmm_alloc_process },
	{ CMD_CTOS_FREE,             vltmm_free_process },
	{ CMD_CTOS_OPENFD,           vltmm_openfd_process },
	{ CMD_CTOS_CLOSEFD,          vltmm_closefd_process },
	{ CMD_CTOS_IMPORTFD,         vltmm_importfd_process },
	{ CMD_CTOS_MAPFD,            vltmm_mapfd_process },
	{ CMD_CTOS_UNMAPFD,          vltmm_unmapfd_process },
	{ CMD_CTOS_POOLDUMP,         vltmm_dump_process },
	{ CMD_CTOS_SHRINKER,         vltmm_shrinker_process },
	{ CMD_CTOS_CREATE_DOMAIN,    vltmm_create_domain },
	{ CMD_CTOS_DESTROY_DOMAIN,   vltmm_destroy_domain },

	{ TEE_TASK_TA_CREATE,        vltmm_tacreate_process },
	{ TEE_TASK_TA_RELEASE,       vltmm_tadestroy_process },
};

static uint32_t g_cmd_num = array_size(g_cmd_tbl);

uint32_t tee_service_init(void)
{
	vltmm_pool_init();
	vltmm_fd_init(MAX_BUFFER_ID);

	return TEE_SUCCESS;
}

void tee_service_handle(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp,
				uint32_t cmd)
{
#ifdef TEE_SUPPORT_VLTMM_SRV
	uint32_t i;

	if (rsp == NULL)
		return;
	if (msg == NULL) {
		rsp->ret = TEE_ERROR_BAD_PARAMETERS;
		return;
	}

	for (i = 0; i < g_cmd_num; i++) {
		if (cmd != g_cmd_tbl[i].cmd)
			continue;
		if (g_cmd_tbl[i].fn != NULL)
			g_cmd_tbl[i].fn(msg, task_id, rsp);
	}

#else
	(void)msg;
	(void)task_id;
	(void)rsp;
	(void)cmd;
	(void)g_cmd_num;
#endif
	return;
}

#ifdef CONFIG_DYNLINK
__attribute__((section(".magic")))
const char magic_string[] = "Dynamically linked.";
#endif

/*
TA's main func
*/
__attribute__((visibility ("default"))) void tee_task_entry(int init_build)
{
	tloge("start of vltmm service task ----------------------\n");

	vltmm_domain_fdtable_init();
	tee_common_task_entry(init_build, VLTMMSRV_TASK_NAME);
}
