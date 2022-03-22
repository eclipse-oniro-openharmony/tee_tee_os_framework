/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secure memory api.
 * Create: 2020-03-16
 * Notes:
 * History: 2020-03-16 create
 */

#include <list.h>
#include <pthread.h>
#include <securec.h>
#include <tee_defines.h>
#include <tee_log.h>
#include <ta_framework.h>
#include <tee_ext_api.h>
#include <procmgr_ext.h>
#include "tee_service_public.h"
#include "sre_syscall.h"
#include "genalloc.h"
#include "vltmm_private.h"
#include "vltmm_client_api.h"

static struct client_pool g_vlt_client_pool;
#define VLT_ALIGN    (g_vlt_client_pool.align)
static int g_vlt_errno = 0;
pthread_mutex_t g_vlt_pthread_lock = PTHREAD_MUTEX_INITIALIZER;

static TEE_Result send_client_msg(struct vltmm_msg_t *clientmsg, uint32_t len);

static inline void vlt_set_errno(int no)
{
	g_vlt_errno = no;
}

static inline uint64_t __print_u64(uint64_t addr)
{
#ifdef DEF_ENG
	return addr;
#else
	return 0ULL;
#endif
}

static inline void *__print_ptr(void *addr)
{
#ifdef DEF_ENG
	return addr;
#else
	return (void *)NULL;
#endif
}

#ifdef TEE_SUPPORT_VLTMM_SRV
static uint32_t __align_to_order(uint32_t align)
{
	for (unsigned int i = 0; i < SIZE_32; i++) {
		if (((align - 1) >> i) == 0)
			return i;
	}
	return SIZE_32;
}
#endif

static inline void __mutex_lock()
{
	if (pthread_mutex_lock(&g_vlt_pthread_lock))
		tloge("vlt mutex lock fail\n");
}

static inline void __mutex_unlock()
{
	if (pthread_mutex_unlock(&g_vlt_pthread_lock))
		tloge("vlt mutex unlock fail\n");
}

static void vltmm_pool_init(uint32_t sid, uint32_t maxsize, uint32_t align)
{
#ifdef TEE_SUPPORT_VLTMM_SRV
	uint32_t tid = 0;
	spawn_uuid_t uuid = {0};
	int ret;

	if (g_vlt_client_pool.init)
		return;

	ret = pthread_mutex_init(&g_vlt_pthread_lock, NULL);
	if (ret)
		return;
	init_list_head(&g_vlt_client_pool.poollist);
	g_vlt_client_pool.align = align;
	g_vlt_client_pool.order = __align_to_order(align);
	g_vlt_client_pool.chunk_size = VLTMM_CHUNK_SIZE;
	g_vlt_client_pool.init = TRUE;
	g_vlt_client_pool.sid  = sid;
	g_vlt_client_pool.maxsize = maxsize;

	__SRE_TaskSelf(&tid);
	ret = hm_getuuid(tid & 0xFFFF, &uuid);
	tloge("vltmm init, sid: %u, align: %x, order: %u, tid: 0x%x, size: 0x%x",
			sid, align, g_vlt_client_pool.order, tid, maxsize);

	if (ret == 0)
		tloge("uuid: %08x-%04x-%04x",
				uuid.uuid.timeLow,
				uuid.uuid.timeMid,
				uuid.uuid.timeHiAndVersion);
#endif
}

static bool vltmm_is_init()
{
	return g_vlt_client_pool.init ? TRUE : FALSE;
}

static int vltmm_pool_add(uint64_t base, uint32_t size, uint32_t fd)
{
	struct client_pool_node *node = NULL;
	node = TEE_Malloc(sizeof(struct client_pool_node), 0);
	if (!node)
		return VLT_ERR_NOMEM;

	node->pool = gen_pool_create(base, size, g_vlt_client_pool.order);
	if (!node->pool)
		return VLT_ERR_NOMEM;
	node->fd   = fd;
	tlogd("vltmm poo add, fd: %u, base: %llx, size: %x", node->fd, __print_u64(base), size);
	list_add_tail(&node->list, &g_vlt_client_pool.poollist);
	g_vlt_client_pool.poolnum++;
	return VLT_SUCCESS;
}

static void *vltmm_pool_alloc(uint32_t size)
{
	struct list_head *pos = NULL;
	struct client_pool_node *node = NULL;
	uint64_t addr;
	uint32_t asize = ALIGN(size, VLT_ALIGN);

	if (size == 0)
		return NULL;

	list_for_each(pos, &g_vlt_client_pool.poollist) {
		node = list_entry(pos, struct client_pool_node, list);
		if (asize > gen_pool_avail(node->pool))
			continue;
		addr = gen_pool_alloc(node->pool, asize);
		if (addr) {
			return (void *)(uintptr_t)addr;
		}
	}
	return NULL;
}

static void vltmm_pool_destroy_node(struct client_pool_node *node)
{
	struct free_msg_t msg;
	int ret;

	(void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
	msg.head.cmd = CMD_CTOS_FREE;
	msg.head.magic = TEE_VLTMM_AGENT_ID;
	msg.addr = node->pool->base;
	msg.size = node->pool->size;
	msg.fd   = node->fd;

	list_del(&node->list);
	gen_pool_destory(node->pool);
	TEE_Free(node);
	g_vlt_client_pool.poolnum--;

	ret = send_client_msg((struct vltmm_msg_t *)&msg, sizeof(msg));
	if (ret)
		tloge("vltmm free msg failed\n");
	return;
}

static void vltmm_pool_destroy()
{
	struct free_msg_t msg;
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct client_pool_node *node = NULL;
	int ret;

	(void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
	msg.head.cmd = CMD_CTOS_FREE;
	msg.head.magic = TEE_VLTMM_AGENT_ID;

	list_for_each_safe(pos, next, &g_vlt_client_pool.poollist) {
		node = list_entry(pos, struct client_pool_node, list);
		msg.addr = node->pool->base;
		msg.size = node->pool->size;
		msg.fd   = node->fd;
		list_del(&node->list);
		gen_pool_destory(node->pool);
		TEE_Free(node);
		ret = send_client_msg((struct vltmm_msg_t *)&msg, sizeof(msg));
		if (!ret)
			tloge("vltmm pool destroy send msg failed, ret: %d \n", ret);
	}

	g_vlt_client_pool.poolnum = 0;
	init_list_head(&g_vlt_client_pool.poollist);
	return;
}

static void vltmm_pool_free(uint64_t addr, uint32_t size)
{
	struct list_head *pos = NULL;
	struct list_head *next = NULL;
	struct client_pool_node *node = NULL;
	uint32_t asize = ALIGN(size, VLT_ALIGN);

	list_for_each_safe(pos, next, &g_vlt_client_pool.poollist) {
		node = list_entry(pos, struct client_pool_node, list);
		if (addr >= node->pool->base &&
			addr < node->pool->base + node->pool->size) {
			if (addr + asize > node->pool->base + node->pool->size) {
				tloge("pool free faild, invalid base(%llx) and size(%x).\n",
					__print_u64(addr),
					asize);
				continue;
			}
			gen_pool_free(node->pool, addr, asize);
			if (bitmap_empty(&node->pool->sbitmap))
				vltmm_pool_destroy_node(node);
			break;
		}
	}
}

static uint32_t vltmm_reversebits(uint32_t num)
{
	uint32_t value = 0;
	uint32_t i;

	for (i = 0; i < SIZE_32; i++) {
		value <<= 1;
		value |= num & (uint32_t)0x1;
		num >>= 1;
	}
	return value;
}

static void vlt_pool_dump_poollist()
{
	struct list_head *pos = NULL;
	struct client_pool_node *node = NULL;
	uint32_t index = 0;
	uint32_t *map = NULL;
	uint32_t bits;
	char     out[POOL_DUMP_LEN];
	char    *pout = out;

	list_for_each(pos, &g_vlt_client_pool.poollist) {
		node = list_entry(pos, struct client_pool_node, list);
		map = node->pool->sbitmap.map;
		bits = node->pool->sbitmap.bits;
		tloge("index %u base: 0x%llx size: 0x%x avail: 0x%x order: %u bits: %u\n",
			index++,
			__print_u64(node->pool->base),
			node->pool->size,
			node->pool->avail,
			node->pool->min_alloc_order,
			bits);
		(void)memset_s(out, POOL_DUMP_LEN, 0, POOL_DUMP_LEN);
		for (uint32_t i = 0; i < ALIGN(bits, SIZE_32) / SIZE_32; i++) {
			if (pout - out >= POOL_DUMP_LEN - 1)
				break;
			pout += snprintf_s(pout, POOL_DUMP_LEN - (pout - out),
							POOL_DUMP_LEN - (pout - out) - 1,
							"%08x ",
							map[i] == 0 ? 0 : vltmm_reversebits(map[i]));
			if (((i + 1) % SIZE_8) == 0) {
				tloge("%s\n", out);
				pout = out;
				(void)memset_s(out, POOL_DUMP_LEN, 0, POOL_DUMP_LEN);
			}
		}
		if (pout > out)
			tloge("%s\n", out);
	}
}

void vlt_pool_dump()
{
	struct alloc_msg_t msg;
	int ret;

	if (vltmm_is_init()) {
		tloge("vltmm client pool info:\n");
		tloge("sid: %u align: 0x%x chunk_size: 0x%x\n",
			g_vlt_client_pool.sid,
			g_vlt_client_pool.align,
			g_vlt_client_pool.chunk_size);
		tloge("order: %u pool_num: %u\n",
			g_vlt_client_pool.order,
			g_vlt_client_pool.poolnum);

		if (!list_empty(&g_vlt_client_pool.poollist))
			vlt_pool_dump_poollist();
	}

	(void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
	msg.head.cmd = CMD_CTOS_POOLDUMP;
	msg.head.magic = TEE_VLTMM_AGENT_ID;
	ret = send_client_msg((void *)&msg, sizeof(struct alloc_msg_t));
	if (ret)
		tloge("send dump msg failed\n");
}

static TEE_Result send_client_msg(struct vltmm_msg_t *clientmsg, uint32_t len)
{
	tee_service_ipc_msg msg;
	tee_service_ipc_msg_rsp rsp = {0};
	struct vltmm_msg_t *head = clientmsg;
	int ret;

	(void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
	if (len < sizeof(struct vltmm_msg_t) ||
		len > sizeof(msg.args_data)) {
		tloge("send client msg failed, len: %u", len);
		return -1;
	}
	ret = memcpy_s((void *)(uintptr_t)&msg.args_data, sizeof(msg.args_data), clientmsg, len);
	if (ret)
		return -1;

	rsp.ret = -1;
	tee_common_ipc_proc_cmd(VLTMMSRV_TASK_NAME, head->cmd, &msg, head->cmd, &rsp);
	if (rsp.ret != TEE_SUCCESS) {
		tloge("send client failed: %d\n", rsp.ret);
		return rsp.ret;
	}

	ret = memcpy_s((char *)clientmsg->buf_start, len - sizeof(struct vltmm_msg_t), &rsp.msg.args_data,
		len - sizeof(struct vltmm_msg_t));
	if (ret)
		return -1;

	return TEE_SUCCESS;
}

void vlt_create_zone(uint32_t sid, uint32_t maxsize, uint32_t align)
{
	vltmm_pool_init(sid, maxsize, align);
}

void vlt_destroy_zone(uint32_t sid)
{
	(void)sid;
	vltmm_pool_destroy();
	g_vlt_client_pool.init = FALSE;
	g_vlt_errno = 0;
}

int vlt_create_siommu_domain(uint32_t sid, uint32_t size)
{
	int ret;
	struct domain_msg_t msg;

	(void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));

	msg.head.cmd = CMD_CTOS_CREATE_DOMAIN;
	msg.head.magic = TEE_VLTMM_AGENT_ID;
	msg.sid = sid;
	msg.size = size;

	ret = send_client_msg((void *)&msg, sizeof(msg));
	if (ret)
		tloge("vlt create domain failed, sid: %u, size: %u, ret: %d",
			sid, size, ret);

	return ret;
}

int vlt_destroy_siommu_domain(uint32_t sid)
{
	int ret;
	struct domain_msg_t msg;

	(void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));

	msg.head.cmd = CMD_CTOS_DESTROY_DOMAIN;
	msg.head.magic = TEE_VLTMM_AGENT_ID;
	msg.sid = sid;

	ret = send_client_msg((void *)&msg, sizeof(msg));
	if (ret)
		tloge("vlt destroy siommu domain failed, sid: %u ret: %d",
			sid, ret);

	return ret;
}

void *vlt_malloc(uint32_t size)
{
	int ret;
	struct alloc_msg_t msg;
	void *uva = NULL;
	uint32_t nsize;

	if (!vltmm_is_init()) {
		vlt_set_errno(VLT_ERR_NOTINIT);
		return NULL;
	}

	if (size == 0) {
		vlt_set_errno(VLT_ERR_PARAM);
		return NULL;
	}

	__mutex_lock();
	uva = vltmm_pool_alloc(size);
	if (uva) {
		tlogi("vlt malloc, va:%x size:%x\n", __print_ptr(uva), size);
		__mutex_unlock();
		return uva;
	}
	__mutex_unlock();

	if (size <= VLTMM_CHUNK_SIZE) {
		nsize = VLTMM_CHUNK_SIZE;
	} else {
		nsize = ALIGN_UP(size, VLTMM_SCATTER_SIZE);
	}

	(void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
	msg.head.cmd = CMD_CTOS_ALLOC;
	msg.head.magic = TEE_VLTMM_AGENT_ID;
	msg.size = nsize;
	ret = send_client_msg((void *)&msg, sizeof(msg));
	uva = (void *)(uintptr_t)msg.addr;
	if (ret != 0) {
		tloge("vlt malloc failed, size: %x, ret: %d", size, ret);
		return NULL;
	}

	__mutex_lock();
	ret = vltmm_pool_add((uint32_t)(uintptr_t)uva, nsize, msg.fd);
	if (ret != 0) {
		tloge("vlt pool add failed, ret: %d", ret);
		vlt_set_errno(ret);
		__mutex_unlock();
		return NULL;
	}

	uva = vltmm_pool_alloc(size);
	if (uva == NULL) {
		vlt_set_errno(VLT_ERR_VLTNOMEM);
		tloge("vlt malloc, va:%p size: %x %x \n", __print_ptr(uva), size, nsize);
	} else {
		tlogi("vlt malloc, va:%p size: %x %x \n", __print_ptr(uva), size, nsize);
	}
	__mutex_unlock();
	return uva;
}

void vlt_free(void *ptr, uint32_t size)
{
	if (!vltmm_is_init() || !ptr || size == 0) {
		vlt_set_errno(VLT_ERR_PARAM);
		return;
	}

	__mutex_lock();
	vltmm_pool_free((uint32_t)(uintptr_t)ptr, size);
	__mutex_unlock();
	tlogi("vlt free, addr:%p size:%x\n", __print_ptr(ptr), size);
}

uint32_t vlt_open(uint32_t size)
{
	struct sharemem_msg_t clientmsg;
	int ret;

	if (!vltmm_is_init() || size == 0)
		return 0;

	(void)memset_s(&clientmsg, sizeof(clientmsg), 0, sizeof(clientmsg));
	clientmsg.head.ret = -1;
	clientmsg.head.cmd = CMD_CTOS_OPENFD;
	clientmsg.head.magic = TEE_VLTMM_AGENT_ID;
	clientmsg.size = size;

	ret = send_client_msg((struct vltmm_msg_t *)&clientmsg,
			sizeof(struct sharemem_msg_t));

	if (ret == TEE_SUCCESS) {
		tlogi("vlt open, fd:%u \n", clientmsg.fd);
		return clientmsg.fd;
	}
	tloge("vlt open, ret: %d fd: %u \n", ret, clientmsg.fd);
	return 0;
}

void vlt_close(uint32_t fd)
{
	struct sharemem_msg_t clientmsg;
	int ret;

	if (!vltmm_is_init())
		return;

	(void)memset_s(&clientmsg, sizeof(clientmsg), 0, sizeof(clientmsg));
	clientmsg.head.ret = -1;
	clientmsg.head.cmd = CMD_CTOS_CLOSEFD;
	clientmsg.head.magic = TEE_VLTMM_AGENT_ID;
	clientmsg.fd = fd;

	ret = send_client_msg((struct vltmm_msg_t *)&clientmsg, sizeof(struct sharemem_msg_t));
	if (ret != TEE_SUCCESS)
		tloge("vlt close ret: %d fd: %u\n", ret, fd);

	return;
}

void *vlt_map(uint32_t fd, uint32_t cached)
{
	struct sharemem_msg_t clientmsg;
	int ret;

	if (!vltmm_is_init())
		return NULL;

	(void)memset_s(&clientmsg, sizeof(clientmsg), 0, sizeof(clientmsg));
	clientmsg.head.ret = -1;
	clientmsg.head.cmd = CMD_CTOS_MAPFD;
	clientmsg.head.magic = TEE_VLTMM_AGENT_ID;
	clientmsg.fd = fd;
	if (cached)
		clientmsg.cached = 1;

	ret = send_client_msg((struct vltmm_msg_t *)&clientmsg, sizeof(struct sharemem_msg_t));
	if (ret != TEE_SUCCESS) {
		tloge("vlt map ret: %d fd: %u\n", ret, fd);
		return NULL;
	}

	return (void *)(uintptr_t)clientmsg.va;
}

int vlt_unmap(uint32_t fd, void *va)
{
	struct sharemem_msg_t clientmsg;
	int ret;

	if (!vltmm_is_init())
		return -1;

	(void)memset_s(&clientmsg, sizeof(clientmsg), 0, sizeof(clientmsg));
	clientmsg.head.ret = -1;
	clientmsg.head.cmd = CMD_CTOS_UNMAPFD;
	clientmsg.head.magic = TEE_VLTMM_AGENT_ID;
	clientmsg.fd = fd;
	clientmsg.va = (uint64_t)(uintptr_t)va;

	ret = send_client_msg((struct vltmm_msg_t *)&clientmsg, sizeof(struct sharemem_msg_t));
	if (ret != TEE_SUCCESS)
		tloge("vlt unmap ret: %d fd:%u va:%p\n", ret, fd, __print_ptr(va));

	return ret;
}

int vlt_import_fd(uint32_t fd)
{
	struct sharemem_msg_t clientmsg;
	int ret;

	if (!vltmm_is_init())
		return -1;

	(void)memset_s(&clientmsg, sizeof(clientmsg), 0, sizeof(clientmsg));
	clientmsg.head.ret = -1;
	clientmsg.head.cmd = CMD_CTOS_IMPORTFD;
	clientmsg.head.magic = TEE_VLTMM_AGENT_ID;
	clientmsg.fd = fd;

	ret = send_client_msg((struct vltmm_msg_t *)&clientmsg, sizeof(struct sharemem_msg_t));
	if (ret != TEE_SUCCESS)
		tloge("vlt import fd ret: %d fd:%u\n", ret, fd);

	return ret;
}

/* return: shrinker count */
uint32_t vlt_shrinker(uint64_t *addr, uint32_t max)
{
	struct vltmm_msg_t *head = NULL;
	struct shrinker_msg_t *data = NULL;
	int ret, len;

	if (!addr)
		return 0;

	len = sizeof(struct vltmm_msg_t) + sizeof(struct shrinker_msg_t);
	head = TEE_Malloc(len, 0);
	if (!head)
		return 0;
	(void)memset_s(head, len, 0, len);

	head->ret = -1;
	head->cmd = CMD_CTOS_SHRINKER;
	head->magic = TEE_VLTMM_AGENT_ID;
	ret = send_client_msg(head, len);
	if (ret) {
		TEE_Free(head);
		return 0;
	}

	data = (struct shrinker_msg_t *)(uintptr_t)head->buf_start;
	ret = memcpy_s(addr, max, data->addr, data->num * sizeof(uint64_t));
	if (ret) {
		TEE_Free(head);
		return 0;
	}

	TEE_Free(head);
	return data->num;
}

int vlt_errno(void)
{
	return g_vlt_errno;
}
