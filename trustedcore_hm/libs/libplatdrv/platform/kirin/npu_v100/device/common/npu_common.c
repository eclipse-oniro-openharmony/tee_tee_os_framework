/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu add and remove
 */

#include "npu_common.h"
#include "libhwsecurec/securec.h"
#include <list.h>
#include <sre_typedef.h>

#include "drv_log.h"

static struct npu_dev_ctx *g_dev_ctxs[NPU_DEV_NUM];

void dev_ctx_array_init(void)
{
	int i;
	for (i = 0; i < NPU_DEV_NUM; i++) {
		g_dev_ctxs[i] = NULL;
	}
}

void set_dev_ctx_with_dev_id(struct npu_dev_ctx *dev_ctx, u8 dev_id)
{
	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %u\n", dev_id);
		return;
	}

	g_dev_ctxs[dev_id] = dev_ctx;
}

struct npu_dev_ctx *get_dev_ctx_by_id(u8 dev_id)
{
	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %u\n", dev_id);
		return NULL;
	}

	return g_dev_ctxs[dev_id];
}

int npu_add_proc_ctx(struct list_head *proc_ctx, u8 dev_id)
{
	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null \n");
		return -1;
	}

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d\n", dev_id);
		return -1;
	}

	if (g_dev_ctxs[dev_id] == NULL) {
		NPU_ERR(" npu dev %d context is null\n", dev_id);
		return -1;
	}

	list_add(proc_ctx, &g_dev_ctxs[dev_id]->proc_ctx_list);

	return 0;
}

int npu_add_proc_ctx_to_rubbish_ctx_list(struct list_head *proc_ctx, u8 dev_id)
{
	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null \n");
		return -1;
	}

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d\n", dev_id);
		return -1;
	}

	if (g_dev_ctxs[dev_id] == NULL) {
		NPU_ERR(" npu dev %d context is null\n", dev_id);
		return -1;
	}

	list_add(proc_ctx, &g_dev_ctxs[dev_id]->rubbish_context_list);

	return 0;
}

int npu_remove_proc_ctx(struct list_head *proc_ctx, u8 dev_id)
{
	struct list_head *pos = NULL;
	struct list_head *n = NULL;

	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null \n");
		return -1;
	}

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d\n", dev_id);
		return -1;
	}

	if (g_dev_ctxs[dev_id] == NULL) {
		NPU_ERR(" npu dev %d context is null\n", dev_id);
		return -1;
	}

	if (list_empty_careful(&g_dev_ctxs[dev_id]->proc_ctx_list)) {
		NPU_DEBUG("g_dev_ctxs npu dev id %d pro_ctx_list is"
			" null ,no need to remove any more\n", dev_id);
		return 0;
	}

	list_for_each_safe(pos, n, &g_dev_ctxs[dev_id]->proc_ctx_list) {
		if (proc_ctx == pos) {
			pos->prev->next = n;
			n->prev = pos->prev;
			list_del(pos);
			break;
		}
	}

	NPU_DEBUG("remove g_dev_ctxs npu dev id %d pro_ctx_list\n", dev_id);

	return 0;
}

void npu_set_sec_stat(u8 dev_id, u32 state)
{
	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %u\n", dev_id);
		return;
	}
	NPU_WARN("set npu dev %u secure state = %u", dev_id, state);
	g_dev_ctxs[dev_id]->secure_state = state;
}

u32 npu_get_sec_stat(u8 dev_id)
{
	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %u\n", dev_id);
		return NPU_SEC_UNDEFINED;
	}

	return g_dev_ctxs[dev_id]->secure_state;
}


// set to 1(occupied)
int bitmap_set(u8 map[], u32 map_size, u32 bit_pos)
{
	u32 byte_idx;
	u32 bit_idx;

	byte_idx = bit_pos / BITS_PER_BYTE;
	if (byte_idx >= map_size) {
		NPU_ERR("byte_idx = %u map_size = %u is illegal", byte_idx, map_size);
		return -1;
	}

	bit_idx = bit_pos % BITS_PER_BYTE;
	map[byte_idx] |= ((u8)(1UL << bit_idx));

	return 0;
}

// clear to 0(free)
int bitmap_clear(u8 map[], u32 map_size, u32 bit_pos)
{
	u32 byte_idx;
	u32 bit_idx;

	byte_idx = bit_pos / BITS_PER_BYTE;
	if (byte_idx >= map_size) {
		NPU_ERR("byte_idx = %u map_size = %u is illegal", byte_idx, map_size);
		return -1;
	}

	bit_idx = bit_pos % BITS_PER_BYTE;
	map[byte_idx] &= ~((u8)(1UL << bit_idx));

	return 0;
}

// bit val 1 is occupied
bool bitmap_occupied(u8 map[], u32 map_size, u32 bit_pos)
{
	u32 byte_idx;
	u32 bit_idx;
	u8 tmp_val;
	u8 cmp_val;

	byte_idx = bit_pos / BITS_PER_BYTE;
	if (byte_idx >= map_size) {
		NPU_ERR("byte_idx = %u map_size = %u is illegal", byte_idx, map_size);
		return false;
	}

	bit_idx = bit_pos % BITS_PER_BYTE;
	cmp_val = map[byte_idx];
	tmp_val = ((u8)(1UL << bit_idx));

	return (cmp_val & tmp_val) ? true : false;
}

