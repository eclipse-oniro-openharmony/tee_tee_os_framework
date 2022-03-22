/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020.. All rights reserved.
 * Description: secure memory header.
 * Create: 2020-03-16
 * Notes:
 * History: 2020-03-16 create
 */

#ifndef __VLTMM_PRIVATE_H_
#define __VLTMM_PRIVATE_H_

#define SHRINKER_CNT_MAX 4
#define VLTMM_CHUNK_SIZE    0x400000  /* 4M */
#define VLTMM_SCATTER_SIZE  0x200000  /* 2M */
#define POOL_DUMP_LEN       80
#define SIZE_8              8
#define SIZE_32            32


enum vltmm_cmd_e {
	CMD_CTOS_CREATE,
	CMD_CTOS_DESTROY,
	CMD_CTOS_ALLOC,
	CMD_CTOS_FREE,
	CMD_CTOS_OPENFD,
	CMD_CTOS_CLOSEFD,
	CMD_CTOS_IMPORTFD,
	CMD_CTOS_MAPFD,
	CMD_CTOS_UNMAPFD,
	CMD_CTOS_POOLDUMP,
	CMD_CTOS_QUERYFD,
	CMD_CTOS_SHRINKER,
	CMD_CTOS_CREATE_DOMAIN,
	CMD_CTOS_DESTROY_DOMAIN,
};
enum vltmm_memtype_e {
	VLT_MEM_NORMAL,
	VLT_MEM_SHARED
};

struct vltmm_msg_t {
	uint32_t  cmd; /* from client to service */
	uint32_t  magic;
	int32_t   ret;
	uint32_t  buf_len;
	void     *buf_start[0];
};
#define VLTMM_MSG_T         struct vltmm_msg_t

struct domain_msg_t {
	struct    vltmm_msg_t head;
	uint32_t  sid;
	uint32_t  size;
};

struct alloc_msg_t {
	struct vltmm_msg_t head;
	uint32_t  fd;
	uint32_t  size;
	uint64_t  addr;
};

struct free_msg_t {
	struct vltmm_msg_t head;
	uint32_t  fd;
	uint32_t  size;
	uint64_t  addr;
};

struct sharemem_msg_t {
	struct vltmm_msg_t head;
	uint32_t  fd;
	uint32_t  size;
	uint64_t  va;
	uint32_t  cached;
};

struct shrinker_msg_t {
	uint32_t  magic;
	uint32_t  num;
	uint64_t  addr[SHRINKER_CNT_MAX];
};

struct client_pool_node {
	struct gen_pool *pool;	
	struct list_head list;
	uint32_t fd;
};

struct client_pool {
	struct list_head poollist;
	uint32_t align;
	uint32_t order;
	uint32_t chunk_size;
	uint32_t init;
	uint32_t sid;
	uint32_t poolnum;
	uint32_t maxsize;
};

enum {
	VLT_SUCCESS = 0,
	VLT_ERR_NOTINIT,
	VLT_ERR_PARAM,
	VLT_ERR_NOMEM,
	VLT_ERR_VLTNOMEM
};

#endif
