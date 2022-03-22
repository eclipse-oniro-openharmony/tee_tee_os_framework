/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020.. All rights reserved.
 * Description: secure memory service.
 * Create: 2020-03-06
 * Notes:
 * History: 2020-03-06 create
 */

#ifndef __SECMEM_SERVICE_H_
#define __SECMEM_SERVICE_H_


#define MAP_MAX          5
#define MAX_BUFFER_ID    8192
#define POOL_DUMP_LEN    80
/* num of gran, if > 7, must modify vltmm_shrinker_process, use sharemem */
#define SHRINKER_CNT_MAX 4
#define VLTMM_GRAN_MAX   128
#define QUERY_CNT_MAX   4

#define SIZE_8          8
#define SIZE_32         32
#define SIZE_2M         0x200000

#define VLTMM_CHUNK_SIZE    0x1000000 /* 16M */
#define VLTMM_SCATTER_SIZE  0x200000  /* 2M */

#define VLTMM_MALLOC_INTERVAL  200   /* ms */

#define VLTMM_MSG_T struct vltmm_msg_t

enum SEC_SVC {
	SEC_TUI = 0,
	SEC_EID,
	SEC_TINY,
	SEC_FACE_ID,
	SEC_FACE_ID_3D,
	SEC_DRM_TEE,
	SEC_HIAI,
	SEC_IVP,
	SEC_ISP,
	SEC_SVC_MAX,
};

enum vltmm_ctos_cmd_e {
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

enum vltmm_stoa_cmd_e {
	CMD_STOA_ALLOC,
	CMD_STOA_FREE,
};

enum __SMEM_CID{
	SMEM_SECCM_XM = 0,
	SMEM_SECOS_1M = 1,
	SMEM_SECOS_2M = 2,
	SMEM_HEAPS_MAX,
};

struct vltmm_msg_t {
	uint32_t  cmd; /* from client to service */
	uint32_t  magic;
	int32_t   ret;
	uint32_t  buf_len;
	void     *buf_start[0];
};

struct vltmm_agent_msg_t {
	uint32_t  magic;
	uint32_t  cmd;
	int32_t   ret;
	uint32_t  cid;
	uint32_t  num;
	uint32_t  pad;
	uint64_t  data[0];
};

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

struct query_msg_t {
	uint32_t  fd;
	uint32_t  num;
	uint64_t  addr[QUERY_CNT_MAX];
};

struct shrinker_msg_t {
	uint32_t  magic;
	uint32_t  num;
	uint64_t  addr[SHRINKER_CNT_MAX];
};

struct vltmm_pool_node {
	struct list_head list;
	uint64_t pa;
	uint32_t size;
};

struct mapinfo_t {
	uint64_t va;
	uint32_t tid;
};

struct vltmm_used_node {
	struct list_head list;
	uint32_t fd;
	uint32_t refcount;
	uint32_t size;
	uint32_t nents;
	struct page_info *array;
	struct mapinfo_t vainfo[MAP_MAX];
	uint32_t owner_pid[MAP_MAX];
};

struct ta_task_t {
	uint32_t pid;
	TEE_UUID uuid;
};

struct vltmm_pool_t {
	struct list_head poollist;
	struct list_head usedlist;
	uint32_t pool_avail;
	uint32_t used_size;
	struct bitmap id_gen;
	uint32_t id_max;
	uint32_t contig_size;
	pthread_mutex_t pthread_lock;
};

#endif
