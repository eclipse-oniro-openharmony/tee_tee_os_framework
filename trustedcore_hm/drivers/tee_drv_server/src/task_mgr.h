/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: drvcaller and drv node structure
 * Create: 2021-12-28
 */

#ifndef TEE_DRV_SERVER_TASK_MGR_H
#define TEE_DRV_SERVER_TASK_MGR_H

#include <stdint.h>
#include <pthread.h>
#include <list.h>
#include <tee_defines.h>
#include <tee_driver_module.h>
#include "drv_dispatch.h"
#include "drv_dyn_conf_mgr.h"
#include "drvcall_dyn_conf_mgr.h"
#include "dyn_conf_common.h"

#define DRVCALL_DEC_CNT_INCLUDE_REGISTER_ONE 2U

struct drv_tlv;

enum node_state {
    TASK_LOAD, /* only used by drv */
    TASK_SPAWN, /* only used by drv */
    TASK_NORMAL,
    TASK_SPAWN_FAIL, /* only used by drv */
    TASK_EXIT, /* only used by ta since drv cannot support load dynamically */
};

struct task_tlv {
    struct tee_uuid uuid;
    struct drvcall_perm_apply_item_t *drvcall_perm_apply_list; /* drvcall_perm_apply items list */
    uint32_t drvcall_perm_apply_list_size;
    struct drv_conf_t *drv_conf;
};

struct drv_task_info {
    cref_t channel;
    int32_t drv_index;
    bool register_policy;
};

struct task_node {
    struct list_head node_list;
    int32_t target_type; /* declare drv or ta */
    uint32_t pid;
    uint32_t ref_cnt; /* TA: register +1, unregister -1 */
    uint32_t fd_count; /* locked by fd_mtx */
    struct list_head fd_head; /* locked by fd_mtx */
    pthread_mutex_t fd_mtx;
    enum node_state state; /* drv and ta state */
    pthread_cond_t state_cond;
    pthread_mutex_t state_mtx;
    struct task_tlv tlv;
    struct drv_task_info drv_task;
};

struct task_node *get_drv_node_by_name_with_lock(const char *drv_name, uint32_t len);
struct task_node *get_node_by_uuid_with_lock(const struct tee_uuid *uuid, uint32_t taskid);
struct task_node *get_ta_node_and_set_exit(const struct tee_uuid *uuid);
int32_t get_drvcall_and_fd_node(int64_t fd, const struct tee_drv_param *params,
    struct task_node **call_node, struct fd_node **fdata);
void put_node_with_lock(struct task_node *node, uint32_t dec_cnt);
int32_t receive_task_conf(struct task_node *node);

struct task_node *alloc_and_init_ta_node(const struct drvcall_conf_t *tlv);
struct task_node *alloc_and_init_drv_node(struct drv_tlv *tlv);
void free_task_node(struct task_node *node);
int32_t free_drv_conf_by_service_name(const char *drv_name, uint32_t len);
struct task_node *find_drv_node_by_taskid(uint32_t exit_pid);
void tee_drv_pm_cmd_handle(uint16_t msg_id);
bool check_hardware_type(const struct task_node *node, uint16_t type);

#ifdef TEE_SUPPORT_DYN_CONF_DEBUG
void dump_task_node(void);
#endif

#endif
