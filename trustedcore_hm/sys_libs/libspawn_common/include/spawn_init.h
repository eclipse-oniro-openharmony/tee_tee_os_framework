/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: structure and function defined for spawn process
 * Create: 2021-07-13
 */

#ifndef LIBSPAWN_COMMON_INCLUDE_SPAWN_INIT_H
#define LIBSPAWN_COMMON_INCLUDE_SPAWN_INIT_H

#include <stdint.h>
#include <sys/types.h>
#include <tee_defines.h>

#define ARGV_SIZE  64
#define ARGV0_SIZE 100
#define ARGV2_SIZE 8
#define MAX_DYN_CLIENT_NUM 20
#define CLIENT_NAME_SIZE   72   /* client name len 64 bytes + path len */
enum env_index {
    ENV_PRIORITY_INDEX,
    ENV_UID_INDEX,
    ENV_TARGET_TYPE_INDEX,
    ENV_DRV_INDEX_INDEX,
    ENV_THREAD_LIMIT_INDEX,
    ENV_STACK_SIZE_INDEX,
    ENV_TERMINATE_INDEX, /* must reserve one since sysmgr will use it as terminate signal */
    ENV_MAX,
};

enum argv_index {
    ARGV_TASK_NAME_INDEX,
    ARGV_TASK_PATH_INDEX,
    ARGV_UNCOMMIT_INDEX,
    ARGV_CLIENT_NAME_INDEX,
    ARGV_TERMINATE_INDEX, /* must reserve one since sysmgr will use it as terminate signal */
    ARGV_MAX,
};

struct env_param {
    int32_t priority;
    uint32_t uid;
    uint32_t target_type;
    uint32_t drv_index;
    uint32_t thread_limit;
    uint32_t stack_size;
};

struct env_base_buffer {
    char priority[ARGV_SIZE];
    char uid[ARGV_SIZE];
    char target_type[ARGV_SIZE];
} __attribute__((packed));

struct env_drv_base_buffer {
    char drv_index[ARGV_SIZE];
    char thread_limit[ARGV_SIZE];
    char stack_size[ARGV_SIZE];
} __attribute__((packed));

struct argv_base_buffer {
    char task_name[ARGV0_SIZE];
    char task_path[ARGV_SIZE];
    char uncommit[ARGV2_SIZE];
    char client_name[CLIENT_NAME_SIZE * MAX_DYN_CLIENT_NUM];
} __attribute__((packed));

struct spawn_buffer {
    struct env_base_buffer env;
    struct argv_base_buffer argv;
} __attribute__((packed));

struct spawn_drv_buffer {
    struct env_base_buffer env;
    struct env_drv_base_buffer env_drv;
    struct argv_base_buffer argv;
} __attribute__((packed));

/* msg used for drvmgr and drv process */
#define DRV_SPAWN_SYNC_NAME "drv_spawn_sync"
#define PROCESS_INIT_SUCC 0x1
#define PROCESS_INIT_FAIL 0x2
struct spawn_sync_msg {
    uint32_t msg_id;
};

int32_t set_env_for_task(const struct env_param *param, const struct tee_uuid *uuid, struct env_base_buffer *env);

int32_t set_drv_env_for_task(const struct env_param *param, struct env_drv_base_buffer *env);

#endif
