/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2020. All rights reserved.
 * Description: gatekeeper proc failed record head file
 * Create: 2015-08-08
 * History: 2019-01-18 jiashi restruct
 */

#ifndef _GATE_KEEPER_FAIL_RECORD_H_
#define _GATE_KEEPER_FAIL_RECORD_H_

#include <stdint.h>
#include <stdbool.h>
#include <dlist.h>
#include <pthread.h>
#include "gatekeeper.h"

#ifndef GK_RECORD
#define GK_RECORD

#define BIT_RESERVED_NUM  3

struct failure_record_t {
    uint64_t secure_user_id;
    uint64_t last_checked_timestamp;
    uint32_t failure_counter;
} __attribute__((packed));

struct failure_record_uid_t {
    uint32_t uid;
    uint8_t version;
    uint8_t reserved[BIT_RESERVED_NUM]; /* 4-byte alignment */
    uint8_t signature[HMAC_SIZE];
    struct failure_record_t record;
} __attribute__((packed));

struct fail_record_t {
    struct dlist_node fail_record_head;
    struct failure_record_uid_t record_uid;
};
#endif

#define MAX_RECORD_LIST_NUM         600U

int gk_mutex_lock_ops(pthread_mutex_t *mutex);
void init_fail_list(void);
bool add_fail_record(struct failure_record_uid_t *record_uid, bool init_flag);
bool read_fail_record(struct failure_record_uid_t *record_uid);
bool write_fail_record(const struct failure_record_uid_t *record_uid);
bool delete_fail_record(const struct failure_record_uid_t *record_uid);
bool read_sub_user_fail_record(struct failure_record_uid_t *record_array, uint32_t *array_size);
bool read_primary_fail_record(struct failure_record_uid_t *primary_record);
bool duplicate_record_exist();
#endif
