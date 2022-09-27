/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: drvmgr head file
 * Create: 2018-03-31
 */

#ifndef LIBHMDRV_HMDRV_H
#define LIBHMDRV_HMDRV_H

#include <hm_msg_type.h>
#include <sys/hm_types.h>
#define MAX_ARGS 16

#ifndef SYSCALL_DATA_MAX
#define SYSCALL_DATA_MAX 512
#define SYSCAL_MSG_BUFFER_SIZE 2048
#endif

struct hm_drv_req_msg_t {
    hm_msg_header header;
    uint64_t args[MAX_ARGS];
    cref_t job_handler;
    char data[];
} __attribute__((__packed__));

struct hm_drv_reply_msg_t {
    hm_msg_header header;
    uint64_t __rsvd;
    char rdata[];
} __attribute__((__packed__));

struct drv_call_params {
    uint64_t *args;
    uint32_t *lens;
    int32_t nr;
    void *rdata;
    uint32_t rdata_len;
};

int32_t hm_drv_init(const char *path);
int32_t renew_hmdrv_job_handler(void);

int64_t hm_drv_call_new(const char *name, uint16_t id, uint64_t *args, uint32_t *lens, int32_t nr);

#endif /* LIBHMDRV_HMDRV_H */
