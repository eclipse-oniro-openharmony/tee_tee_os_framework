/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declare the functions and struct related itrustee driver call check.
 * Create: 2020-02
 */
#ifndef ITRUSTEE_DRV_CALL_H
#define ITRUSTEE_DRV_CALL_H

#include <sys/hm_types.h>
#include <drv_module.h>
#include <tee_defines.h>

#define DRV_CALL_ERROR     (-1)
#define DRV_CALL_OK        0
#define ACCESS_WRITE_RIGHT 1U
#define ACCESS_READ_RIGHT  2U
#define MMAP_PTR_MAX       16U
#define A32                1U
#define A64                2U

struct mmaped_ptr {
    union {
        uint64_t addr_64;
        uint32_t addr_32;
    } addr;
    uint32_t len;
    void *ptr;
    void *l_ptr;
    void *pptr;
    char need_cp;
    char need_lo;
    uint64_t ori_ptr;
    int32_t prot;
    uint32_t access_flag;
};

struct msg_args {
    uint64_t r0;
    uint64_t r1;
    uint64_t r2;
    uint64_t r3;
    uint64_t r10;
    uint64_t r11;
};

struct timer_sys_id {
    struct tee_uuid uuid;
    pid_t pid;
};

struct call_params {
    int32_t swi_id;
    struct mmaped_ptr mmaped_ptrs[MMAP_PTR_MAX];
    struct timer_sys_id sys_id;
    struct msg_args *regs;
    uint32_t mmaped_ptr_cnt;
    pid_t pid;
    pid_t self_pid;
    uint64_t *args;
    uint32_t addr_type;
    uint64_t job_handler;
};

int32_t audit_check_fail(void);
int32_t check_call_permission(uint64_t current_permission, uint64_t permission);
void unmap_maped_ptrs(struct call_params *param);
int32_t mmap_call_param(struct call_params *param, uint32_t index);

#endif
