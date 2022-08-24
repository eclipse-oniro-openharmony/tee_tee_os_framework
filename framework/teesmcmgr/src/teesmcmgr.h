/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: some functions declaration of hmsmcmgr
 * Create: 2020-05-12
 */
#ifndef TEESMCMGR_H
#define TEESMCMGR_H

#include <stdint.h>
#include <hmlog.h>
#include <stdbool.h>
#include <sys/hmapi.h>
#define SMCMGR_STACK_SIZE  0x2000

#define PAY_LOAD_SIZE 24
#define MAGIC_MSG "IDLE_0xDEADBEEF"

#define panic(fmt...)                             \
    do {                                          \
        hm_panic("*PANIC* teesmcmgr: " fmt); \
    } while (0)
#define fatal(fmt...)                             \
    do {                                          \
        hm_fatal("*FATAL* teesmcmgr: " fmt); \
        if (hmapi_proc_exit((uint32_t)-1))        \
            hm_panic("*PANIC* teesmcmgr error");  \
    } while (0)
#define error(fmt...)                             \
    do {                                          \
        hm_error("*ERROR* teesmcmgr: " fmt); \
    } while (0)
#define info(fmt...)                             \
    do {                                         \
        hm_info("*INFO* teesmcmgr: " fmt); \
    } while (0)
#define debug(fmt...)                             \
    do {                                          \
        hm_debug("*DEBUG* teesmcmgr: " fmt); \
    } while (0)

void *tee_idle_thread(void *arg);
void *tee_smc_thread(void *arg);

rref_t acquire_sysctrl_local_irq_hdlr(void);
cref_t acquire_teesmc_hdlr(void);
rref_t acquire_gtask_channel(void);

void set_teesmc_hdlr(cref_t value);
void set_sysctrl_hdlr(rref_t value);
void set_gtask_channel_hdlr(rref_t value);
void set_is_gtask_alive(bool value);

cref_t get_teesmc_hdlr(void);
rref_t get_sysctrl_hdlr(void);
rref_t get_gtask_channel_hdlr(void);
bool   get_is_gtask_alive(void);

#endif
