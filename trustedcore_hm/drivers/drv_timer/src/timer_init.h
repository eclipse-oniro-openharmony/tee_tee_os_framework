/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for timer_init
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_SRC_TIMER_INIT_H
#define DRV_TIMER_SRC_TIMER_INIT_H

#include <stdint.h>
#include <kernel/time.h>
#include <sys/usrsyscall_new_ext.h>
#include <hm_msg_type.h>
#include <tee_defines.h>
#include <sys/hm_types.h>

TEE_Result add_ta_permission(const TEE_UUID *uuid, uint64_t permissions);
intptr_t timer_pm_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info);
intptr_t timer_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info);
int32_t timer_init(cref_t chnl_cref);
uint32_t get_mix_seed(void);
uint32_t timer_drv_init(void);
pid_t get_g_caller_pid(void);

struct ioaddr_timer_t {
    paddr_t base;
    uint32_t size;
    bool mapped;
};

#endif /* DRV_TIMER_SRC_TIMER_INIT_H */
