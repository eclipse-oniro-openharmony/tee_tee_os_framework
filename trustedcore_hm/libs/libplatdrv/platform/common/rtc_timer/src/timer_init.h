/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for timer_init
 * Create: 2021-05-27
 */

#ifndef RTC_TIMER_DRIVER_TIMER_INIT_H
#define RTC_TIMER_DRIVER_TIMER_INIT_H

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

#endif /* RTC_TIMER_DRIVER_TIMER_INIT_H */
