/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Header of gp time api
 * Create: 2022-04-22
 */

#ifndef SYS_LIBS_LIBTIMER_ANTI_ROOT_API_H
#define SYS_LIBS_LIBTIMER_ANTI_ROOT_API_H

TEE_Result tee_antiroot_create_timer(uint32_t time_seconds);
TEE_Result tee_antiroot_destory_timer(void);

#endif