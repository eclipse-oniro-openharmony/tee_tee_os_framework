/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:  Tee-load-lib function declaration.
 * Author: yangjing  y00416812
 * Create: 2019-04-18
 */

#ifndef GTASK_TEE_LOAD_LIB_H
#define GTASK_TEE_LOAD_LIB_H
#include "gtask_core.h"

extern struct service_struct *g_cur_service;
extern struct session_struct *g_cur_session;

#define CHECK_ERROR    (-1)
#define LIB_LOADED     1
#define LIB_NOT_LOADED 0

TEE_Result process_close_session_entry(struct service_struct **service, struct session_struct **session);
void tee_delete_all_libinfo(struct service_struct *service);
TEE_Result tee_add_libinfo(struct service_struct *service, const char *name, size_t name_size,
                           tee_img_type_t type);
int is_lib_loaded(const struct service_struct *service, const char *name, size_t name_size);
void do_age_timeout_lib(struct service_struct *service);
int32_t handle_unlink_dynamic_drv(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size);
#endif
