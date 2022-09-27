/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: Tee object header file
 * Create: 2012-01-15
 */
#ifndef TEE_OBJ_H
#define TEE_OBJ_H

#include <pthread.h>

#include "tee_defines.h"

TEE_Result tee_obj_setname(TEE_ObjectHandle object, const uint8_t *name, uint32_t len);
TEE_Result tee_obj_new(TEE_ObjectHandle *object);
TEE_Result tee_obj_free(TEE_ObjectHandle *object);
TEE_Result tee_obj_init(void);
void tee_memory_dump(const uint8_t *data, uint32_t count);
void dump_object(void);
TEE_Result check_object(const TEE_ObjectHandle object);
TEE_Result add_object(TEE_ObjectHandle object);
TEE_Result delete_object(const TEE_ObjectHandle object);
TEE_Result check_permission(const char *object_id, size_t object_id_len, uint32_t flags);
int mutex_lock_ops(pthread_mutex_t *mutex);
TEE_Result check_enum_object_in_list(const TEE_ObjectEnumHandle object);
TEE_Result add_enum_object_in_list(const TEE_ObjectEnumHandle object);
void delete_enum_object_in_list(const TEE_ObjectEnumHandle object);
#endif
