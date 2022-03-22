/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key format transfer between GP and buffer header
 * Create: 2020-11-09
 */
#ifndef __KM_KEY_GP_H
#define __KM_KEY_GP_H
TEE_Result gp_buffer_to_key_obj(uint8_t *buffer, uint32_t buffer_len, TEE_ObjectHandle key_obj);
TEE_Result key_object_to_buffer(const TEE_ObjectHandle key_obj, uint8_t *kb, uint32_t *buffer_len);
#endif