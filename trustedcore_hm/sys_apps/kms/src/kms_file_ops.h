/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:kms file operation functions
 * Create: 2021-12-01
 */

#ifndef KMS_KMS_FILE_OPS_H
#define KMS_KMS_FILE_OPS_H

#include "kms_pub_def.h"

TEE_Result kms_file_write(const char *file_name, const uint8_t *buffer, uint32_t len);

TEE_Result kms_file_access(const char *file_name);

TEE_Result kms_file_read(const char *file_name, uint8_t *buffer, uint32_t *len);

TEE_Result kms_file_rename(const char *old_file_name, const char *new_file_name);

TEE_Result kms_file_remove(const char *file_name);
#endif
