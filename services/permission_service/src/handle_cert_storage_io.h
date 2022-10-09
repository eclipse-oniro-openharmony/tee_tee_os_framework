/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: perm service do elf verify
 * Create: 2022-03-11
 */
#ifndef HANDLE_CERT_SSA_IO_H
#define HANDLE_CERT_SSA_IO_H

#include <tee_defines.h>
#include <tamgr_ext.h>
#include "permission_service.h"

#define MAX_CRT_LEN 2048

TEE_Result export_cert_from_storage(uint8_t *dst, uint32_t *dst_len, uint32_t limit);
TEE_Result import_cert_to_storage(uint8_t *src, size_t len);
TEE_Result remove_cert_from_storage(void);
#endif
