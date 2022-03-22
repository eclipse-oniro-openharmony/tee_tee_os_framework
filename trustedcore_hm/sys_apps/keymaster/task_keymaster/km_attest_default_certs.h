/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster attest cert headers
 * Create: 2020-02-13
 */
#ifndef __KM_ATTEST_DEFAULT_CERTS_H
#define __KM_ATTEST_DEFAULT_CERTS_H
#include "tee_internal_api.h"
#include "keymaster_defs.h"

/* untrusted certificates from google SoftKeymasterDevice, for using when no provision key exist. */
#define UNTRUSTED_CERTS_COUNT 2
int32_t device_cert(int alg, keymaster_blob_t *cert_entry);
int32_t get_default_attest_key(keymaster_algorithm_t algorithm, void *attest_key);
int32_t format_untrusted_chain(uint8_t *chain, uint32_t *out_len, int32_t src, int32_t alg);
#endif