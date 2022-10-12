/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee app image load service head file
 * Create: 2022.04.15
 */
#ifndef TEE_PERM_IMG_H
#define TEE_PERM_IMG_H

#include "tee_defines.h"
#include "permission_service.h"

struct sign_config_t {
    uint32_t key_len;
    size_t hash_size;
    int32_t hash_nid;
    int32_t padding;
    uint32_t key_style;
    uint32_t sign_ta_alg;
    bool is_oh;
};

TEE_Result oh_get_verify_key(void **key, const struct sign_config_t *config, cert_param_t *cert_param);
TEE_Result get_config_cert_param(cert_param_t *cert_param, struct sign_config_t *config);

#endif

