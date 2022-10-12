/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee app image load service head file
 * Create: 2022.04.15
 */
#include "handle_config.h"
#include "tee_log.h"
#include "permission_service.h"
#include "tee_perm_img.h"

TEE_Result get_config_cert_param(cert_param_t *cert_param, struct sign_config_t *config)
{
    (void)cert_param;
    (void)config;
    return TEE_SUCCESS;
}

TEE_Result oh_get_verify_key(void **key, const struct sign_config_t *config, cert_param_t *cert_param)
{
    (void)key;
    (void)config;
    (void)cert_param;
    tloge("should support permission service\n");
    return TEE_ERROR_GENERIC;
}

