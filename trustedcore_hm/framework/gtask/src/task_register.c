/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: register task to gtask
 * Create: 2022-01-15
 */

#include "task_register.h"
#include "task_dynamic_adaptor.h"

void register_task_art_srv(void)
{
#ifdef TEE_SUPPORT_ART
    TEE_UUID uuid = TEE_SERVICE_ART;
    struct srv_adaptor_config_t config = {0};
    config.agent_id = 0;
    config.task_prio = TASK_PRIO_ART_SERVICE;
    config.is_need_release_ta_res = false;
    config.crash_callback = true;
    config.is_need_create_msg = false;
    config.is_need_release_msg = false;
    register_dynamic_task(&uuid, ART_TASK_NAME, &config);
#endif
}

void register_task_bio_srv(void)
{
#ifdef TEE_SUPPORT_BIO
    TEE_UUID uuid = TEE_SERVICE_BIO;
    struct srv_adaptor_config_t config = {0};
    config.task_prio = TASK_PRIO_BIO_SERVICE;
    config.agent_id = 0;
    config.is_need_release_ta_res = false;
    config.crash_callback = true;
    config.is_need_create_msg = false;
    config.is_need_release_msg = false;
    register_dynamic_task(&uuid, BIO_TASK_NAME, &config);
#endif
}

void register_task_hsm_srv(void)
{
#ifdef TEE_SUPPORT_HSM
    TEE_UUID uuid = TEE_SERVICE_HSM;
    struct srv_adaptor_config_t config = {0};
    config.task_prio = TASK_PRIO_HSM_SERVICE;
    config.agent_id = 0;
    config.is_need_release_ta_res = false;
    config.crash_callback = true;
    config.is_need_create_msg = false;
    config.is_need_release_msg = false;
    register_dynamic_task(&uuid, HSM_TASK_NAME, &config);
#endif
}

void register_task_huk_srv(void)
{
#if (defined TEE_SUPPORT_HUK_SERVICE_32BIT || defined TEE_SUPPORT_HUK_SERVICE_64BIT)
    TEE_UUID uuid = TEE_SERVICE_HUK;
    struct srv_adaptor_config_t config = {0};
    config.agent_id = 0;
    config.task_prio = TASK_PRIO_HUK_SERVICE;
    config.is_need_release_ta_res = false;
    config.crash_callback = true;
    config.is_need_create_msg = false;
    config.is_need_release_msg = false;
    register_dynamic_task(&uuid, HUK_TASK_NAME, &config);
#endif
}

void register_task_rot_srv(void)
{
#ifdef TEE_SUPPORT_ROT
    TEE_UUID uuid = TEE_SERVICE_ROT;
    struct srv_adaptor_config_t config = {0};
    config.task_prio = TASK_PRIO_ROT_SERVICE;
    config.agent_id = 0;
    config.is_need_release_ta_res = false;
    config.crash_callback = true;
    config.is_need_create_msg = false;
    config.is_need_release_msg = false;
    register_dynamic_task(&uuid, ROT_TASK_NAME, &config);
#endif
}

void register_task_vltmm_srv(void)
{
#ifdef TEE_SUPPORT_VLTMM_SRV
    TEE_UUID uuid = TEE_SERVICE_VLTMM_SRV;
    struct srv_adaptor_config_t config = {0};
    config.task_prio = TASK_PRIO_VLTMM_SRV;
    config.agent_id = TEE_VLTMM_AGENT_ID;
    config.is_need_release_ta_res = false;
    config.crash_callback = false;
    config.is_need_create_msg = true;
    config.is_need_release_msg = true;

    register_dynamic_task(&uuid, VLTMMSRV_TASK_NAME, &config);
#endif
}

void register_task_crypto_agent_srv(void)
{
#ifdef TEE_SUPPORT_CRYPTO_AGENT
    TEE_UUID uuid = TEE_SERVICE_CRYPTOAGENT;
    struct srv_adaptor_config_t config = {0};
    config.task_prio = TASK_PRIO_CRYPTO_AGENT_SERVICE;
    config.agent_id = 0;
    config.is_need_release_ta_res = false;
    config.crash_callback = true;
    config.is_need_create_msg = false;
    config.is_need_release_msg = false;
    register_dynamic_task(&uuid, CRYPTO_AGENT_TASK_NAME, &config);
#endif
}

void register_multi_task(void)
{
    register_task_art_srv();
    register_task_bio_srv();
    register_task_hsm_srv();
    register_task_huk_srv();
    register_task_rot_srv();
    register_task_vltmm_srv();
    register_task_crypto_agent_srv();
}
