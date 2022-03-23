/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: Secure element manager in Secure OS.
 * Author: Lu Xiangyu <luxiangyu@huawei.com>
 * Create: 2017-08-12
 * History: 2019-08-20 He Muyang h00512727 CSEC rectification
 */
#include "tee_ext_api.h"
#include "tee_log.h"
#include "sre_syscalls_ext.h"
#include "sre_syscall.h"
#include "tee_private_api.h"

#include "ukey_ta_data.h"

#define CMD_SE_ESE_TRANSMIT     0x00000008
#define CMD_SE_ESE_READ         0x00000009
#define CMD_SE_SET_DEACTIVEFLAG 0x00000010
#define CMD_UKEY_SET_SWITCH     0x00000040
#define CMD_UKEY_GET_SWITCH     0x00000041

#define SYSTEM_SERVER_PKGNAME "system_server"
#define SYSTEM_SERVER_UUID    1000U

#define SE_OPEN_SESSION_PERMISSION 0x01
#define BYTE_BITS                  8
#define TEE_PARAM_MAX              4U

static TEE_UUID g_cur_ta_uuid;
typedef TEE_Result (*cmd_func)(uint32_t param_types,
                               TEE_Param params[], uint32_t params_size);

struct cmd_check_config_s {
    uint32_t cmd_id;
    cmd_func check_func;
};

typedef struct {
    char *packagename;
    char *modulus;
    char *public_exponent;
} login_apk;

static login_apk g_se_service[] = {
    {
        "com.huawei.hwpanpayservice",
        "a5a7fca53b3e7a551c94bdc8cddc9e6eebb8dddb724cff1d823b4"
        "50c710a84373b07fb03aa2238283e80702b5d444d91995ac2ecd9"
        "4f34e464de7c767a2003aa1228ae413eed80133b9aba8ba2a75f1"
        "573af1bc1baa2b5310096ae5f37717dbd3b126b30b16d43fc100a"
        "1406b3e366ae4a3e153f044673e229988d9ba94e3590427fe4ce8"
        "a0b3b96e7f521996cf112a5834a71c4613bb90bf4adf841708882"
        "505898f6e0299785f5aa6b21007f5fd493b78720271b76c6c7100"
        "33b85b9fa1d73039b4f0d433f9f151e9cdede1077f9a152ce50b4"
        "54259aee126ba03f107c6eee12a4831052f1e9c7a777a38d14d45"
        "8fe9558828fb97c77b3dcf243a2d45f71b7",
        "010001"
    },
    {
        "com.huawei.hwpanpayservice",
        "c6e4ff09588156bac87e35494332ca76051b44533d6da878b7480"
        "fa283420015e54f301430dbc506489d317e442dfc498be134b953"
        "13642d44653f58de4862fb49b69246fa631ea0a95e70005e311be"
        "b66b49df92a7ec049a0a85642c16945be6293d25309d018d516c2"
        "9d51d23c0e6c6f08ad50cb9dc690d4629663e03a3c7f5a997bdc8"
        "9fe21091168faf353ecd3bf8839587c79ee2b8671ca425feb8ea3"
        "f4f5243db630bfb8d90573631bfd4714aa0a215021408c0f14590"
        "ef2751649f770bc5327bb2ac216520f029e4d4e762a85dc87f3fb"
        "de3e12aae4da9e8dbbca46a98e9e9263b49b5bda99409073cb04d"
        "8bfcc16fe405ee341f2bb91d948900cc20b98181072dc5331a971"
        "c75b335679362276efac9f8e26e89d904b3afcb4ac341d51441b9"
        "4b470aac340e7e0f1b69b6b6feacb179b5d0f36296629b7ccee3e"
        "278542750d597345b7fefde7f50225bbe6d50c1e4c6a28547b7bb"
        "d218554f8594673bf976e5a1567b9f4ab7612888bdeabd51d1dc9"
        "a0076a5684a251ae784dfbb9bf",
        "010001"
    },
};

static TEE_Result release_ta_connect(void)
{
    TEE_Result ret;
    caller_info caller_data_buf = {0};

    ret = TEE_EXT_GetCallerInfo(&caller_data_buf, sizeof(caller_data_buf));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get caller info ret is 0x%x\n", ret);
        return ret;
    }

    if (caller_data_buf.session_type == SESSION_FROM_CA) {
        tlogd("Session call come from CA\n");
        return TEE_SUCCESS;
    } else if (caller_data_buf.session_type == SESSION_FROM_TA) {
        tlogd("Session call come from TA\n");
        return TEE_SUCCESS;
    } else {
        tloge("Session type invalid is %u, just return\n", caller_data_buf.session_type);
        return TEE_ERROR_GENERIC;
    }
}

static TEE_Result sem_check_permission(const TEE_UUID *uuid)
{
    uint64_t capability = 0;

    if (TEE_EXT_GetSeCapability(uuid, &capability) == TEE_SUCCESS) {
        if ((capability & SE_OPEN_SESSION_PERMISSION) != 0)
            return TEE_SUCCESS;
    }

    return TEE_ERROR_ACCESS_DENIED;
}

static TEE_Result check_ta_permission()
{
    TEE_Result ret;
    caller_info caller_data_buf = {0};

    ret = TEE_EXT_GetCallerInfo(&caller_data_buf, sizeof(caller_data_buf));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get caller info ret is 0x%x\n", ret);
        return ret;
    }

    if (caller_data_buf.session_type == SESSION_FROM_CA) {
        tlogd("Session call come from CA\n");
        return TEE_SUCCESS;
    } else if (caller_data_buf.session_type == SESSION_FROM_TA) {
        tlogd("Session call come from TA\n");
        ret = sem_check_permission(&caller_data_buf.caller_identity.caller_uuid);
        if (ret != TEE_SUCCESS) {
            tloge("TA has not enough permission is 0x%x\n", ret);
            return ret;
        }
        g_cur_ta_uuid = caller_data_buf.caller_identity.caller_uuid;
        return TEE_SUCCESS;
    } else {
        tloge("Session type invalid is %u, just return\n", caller_data_buf.session_type);
        return TEE_ERROR_GENERIC;
    }
}

static TEE_Result se_set_deactiveflag(uint32_t param_types,
                                      TEE_Param params[], uint32_t params_size)
{
    TEE_Result ret;

    if ((params_size != TEE_PARAM_MAX) ||
        (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("Bad expected parameter types for se set deactiveflag\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tlogd("start to set se deactive flag\n");
    ret = set_se_deactive_flag((int)params[0].value.a);
    if (ret != TEE_SUCCESS)
        tloge("set deactive flag value failed:0x%x\n", ret);

    return ret;
}

static TEE_Result ukey_get_switch(uint32_t param_types,
                                  TEE_Param params[], uint32_t params_size)
{
    TEE_Result ret;

    if (params_size != TEE_PARAM_MAX) {
        tloge("Bad expected parameter types for se get ese type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_switch_impl(param_types, params);
    if (ret != TEE_SUCCESS)
        tloge("ta cmd get switch failed:0x%x\n", ret);

    return ret;
}

static TEE_Result ukey_set_switch(uint32_t param_types,
                                  TEE_Param params[], uint32_t params_size)
{
    TEE_Result ret;

    if (params_size != TEE_PARAM_MAX) {
        tloge("Bad expected parameter types for se get ese type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = set_switch_impl(param_types, params);
    if (ret != TEE_SUCCESS)
        tloge("ta cmd set switch failed:0x%x\n", ret);

    return ret;
}

static TEE_Result se_ese_transmit(uint32_t param_types,
                                  TEE_Param params[], uint32_t params_size)
{
    TEE_Result ret;

    if ((params_size != TEE_PARAM_MAX) ||
        (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (params[0].memref.buffer == NULL) || (params[0].memref.size == 0)) {
        tloge("ese transmit data Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = (TEE_Result)__ese_transmit_data(params[0].memref.buffer,
                                          params[0].memref.size);
    if (ret != TEE_SUCCESS)
        tloge("ese transmit data 0x%x\n", ret);

    return ret;
}

static TEE_Result se_ese_read(uint32_t param_types,
                              TEE_Param params[], uint32_t params_size)
{
    TEE_Result ret;

    if ((params_size != TEE_PARAM_MAX) ||
        (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
        (params[0].memref.buffer == NULL)) {
        tloge("ese read data Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = (TEE_Result)__ese_read_data(params[0].memref.buffer, params[0].memref.size);
    if (ret != TEE_SUCCESS)
        tloge("ese read data 0x%x\n", ret);

    return ret;
}

/*
 * -----------------------------------------------------------------------------------------------
 * APIs under the line are defined by Global Platform, need to follow Global Platform code style
 * don't change function name / return value type / parameters types / parameters names
 * -----------------------------------------------------------------------------------------------
 */
__attribute__((visibility("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    tlogd("Start create sem ta\n");

    if (AddCaller_TA_all() == TEE_SUCCESS) {
        tlogd("TA create entry point: Add caller TA all success\n");
    } else {
        tloge("TA create entry point: Add caller TA all failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (AddCaller_CA_exec(SYSTEM_SERVER_PKGNAME, SYSTEM_SERVER_UUID) != TEE_SUCCESS) {
        tloge("TA create entry point: Add caller CA exec failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (AddCaller_CA_apk(g_se_service[0].packagename,
                         g_se_service[0].modulus, g_se_service[0].public_exponent) != TEE_SUCCESS) {
        tloge("TA_CreateEntryPoint: AddCaller_CA_apk failed.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (AddCaller_CA_apk(g_se_service[1].packagename,
                         g_se_service[1].modulus, g_se_service[1].public_exponent) != TEE_SUCCESS) {
        tloge("TA_CreateEntryPoint: AddCaller_CA_apk failed.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = data_init();
    // under recovery factory model, it can not access security storage, so just put error log and not return fail.
    if (ret != TEE_SUCCESS)
        tloge("data init failed!");

    tlogd("End create sem ta\n");
    return TEE_SUCCESS;
}

__attribute__((visibility("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
    TEE_Param params[TEE_PARAM_MAX], void **session_context)
{
    TEE_Result ret;

    S_VAR_NOT_USED(session_context);
    S_VAR_NOT_USED(param_types);
    S_VAR_NOT_USED(params);

    tlogd("Start sem ta open session\n");
    ret = check_ta_permission();
    if (ret != TEE_SUCCESS) {
        tloge("TA has not enough permission\n");
        return ret;
    }
    tlogd("End sem ta open session\n");

    return ret;
}

static const struct cmd_check_config_s g_cmd_check_config[] = {
    { CMD_SE_SET_DEACTIVEFLAG, se_set_deactiveflag },
    { CMD_UKEY_GET_SWITCH,     ukey_get_switch },
    { CMD_UKEY_SET_SWITCH,     ukey_set_switch },
    { CMD_SE_ESE_TRANSMIT,     se_ese_transmit },
    { CMD_SE_ESE_READ,         se_ese_read },
};
#define CMD_COUNT (sizeof(g_cmd_check_config) / sizeof(g_cmd_check_config[0]))

__attribute__((visibility("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *session_context,
    uint32_t cmd_id, uint32_t param_types, TEE_Param params[TEE_PARAM_MAX])
{
    TEE_Result ret;
    size_t i;

    tlogd("Start sem ta invoke command\n");
    S_VAR_NOT_USED(session_context);

    if (params == NULL) {
        tloge("params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    for (i = 0; i < CMD_COUNT; i++) {
        if ((cmd_id == g_cmd_check_config[i].cmd_id) && (g_cmd_check_config[i].check_func != NULL)) {
            ret = g_cmd_check_config[i].check_func(param_types, params, TEE_PARAM_MAX);
            tlogd("End sem ta invoke command\n");
            return ret;
        }
    }

    tloge("Invalid cmd:%u\n", cmd_id);
    return TEE_ERROR_GENERIC;
}

__attribute__((visibility("default"))) void TA_CloseSessionEntryPoint(void *session_context)
{
    TEE_Result ret;

    S_VAR_NOT_USED(session_context);

    ret = release_ta_connect();
    if (ret != TEE_SUCCESS)
        tlogd("Failed to close session ret is 0x%x\n", ret);
    else
        tlogd("Close session call\n");
}

__attribute__((visibility("default"))) void TA_DestroyEntryPoint(void)
{
    data_destroy();

    tlogd("Destroy entry point call\n");
}
