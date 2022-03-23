/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: REE INVOKE
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#include "invoke.h"
#include "invoke_check.h"
#include "tee_log.h"
#include "tee_ext_api.h"
#include "kms_key_node.h"
#include "crypto_operation.h"
#include "volatile_key.h"
#include "kms_key_storage.h"

typedef int32_t (*kms_invoke_fun)(TEE_Param params[CMD_PARAMS_LEN]);
typedef int32_t (*kms_invoke_fun_check)(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types);
struct shb_invoke_cmd {
    enum kms_cmd_id cmd_id;
    kms_invoke_fun cmd_proc_func;
    kms_invoke_fun_check cmd_check_func;
};

static struct shb_invoke_cmd g_kms_invoke_cmd[] = {
    { KMS_CMD_CREATE_KEY, kms_cmd_create_key, kms_cmd_iinn_check },
    { KMS_CMD_ENCRYPTO, kms_cmd_encrypto, kms_cmd_iiio_check },
    { KMS_CMD_ENCRYPTO_BEGIN, kms_cmd_begin, kms_cmd_begin_check },
    { KMS_CMD_ENCRYPTO_UPDATE, kms_cmd_update, kms_cmd_update_check },
    { KMS_CMD_ENCRYPTO_FINISH, kms_cmd_finish, kms_cmd_finish_check },
    { KMS_CMD_DECRYPTO, kms_cmd_decrypto, kms_cmd_iiio_check },
    { KMS_CMD_DECRYPTO_BEGIN, kms_cmd_begin, kms_cmd_begin_check },
    { KMS_CMD_DECRYPTO_UPDATE, kms_cmd_update, kms_cmd_update_check },
    { KMS_CMD_DECRYPTO_FINISH, kms_cmd_finish, kms_cmd_finish_check },
    { KMS_CMD_SIGN, kms_cmd_sign, kms_cmd_iiio_check },
    { KMS_CMD_SIGN_BEGIN, kms_cmd_begin, kms_cmd_begin_check },
    { KMS_CMD_SIGN_UPDATE, kms_cmd_update, kms_cmd_update_check },
    { KMS_CMD_SIGN_FINISH, kms_cmd_finish, kms_cmd_finish_check },
    { KMS_CMD_VERIFY, kms_cmd_verify, kms_cmd_iiii_check },
    { KMS_CMD_VERIFY_BEGIN, kms_cmd_begin, kms_cmd_begin_check },
    { KMS_CMD_VERIFY_UPDATE, kms_cmd_update, kms_cmd_update_check },
    { KMS_CMD_VERIFY_FINISH, kms_cmd_finish, kms_cmd_finish_check },
    { KMS_CMD_IMPORT_KEY, kms_cmd_import_key, kms_cmd_iiin_check },
    { KMS_CMD_UPDATE_KEY, NULL, NULL },
    { KMS_CMD_UPDATE_KEY_ID, NULL, NULL },
    { KMS_CMD_DELETE_KEY, kms_cmd_delete_key, kms_cmd_iinn_check },
    { KMS_CMD_EXPORT_KEY, kms_cmd_export_key, kms_cmd_iion_check },
    { KMS_CMD_MAC_GENERATE, kms_cmd_mac_generate, kms_cmd_iiio_check },
    { KMS_CMD_MAC_GENERATE_BEGIN, kms_cmd_begin, kms_cmd_begin_check },
    { KMS_CMD_MAC_GENERATE_UPDATE, kms_cmd_update, kms_cmd_update_check },
    { KMS_CMD_MAC_GENERATE_FINISH, kms_cmd_finish, kms_cmd_finish_check },
    { KMS_CMD_DIGEST, kms_cmd_digest, kms_cmd_iion_check },
    { KMS_CMD_DIGEST_BEGIN, kms_cmd_begin, kms_cmd_begin_check },
    { KMS_CMD_DIGEST_UPDATE, kms_cmd_update, kms_cmd_update_check },
    { KMS_CMD_DIGEST_FINISH, kms_cmd_finish, kms_cmd_finish_check },
    { KMS_CMD_RANDOM, kms_cmd_random, kms_cmd_random_check },
    { KMS_CMD_ABORT, kms_cmd_abort, kms_cmd_abort_check },
    { KMS_CMD_GET_META, kms_cmd_getmeta, kms_cmd_iion_check },
    { KMS_CMD_DERIVE_KEY, kms_cmd_kdf, kms_cmd_iiin_check },
};

__attribute__((visibility("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;
#ifdef DEF_ENG
#define TEST_CA_PATH "/vendor/bin/teec_hello"
    ret = AddCaller_CA_exec(TEST_CA_PATH, 0);
    if (ret != TEE_SUCCESS) {
        tloge("add teec_hello ca error\n");
        return ret;
    }
#endif
#define SECMGR_PATH "/usr/bin/mdc/base-plat/secmgr/secmgr"
    ret = AddCaller_CA_exec(SECMGR_PATH, SECMGR_UID);
    if (ret != TEE_SUCCESS) {
        tloge("add secmgr ca fail, ret = 0x%x\n", ret);
        return ret;
    }
    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS) {
        tloge("add ta caller fail, ret = 0x%x\n", ret);
        return ret;
    }
    ret = key_node_init();
    if (ret != TEE_SUCCESS) {
        tloge("key node init fail\n");
        return ret;
    }
    ret = vkey_list_init();
    if (ret != TEE_SUCCESS) {
        tloge("vkey list init fail\n");
        return ret;
    }
    return ret;
}

__attribute__((visibility("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
    TEE_Param params[CMD_PARAMS_LEN], void **session_context)
{
    (void)session_context;
    if (TEE_PARAM_TYPE_GET(param_types, INDEX_0) == TEE_PARAM_TYPE_MEMREF_INOUT) {
        struct kms_buffer_data in_key = { 0, NULL };
        in_key.buffer = params[INDEX_0].memref.buffer;
        in_key.length = params[INDEX_0].memref.size;
        if (kms_access_key(&in_key) != TEE_SUCCESS)
            params[INDEX_0].memref.size = 0;
    }
    tlogd("---- TA_OpenSessionEntryPoint -------- \n");
    return TEE_SUCCESS;
}

static void clear_context_while_final_fail(uint32_t cmd_id, uint32_t param_types,
    const TEE_Param params[CMD_PARAMS_LEN])
{
    uint32_t finish_cmds[] = { KMS_CMD_ENCRYPTO_FINISH, KMS_CMD_DECRYPTO_FINISH, KMS_CMD_SIGN_FINISH,
        KMS_CMD_VERIFY_FINISH, KMS_CMD_MAC_GENERATE_FINISH, KMS_CMD_DIGEST_FINISH };
    uint32_t index = 0;
    for (; index < sizeof(finish_cmds) / sizeof(finish_cmds[0]); index++) {
        if (cmd_id == finish_cmds[index])
            break;
    }
    uint32_t op_handle_index = INDEX_0;
    if (index < sizeof(finish_cmds) / sizeof(finish_cmds[0]))
        op_handle_index = INDEX_1;
    else if (cmd_id == KMS_CMD_ABORT)
        op_handle_index = INDEX_0;
    else
        return;

    bool check = (params != NULL && TEE_PARAM_TYPE_GET(param_types, op_handle_index) == TEE_PARAM_TYPE_MEMREF_INPUT &&
        params[op_handle_index].memref.buffer != NULL && params[op_handle_index].memref.size == sizeof(uint64_t));
    if (check) {
        struct kms_buffer_data op_handle = {
            params[op_handle_index].memref.size, params[op_handle_index].memref.buffer
        };
        TEE_Result ret = kms_abort(&op_handle);
        if (ret != TEE_SUCCESS)
            tloge("try to clear context failed while the last operation fail, ret = %d\n", ret);
    }
    return;
}

__attribute__((visibility("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *session_context,
    uint32_t cmd_id, uint32_t param_types, TEE_Param params[CMD_PARAMS_LEN])
{
    int32_t ret;
    (void)session_context;
    tlogd("*******************run cmd %u start******************************\n", cmd_id);
#ifdef DEF_ENG
    get_memusage();
#endif
    ret = (int32_t)permission_check(cmd_id);
    if ((TEE_Result)ret != TEE_SUCCESS) {
        tloge("permission denied, ret = 0x%x\n", ret);
        return (TEE_Result)ret;
    }
    size_t index = 0;
    size_t cmd_size = sizeof(g_kms_invoke_cmd) / sizeof(g_kms_invoke_cmd[0]);
    for (; index < cmd_size; index++) {
        if (cmd_id == g_kms_invoke_cmd[index].cmd_id)
            break;
    }

    if (index == cmd_size || g_kms_invoke_cmd[index].cmd_check_func == NULL ||
        g_kms_invoke_cmd[index].cmd_proc_func == NULL) {
        tloge("unsupport cmd %u\n", cmd_id);
        ret = TEE_ERROR_BAD_PARAMETERS;
    } else {
        ret = g_kms_invoke_cmd[index].cmd_check_func(params, param_types);
        if (ret != TEE_SUCCESS) {
            tloge("cmd %u, input check fail\n", cmd_id);
            clear_context_while_final_fail(cmd_id, param_types, params);
            return (TEE_Result)ret;
        }
        ret = g_kms_invoke_cmd[index].cmd_proc_func(params);
    }
#ifdef DEF_ENG
    get_memusage();
#endif
    tlogd("*******************run cmd %u end return = 0x%x******************************\n", cmd_id, ret);
    return (TEE_Result)ret;
}

__attribute__((visibility("default"))) void TA_CloseSessionEntryPoint(void *session_context)
{
    (void)session_context;
    tlogd("---- Close Session Entry Point ----- \n");
}
__attribute__((visibility("default"))) void TA_DestroyEntryPoint(void)
{
    destroy_node_list_lock();
    destroy_vkey_list_lock();
    tlogd("destroy kms entrypoint\n");
}
