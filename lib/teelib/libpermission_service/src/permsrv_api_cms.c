/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: permission service cms signature api
 * Create: 2022-04-01
 */
#include <mem_ops_ext.h>
#include "securec.h"
#include "tee_log.h"
#include "permsrv_api_cms.h"
#include "permsrv_api_imp.h"
#include "cms_signature_verify.h"

static TEE_UUID g_permsrv_uuid = TEE_SERVICE_PERM;

static TEE_Result fill_msg(perm_srv_req_msg_t *req_msg, perm_srv_reply_msg_t *rep_msg,
    const uint8_t *buffer, uint32_t size)
{
    if (memset_s(req_msg, sizeof(*req_msg), 0, sizeof(perm_srv_req_msg_t)) != 0)
        return TEE_ERROR_BAD_PARAMETERS;
    req_msg->header.send.msg_id = PERMSRV_CRL_UPDATE;
    req_msg->req_msg.crl_update_req.size = size;
    req_msg->req_msg.crl_update_req.buffer = (uint64_t)(uintptr_t)buffer;

    if (memset_s(rep_msg, sizeof(*rep_msg), 0, sizeof(perm_srv_reply_msg_t)) != 0)
        return TEE_ERROR_BAD_PARAMETERS;
    rep_msg->reply.ret = TEE_ERROR_GENERIC;

    return TEE_SUCCESS;
}

TEE_Result permsrv_crl_update(const uint8_t *buffer, uint32_t size)
{
    TEE_Result ret;
    void *copy_addr = NULL;
    perm_srv_req_msg_t req_msg;
    perm_srv_reply_msg_t rep_msg;

    if (buffer == NULL) {
        tloge("crl update failed, input param invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (size == 0 || size > DEVICE_CRL_MAX) {
        tloge("crl size %u invalid\n", size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    copy_addr = tee_alloc_sharemem_aux(&g_permsrv_uuid, size);
    if (copy_addr == NULL) {
        tloge("malloc crl fail\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memcpy_s(copy_addr, size, buffer, size) != 0) {
        tloge("copy crl fail\n");
        ret = TEE_ERROR_GENERIC;
        goto end;
    }

    ret = fill_msg(&req_msg, &rep_msg, copy_addr, size);
    if (ret != TEE_SUCCESS) {
        tloge("fill msg fail\n");
        goto end;
    }

    if (perm_srv_msg_call(PERMSRV_FILE_OPT, &req_msg, &rep_msg) < 0) {
        tloge("msg send fail\n");
        ret = TEE_ERROR_GENERIC;
        goto end;
    }

    ret = rep_msg.reply.ret;
end:
    (void)tee_free_sharemem(copy_addr, size);
    return ret;
}
