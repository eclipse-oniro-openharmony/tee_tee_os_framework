/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: permission service cert api
 * Create: 2022-04-01
 */
#include <mem_ops_ext.h>
#include "securec.h"
#include "tee_log.h"
#include "permsrv_api_imp.h"
#include "permsrv_api_cert.h"

static TEE_UUID g_permsrv_uuid = TEE_SERVICE_PERM;

TEE_Result ta_signing_cert_import(const char *cert_buf, uint32_t cert_size, const char *pub_key_buf, uint32_t pub_size)
{
    TEE_Result ret;

    if (cert_buf == NULL || cert_size == 0 || pub_key_buf == NULL || pub_size == 0) {
        tloge("TEE_EXT_cert_verfiy param error!\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        return ret;
    }

    ret = tee_cert_import((uint8_t *)cert_buf, cert_size, (uint8_t *)pub_key_buf, pub_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to do crl cert process\n");
        return ret;
    }

    tlogd("cert import finished, ret: %d", ret);
    return TEE_SUCCESS;
}

TEE_Result ta_signing_cert_export(uint8_t *dst, uint32_t *len, uint32_t limit)
{
    if (dst == NULL || len == NULL) {
        tloge("crt export file is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return permsrv_crt_export(dst, len, limit);
}

TEE_Result ta_signing_cert_destroy(void)
{
    return permsrv_crt_remove();
}

#define MAX_CERT_LEN 2048
#define MAX_PUBKEY_LEN 1024
TEE_Result tee_cert_import(const uint8_t *cert_buf, uint32_t cert_size, const uint8_t *pub_key, uint32_t pub_key_size)
{
    perm_srv_req_msg_t req_msg;
    perm_srv_reply_msg_t reply_msg;

    uint8_t *cert_shared = NULL;
    uint8_t *pub_key_shared = NULL;

    tee_perm_init_msg(&req_msg, &reply_msg);
    TEE_Result ret = TEE_ERROR_GENERIC;

    if (cert_buf == NULL || pub_key == NULL || cert_size == 0 || pub_key_size == 0 ||
        cert_size > MAX_CERT_LEN || pub_key_size > MAX_PUBKEY_LEN) {
        tloge("bad parameter for points and size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cert_shared = tee_alloc_sharemem_aux(&g_permsrv_uuid, cert_size);
    pub_key_shared = tee_alloc_sharemem_aux(&g_permsrv_uuid, pub_key_size);
    if (cert_shared == NULL || pub_key_shared == NULL) {
        tloge("malloc sharedBuff failed, size=0x%x\n", cert_size);
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    if (memcpy_s(cert_shared, cert_size, cert_buf, cert_size) != EOK) {
        tloge("copy the conf error");
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    if (memcpy_s(pub_key_shared, pub_key_size, pub_key, pub_key_size) != EOK) {
        tloge("copy the pub key shared failed");
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    req_msg.header.send.msg_id           = CERT_VERIFY_CMD;
    req_msg.req_msg.ta_cert.ta_cert_buff = (uintptr_t)cert_shared;
    req_msg.req_msg.ta_cert.ta_cert_size = cert_size;
    req_msg.req_msg.ta_cert.pub_key_buff = (uintptr_t)pub_key_shared;
    req_msg.req_msg.ta_cert.pub_key_size = pub_key_size;
    reply_msg.reply.ret                  = TEE_ERROR_GENERIC;

    ret = rslot_file_msg_call(&req_msg, &reply_msg);
    if (ret != TEE_SUCCESS) {
        ret = reply_msg.reply.ret;
        goto clean;
    }
clean:
    if (cert_shared != NULL)
        (void)tee_free_sharemem(cert_shared, cert_size);
    if (pub_key_shared != NULL)
        (void)tee_free_sharemem(pub_key_shared, pub_key_size);
    return ret;
}

TEE_Result permsrv_crt_export(uint8_t *dst, uint32_t *len, uint32_t limit)
{
    TEE_Result ret = TEE_SUCCESS;
    /* initialize request and reply */
    perm_srv_req_msg_t req;
    perm_srv_reply_msg_t rep;
    tee_perm_init_msg(&req, &rep);
    /* allocate shared memory */
    uint8_t *shared_mm = tee_alloc_sharemem_aux(&g_permsrv_uuid, limit);
    if (shared_mm == NULL) {
        ret = TEE_ERROR_OUT_OF_MEMORY;
        tloge("tee alloc share mem failed");
        return ret;
    }
    /* padding request parameters */
    req.header.send.msg_id = PERMSRV_CRT_EXPORT;
    req.req_msg.crt.dst = (uint64_t)(uintptr_t)shared_mm;
    req.req_msg.crt.len = limit;

    /* send request */
    if (perm_srv_msg_call(PERMSRV_FILE_OPT, &req, &rep) < 0) {
        tloge("msg call failed");
        ret = rep.reply.ret;
        (void)tee_free_sharemem(shared_mm, limit);
        return ret;
    }

    /* copy from shared memory */
    *len = rep.reply.permsrsp.crt.len;
    if (memcpy_s(dst, limit, shared_mm, *len) != 0) {
        tloge("copy dst to shared mem failed");
        ret = TEE_ERROR_GENERIC;
        (void)tee_free_sharemem(shared_mm, limit);
    }
    return ret;
}

TEE_Result permsrv_crt_remove(void)
{
    TEE_Result ret = TEE_SUCCESS;
    /* initialize request and reply */
    perm_srv_req_msg_t req;
    perm_srv_reply_msg_t rep;
    tee_perm_init_msg(&req, &rep);
    /* padding request parameters */
    req.header.send.msg_id = PERMSRV_CRT_REMOVE;
    /* send request */
    if (perm_srv_msg_call(PERMSRV_FILE_OPT, &req, &rep) < 0) {
        ret = rep.reply.ret;
        tloge("message call failed");
    }
    return ret;
}