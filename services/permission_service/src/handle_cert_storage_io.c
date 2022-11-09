/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "handle_cert_storage_io.h"
#include "handle_file_op.h"
#include <securec.h>
#include <tee_log.h>
#include <msg_ops.h>
#include <ta_framework.h>
#include <target_type.h>
#include <sys/usrsyscall.h>
#include <ipclib.h>
#include "handle_config.h"
#include "register_ssa_perm.h"
#include "permission_service.h"

#ifdef DYN_IMPORT_CERT

#define IMPORTED_CRT_FILE_PATH "imported_crt.der";

struct cert_cache_s {
    uint8_t data[MAX_CRT_LEN];
    int32_t len;
    bool is_valid;
};

/* cache for storage reading */
static struct cert_cache_s g_cert_cache = {
    .data = { 0 },
    .len = 0,
    .is_valid = false
};

static const char *get_crt_path(void)
{
    return IMPORTED_CRT_FILE_PATH;
}

static TEE_Result get_self_pid(uint32_t *self_pid)
{
    *self_pid = get_selfpid();
    if (*self_pid == SRE_PID_ERR) {
        tloge("get self pid error\n");
        return TEE_ERROR_SECURITY;
    }
    return TEE_SUCCESS;
}

#endif

/*
 * Description: export certification from ssa
 * dst: points to the output buffer which holds the content of certification
 * len: points to the output buffer which holds the length of certification
 * limit: size of avaliable space of buffer pointed by dst
 * return: TEE_SUCCESS if success and others otherwise
 */
TEE_Result export_cert_from_storage(uint8_t *dst, uint32_t *len, uint32_t limit)
{
#ifdef DYN_IMPORT_CERT
    uint32_t self_pid;
    if (get_self_pid(&self_pid) != TEE_SUCCESS)
        return TEE_ERROR_SECURITY;
    register_self_to_ssa(self_pid, TEE_TASK_REGISTER_TA);
    hm_yield();

    if (!g_cert_cache.is_valid) {
        /* get public key from ssa */
        const char *crt_path = get_crt_path();
        g_cert_cache.len = perm_srv_file_read(crt_path, g_cert_cache.data,
                                              sizeof(g_cert_cache.data) / sizeof(uint8_t));
        if (g_cert_cache.len < 0) {
            tloge("Failed to read file");
            goto err;
        }
        g_cert_cache.is_valid = true;
    }

    /* copy from g_cert_cache */
    if (memcpy_s(dst, limit, g_cert_cache.data, g_cert_cache.len) != EOK) {
        tloge("copy from cert cache failed");
        goto err;
    }
    *len = g_cert_cache.len;
    register_self_to_ssa(self_pid, TEE_TASK_UNREGISTER_TA);
    return TEE_SUCCESS;
err:
    register_self_to_ssa(self_pid, TEE_TASK_UNREGISTER_TA);
    return TEE_ERROR_SECURITY;
#else
    (void)dst;
    (void)len;
    (void)limit;
    return TEE_SUCCESS;
#endif
}

/*
 * Description: import certification to ssa
 * src: points to the source buffer of the certification
 * len: length of the source buffer
 * return: TEE_SUCCESS if success and others otherwise
 */
TEE_Result import_cert_to_storage(uint8_t *src, size_t len)
{
#ifdef DYN_IMPORT_CERT
    uint32_t self_pid;
    if (get_self_pid(&self_pid) != TEE_SUCCESS)
        return TEE_ERROR_SECURITY;
    register_self_to_ssa(self_pid, TEE_TASK_REGISTER_TA);
    hm_yield();

    const char *crt_path = get_crt_path();
    if (perm_srv_file_write(crt_path, src, len) != 0) {
        tloge("Write certification to ssa failed");
        register_self_to_ssa(self_pid, TEE_TASK_UNREGISTER_TA);
        return TEE_ERROR_STORAGE_EIO;
    }
    g_cert_cache.is_valid = false;
    register_self_to_ssa(self_pid, TEE_TASK_UNREGISTER_TA);
    return TEE_SUCCESS;
#else
    (void)src;
    (void)len;
    return TEE_SUCCESS;
#endif
}

/*
 * Description: remove certification on ssa
 * return: TEE_SUCCESS if success and others otherwise
 */
TEE_Result remove_cert_from_storage(void)
{
#ifdef DYN_IMPORT_CERT
    uint32_t self_pid;
    if (get_self_pid(&self_pid) != TEE_SUCCESS)
        return TEE_ERROR_SECURITY;
    register_self_to_ssa(self_pid, TEE_TASK_REGISTER_TA);
    hm_yield();

    g_cert_cache.is_valid = false;
    const char *crt_path = get_crt_path();

    /* check the return value in the next function */
    int32_t ret = perm_srv_file_remove(crt_path);
    register_self_to_ssa(self_pid, TEE_TASK_UNREGISTER_TA);
    return ret;
#else
    return TEE_SUCCESS;
#endif
}

