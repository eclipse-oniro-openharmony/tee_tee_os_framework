/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: TEE huk srv msg call API.
 * Create: 2022-04-01
 */
#include <errno.h>
#include <ipclib.h>
#include <securec.h>
#include <sys/usrsyscall_ext.h>
#include <pthread.h>
#include <tee_log.h>
#include <tee_ext_api.h>
#include "huk_service_msg_call.h"

static pthread_mutex_t g_msg_call_mutex = PTHREAD_ROBUST_MUTEX_INITIALIZER;
int32_t huk_srv_msg_call(struct huk_srv_msg *msg, struct huk_srv_rsp *rsp)
{
    errno_t rc;
    cref_t rslot = 0;

    if (msg == NULL || rsp == NULL) {
        tloge("msg or rsp is NULL\n");
        return -1;
    }

    if (pthread_mutex_lock(&g_msg_call_mutex) != 0) {
        tloge("huk msg call mutex lock failed\n");
        return -1;
    }
    rc = hm_ipc_get_ch_from_path(HUK_PATH, &rslot);
    if (rc == -1) {
        tloge("huksrv: get channel from pathmgr failed\n");
        if (pthread_mutex_unlock(&g_msg_call_mutex) != 0)
            tloge("huk msg call mutex unlock failed\n");
        return rc;
    }

    rc = hm_msg_call(rslot, msg, sizeof(*msg), rsp, sizeof(*rsp), 0, -1);
    if (rc < 0)
        tloge("msg send 0x%llx failed: 0x%x\n", rslot, rc);

    (void)hm_ipc_release_path(HUK_PATH, rslot);
    if (pthread_mutex_unlock(&g_msg_call_mutex) != 0) {
        tloge("huk msg call mutex unlock failed\n");
        return -1;
    }
    return rc;
}

