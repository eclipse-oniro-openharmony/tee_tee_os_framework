/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: ssa embedded msg
 * Author: Lilianhui lilianhui1@huawei.com
 * Create: 2021-01-09
 */
#include "ssa_snd_msg.h"
#include <ipclib.h>
#include <sys/usrsyscall.h>
#include <tee_log.h>
#include <securec.h>

uint32_t send_msg_to_ssa(uint32_t cmd_id, const void *msg, uint32_t msg_szie)
{
    struct msg_st hm_msg = { 0 };
    cref_t rslot = 0;
    uint32_t ret;

    ret = (uint32_t)hm_ipc_get_ch_from_path(SSA_SERVICE_PATH, &rslot);
    if (ret != HM_OK) {
        tloge("get channel from pathmgr failed\n");
        return ret;
    }

    hm_msg.msg_id = cmd_id;
    if (memcpy_s(hm_msg.payload, sizeof(hm_msg.payload), msg, msg_szie) != HM_OK) {
        (void)hm_ipc_release_path(SSA_SERVICE_PATH, rslot);
        return HM_ERROR;
    }

    ret = (uint32_t)hm_msg_notification(rslot, &hm_msg, sizeof(hm_msg));
    if (ret != HM_OK)
        tloge("msg snd error %x\n", ret);

    (void)hm_ipc_release_path(SSA_SERVICE_PATH, rslot);
    return ret;
}
