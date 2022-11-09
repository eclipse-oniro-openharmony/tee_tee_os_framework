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
#include <stdio.h>
#include <inttypes.h>
#include <procmgr_ext.h>
#include <sys/hmapi_ext.h>
#include <sys/hm_priorities.h>
#include <sys/fileio.h>
#include <sys/usrsyscall_ext.h>
#include <ac.h>
#include <ipclib.h>
#include <libdrv_frame.h>
#include "drv_thread.h"
#include "drv_process_mgr.h"

const char *g_debug_prefix = "drvmgr";

int32_t drv_framework_init(const struct drv_frame_t *drv_frame)
{
    (void)drv_frame;
    return 0;
}

__attribute__((visibility("default"))) \
int32_t main(int32_t argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
    static dispatch_fn_t dispatch_fns[] = {
        [0] = driver_dispatch,
        [HM_MSG_HEADER_CLASS_ACMGR_PUSH] = ac_dispatch,
    };

    hm_info("drvmgr main begin\n");

    struct drv_frame_t drv_frame = { "drvmgr", true, NULL };

    cref_t ch = 0;

    int32_t ret = hm_register_drv_framework(&drv_frame, &ch, true);
    if (ret != 0) {
        hm_error("failed to register drv framework: 0x%x\n", ret);
        hm_exit(ret);
    }

    ret = fileio_init();
    if (ret != 0) {
        hm_error("file io init failed:0x%x\n", ret);
        hm_exit(ret);
    }

    ret = hmapi_set_priority(HM_PRIO_TEE_DRV);
    if (ret < 0) {
        hm_error("failed to set drv server priority\n");
        hm_exit(ret);
    }

    ret = create_spawn_sync_msg_info();
    if (ret < 0) {
        hm_error("create spawn channel fail\n");
        hm_exit(ret);
    }

    (void)register_base_drv_node();

    /* stack_size set 0 will use default size */
    ret = drv_thread_init("drvmgr_multi", 0, DRV_THREAD_MAX);
    if (ret != 0) {
        hm_error("drv thread init fail\n");
        hm_exit(ret);
    }
    hm_info("%s: start server loop\n", drv_frame.name);
    cs_server_loop(ch, dispatch_fns, ARRAY_SIZE(dispatch_fns), NULL, NULL);

    return 0;
}
