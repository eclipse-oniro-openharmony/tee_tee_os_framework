/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Safe time function setting
 * Create: 2020-02-04
 */
#include <errno.h>
#include <io_map_public.h>
#include <iomgr_ext.h>
#include <ipclib.h>
#include <ac.h>
#include <sys/hm_priorities.h>
#include <sys/hmapi_ext.h>
#include <libdrv_frame.h>
#include <procmgr_ext.h>
#include <tee_defines.h>
#include <tee_config.h>
#include <hmlog.h>
#include "platdrv_io_map.h"
#include "platdrv.h"
#include "ccmgr_hm.h"
#include "rand_update.h"

#include "drv_thread.h"
#include "platdrv_hash.h"
#ifdef TEE_SUPPORT_M_DRIVER
#include "vendor_syscall.h"
#include "secmem_core_api.h"
#endif

#ifdef ASCEND_SEC_ENABLE
#include "sec_api.h"
#endif

const char *g_debug_prefix = "platdrv";

static int32_t platdrv_map_io(void)
{
    uint32_t i;

    /* prepare io mmap */
    for (i = 0; i < ARRAY_SIZE(g_ioaddrs); i++) {
        if (g_ioaddrs[i].base == 0 || g_ioaddrs[i].size == 0)
            continue;

        void *ptr = hm_io_map(g_ioaddrs[i].base, (void *)(uintptr_t)g_ioaddrs[i].base, PROT_READ | PROT_WRITE);
        if (ptr != (void *)(uintptr_t)g_ioaddrs[i].base) {
            hm_error("failed to map register %u for driver\n", i);
            return -ENOMEM;
        }
    }

    for (i = 0; i < ARRAY_SIZE(g_ioaddrs_public); i++) {
        if (g_ioaddrs_public[i].base == 0 || g_ioaddrs_public[i].size == 0)
            continue;
        void *ptr = hm_io_map(g_ioaddrs_public[i].base, (void *)(uintptr_t)g_ioaddrs_public[i].base,
                              PROT_READ | PROT_WRITE);
        if (ptr != (void *)(uintptr_t)g_ioaddrs_public[i].base) {
            hm_error("failed to map public register %u for driver\n", i);
            return -ENOMEM;
        }
    }

    return 0;
}

static int32_t platdrv_framework_init(void)
{
    int32_t ret;

    ret = platdrv_map_io();
    if (ret != 0) {
        hm_error("platdrv :failed to map io: %d\n", ret);
        hm_exit(ret);
    }

    drv_hash_map();
    return 0;
}

/* each dependent driver has a white table for uuid-libname */
bool is_modload_perm_valid(const TEE_UUID *uuid, const char *name)
{
    const struct drvlib_load_caller_info *info_list = get_drvlib_load_caller_infos();
    const uint32_t nr = get_drvlib_load_caller_nums();
    uint32_t i;

    if (uuid == NULL || name == NULL) {
        hm_error("input params is invalid\n");
        return false;
    }

    hm_debug("uuid is 0x%x is calling %s\n", uuid->timeLow, name);
    for (i = 0; i < nr; i++) {
        if (memcmp(&info_list[i].uuid, uuid, sizeof(*uuid)) == 0 &&
            strcmp(info_list[i].name, name) == 0)
            return true;
    }

    return false;
}

#ifdef TEE_SUPPORT_M_DRIVER
void driver_module_init(void)
{
    int32_t ret;
    ret = module_control_init();
    if (ret != 0) {
        hm_error("module control init failed\n");
        hm_exit(ret);
    }
    secmem_core_init();
}
#else
void driver_module_init(void)
{
}
#endif

__attribute__((visibility("default"))) \
int32_t main(int32_t argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
    static dispatch_fn_t dispatch_fns[] = {
        [0] = single_thread_driver_dispatch,
        [HM_MSG_HEADER_CLASS_DRV_PWRMGR] = hm_platdrv_pm_dispatch,
        [HM_MSG_HEADER_CLASS_ACMGR_PUSH] = ac_dispatch,
#ifndef CRYPTO_MGR_SERVER_ENABLE
        [HM_MSG_HEADER_CLASS_UPDATE_RND] = rand_update,
#endif
    };

    struct drv_frame_t drv_frame = { "platdrv", true, platdrv_framework_init };
    cref_t ch = 0;

    int32_t ret = hm_register_drv_framework(&drv_frame, &ch, false);
    if (ret != 0) {
        hm_error("failed to register drv framework: %d\n", ret);
        hm_exit(ret);
    }

#ifndef CRYPTO_MGR_SERVER_ENABLE
    ret = hm_ipc_register_ch_path(RAND_DRV_PATH, ch);
    if (ret != 0) {
        hm_error("failed to register channel with name \"%s\":%d\n", RAND_DRV_PATH, ret);
        hm_exit(ret);
    }
#ifdef ASCEND_SEC_ENABLE
    ret = sec_init(SEC_FIRST_INIT);
    if (ret != 0)
        printf("platdrv : failed to init sec: %d\n", ret);
#endif
#endif

    ret = hmapi_set_priority(HM_PRIO_TEE_DRV);
    if (ret < 0) {
        hm_error("failed to set platdrv priority\n");
        hm_exit(ret);
    }

    driver_module_init();

    /* stack_size set 0 will use default size */
    ret = drv_thread_init("multidrv", 0, DRV_THREAD_MAX);
    if (ret != 0) {
        hm_error("drv thread init fail\n");
        hm_exit(ret);
    }

    hm_debug("%s: start server loop for channel 0x%llx\n", drv_frame.name, (long long)ch);
    cs_server_loop(ch, dispatch_fns, ARRAY_SIZE(dispatch_fns), NULL, NULL);

    return 0;
}
