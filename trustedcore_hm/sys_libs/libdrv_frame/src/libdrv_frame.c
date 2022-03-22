/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: drv frame function setting
 * Create: 2020-04-15
 */
#include "libdrv_frame.h"
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <hm_unistd.h>
#include <mmgrapi.h>
#include <procmgr_ext.h>
#include <pathmgr_ext.h>
#include <ipclib.h>
#include <sys/kuapi.h>
#include <sys/hmapi_ext.h>
#include <sys/usrsyscall_ext.h>
#include <sys/usrsyscall_new_ext.h>
#include <sys/fileio.h>
#include <timer.h>
#include <irqmgr.h>
#include <irqmgr_api_ext.h>
#include <tamgr_ext.h>
#include <ac.h>
#include <ta_permission.h>
#include <tee_tag.h>
#include <tee_drv_internal.h>
#include "tc_drv.h"

static cref_t g_teesmc_hdlr;
static rref_t g_sysctrl_ref;

#define IPC_CHANNEL_NUM 2

cref_t get_teesmc_hdlr(void)
{
    return g_teesmc_hdlr;
}

cref_t get_sysctrl_hdlr(void)
{
    return g_sysctrl_ref;
}

static int32_t ipc_init(const char *name, cref_t *ch)
{
    int32_t ret;
    struct reg_items_st reg_items = { true, false, false };

    ret = hm_create_multi_ipc_channel(NULL, IPC_CHANNEL_NUM, NULL, reg_items);
    if (ret != 0) {
        printf("%s: failed to create SRE channel with pid %d: %d\n", name, hm_getpid(), ret);
        return -1;
    }

    ret = hm_create_ipc_native(name, ch);
    if (ret != 0) {
        printf("%s: failed to create channel :%d\n", name, ret);
        return -1;
    }

#ifndef CONFIG_TIMER_DISABLE
    ret = hm_timer_init();
    if (ret != 0) {
        printf("%s :failed to init hm timer: %d\n", name, ret);
        return -1;
    }
#endif

    return 0;
}

static void print_drv_info(const char *name)
{
    printf(" _______________________________________________________\n");
    printf("|  _____________________________________________________\n");
    printf("| |\n");
    printf("| |  %s init - pid %d\n", name, hm_getpid());
    printf("| |_____________________________________________________\n");
    printf("|_______________________________________________________\n");
}

static int32_t system_init(const char *name, bool new_frame)
{
    int32_t ret;

    set_log_use_tid_flag();

    ret = ac_init(hmapi_cnode_cref(), __sysmgrch, name);
    if (ret != 0) {
        printf("%s: libac initialization failed\n", name);
        return -1;
    }

    ret = hm_tamgr_register(name);
    if (ret != 0) {
        printf("%s: tamgr registration for platdrv failed\n", name);
        return -1;
    }

    if (!new_frame) {
        g_sysctrl_ref = irqmgr_acquire_sysctrl_local_irq_hdlr();
        if (is_ref_err(g_sysctrl_ref) != 0) {
            printf("%s: get sysctrl ref error %s\n", name, hmapi_strerror(ref_to_err(g_sysctrl_ref)));
            return -1;
        }
    }

    g_teesmc_hdlr = irqmgr_acquire_teesmc_hdlr();
    if (is_ref_err(g_teesmc_hdlr) != 0) {
        printf("%s: get teesmc hdlr error %s\n", name, hmapi_strerror(ref_to_err(g_teesmc_hdlr)));
        return -1;
    }

    ret = ta_permission_init();
    if (ret != 0) {
        hm_error("failed to init ta permission\n");
        return -1;
    }

    return 0;
}

static int32_t hwi_context_init(const struct drv_frame_t *drv_frame)
{
    cref_t hwi_ch = 0;
    const int channel_index = 1;
    int32_t ret;

    if (!drv_frame->is_irq_triggered)
        return 0;

    ret = hm_get_ipc_channel(channel_index, &hwi_ch);
    if (ret != 0) {
        printf("%s : failed to get ipc channel for hwi: %d\n", drv_frame->name, ret);
        return -1;
    }

    ret = hwi_init(hwi_ch);
    if (ret != 0) {
        printf("%s: HWI init failed: %d\n", drv_frame->name, ret);
        return -1;
    }

    ret = hwi_create_irq_thread();
    if (ret != 0) {
        printf("%s: failed to create hwi irq thread: %d\n", drv_frame->name, ret);
        return -1;
    }

    return 0;
}

static int32_t drv_framework_init(const struct drv_frame_t *drv_frame)
{
    int32_t ret;

    ret = hwi_context_init(drv_frame);
    if (ret != 0)
        return -1;

    if (drv_frame->init != NULL) {
        ret = drv_frame->init();
        if (ret != 0) {
            printf("%s: failed to init platorm driver: %d\n", drv_frame->name, ret);
            return -1;
        }
    }

    ret = tc_drv_init();
    if (ret != 0) {
        printf("%s: failed to init platorm driver: %d\n", drv_frame->name, ret);
        return -1;
    }

    return 0;
}

int32_t hm_register_drv_framework(const struct drv_frame_t *drv_frame, cref_t *ch, bool new_frame)
{
    int32_t ret;

    if (drv_frame == NULL || drv_frame->name == NULL || ch == NULL) {
        printf("invalid params\n");
        return -1;
    }

    hm_mmgr_clt_init();
    ret = cs_client_init(&g_sysmgr_client, __sysmgrch);
    if (ret != 0) {
        printf("%s: failed to init cc client: %d\n", drv_frame->name, ret);
        return -1;
    }

    print_drv_info(drv_frame->name);
    _init();

    ret = ipc_init(drv_frame->name, ch);
    if (ret != 0)
        return ret;

    ret = system_init(drv_frame->name, new_frame);
    if (ret != 0)
        return ret;

    if (!new_frame) {
        ret = drv_framework_init(drv_frame);
        if (ret != 0)
            return ret;
    }

    ret = hmapi_extend_utable();
    if (ret < 0) {
        printf("%s: failed to extend utable: %s\n", drv_frame->name, hmapi_strerror(ret));
        return ret;
    }

    return 0;
}

static int32_t pm_forward_msg_param_check(uint16_t msg_id, const char *drv_name, cref_t *drv_cref)
{
    if (msg_id != HM_MSG_ID_DRV_PWRMGR_SUSPEND_CPU && msg_id != HM_MSG_ID_DRV_PWRMGR_RESUME_CPU &&
        msg_id != HM_MSG_ID_DRV_PWRMGR_SUSPEND_S4 && msg_id != HM_MSG_ID_DRV_PWRMGR_RESUME_S4) {
        hm_error("pm forward invalid msg id:0x%x\n", msg_id);
        return -1;
    }

    if (drv_cref == NULL) {
        hm_error("pm forward invalid drv cref\n");
        return -1;
    }

    if (drv_name == NULL) {
        hm_error("pm forward invalid drv name\n");
        return -1;
    }

    size_t len = strnlen(drv_name, DRV_NAME_MAX_LEN);
    if (len == 0 || len >= DRV_NAME_MAX_LEN) {
        hm_error("pm forward invalid drv name len\n");
        return -1;
    }

    return 0;
}

int32_t pm_forward_msg_to_other_drv(uint16_t msg_id, const char *drv_name, cref_t *drv_cref)
{
    int32_t err = pm_forward_msg_param_check(msg_id, drv_name, drv_cref);
    if (err != 0)
        return -1;

    hm_msg_header req = {{ 0 }};
    hm_msg_header reply = {{ 0 }};

    if (is_ref_err(*drv_cref)) {
        err = pathmgr_acquire(drv_name, drv_cref);
        if (err != 0 || is_ref_err(*drv_cref)) {
            hm_error("get drv:%s cref failed error %s, cref %s\n", drv_name, hmapi_strerror(err),
                     hmapi_strerror(ref_to_err(*drv_cref)));
            return -1;
        }
    }

    req.send.msg_class = HM_MSG_HEADER_CLASS_DRV_PWRMGR;
    req.send.msg_id    = msg_id;
    req.send.msg_size  = sizeof(req);
    err = hm_msg_call(*drv_cref, &req, sizeof(req), &reply, sizeof(reply), 0, -1);
    if (err != 0)
        hm_error("forward msg 0x%x to drv:%s failed, error %s\n", msg_id, drv_name, hmapi_strerror(err));
    return err;
}

int32_t hm_driver_pm_return_to_ree(uint16_t msg_id)
{
    int32_t cpu;
    enum cap_teesmc_req req;
    int32_t err;

    cpu = hm_get_current_cpu_id();

    switch (msg_id) {
    case HM_MSG_ID_DRV_PWRMGR_SUSPEND_CPU:
        req = CAP_TEESMC_REQ_CPU_SUSPEND;
        break;
    case HM_MSG_ID_DRV_PWRMGR_RESUME_CPU:
        req = CAP_TEESMC_REQ_CPU_RESUME;
        break;
    case HM_MSG_ID_DRV_PWRMGR_SUSPEND_S4:
        req = CAP_TEESMC_REQ_S4_SUSPEND_DONE;
        break;
    case HM_MSG_ID_DRV_PWRMGR_RESUME_S4:
        req = CAP_TEESMC_REQ_S4_RESUME_DONE;
        break;
    default:
        req = CAP_TEESMC_REQ_NR;
    }
    err = hmex_teesmc_switch_req(get_teesmc_hdlr(), req);
    if (err != 0)
        hm_error("cpus %d return to ree failed msg 0x%x, error %s\n", cpu, msg_id, hmapi_strerror(err));
    return err;
}
