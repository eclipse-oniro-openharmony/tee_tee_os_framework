/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tc driver init file
 * Create: 2019-09-18
 */

#include "tc_drv.h"
#include <errno.h>
#include <drv_module.h>
#include <tee_log.h>
#include <drv_module.h>
#include "drv_mod.h"

extern uint32_t g_tc_drv_descs_start;
extern uint32_t g_tc_drv_descs_end;
#define TC_DRV_DESCS_START ((uint32_t)(uintptr_t)(&g_tc_drv_descs_start))
#define TC_DRV_DESCS_END   ((uint32_t)(uintptr_t)(&g_tc_drv_descs_end))
extern uint32_t g_tc_drv_descs_multi_start;
extern uint32_t g_tc_drv_descs_multi_end;
#define TC_DRV_DESCS_MULTI_START      ((uint32_t)(uintptr_t)(&g_tc_drv_descs_multi_start))
#define TC_DRV_DESCS_MULTI_END        ((uint32_t)(uintptr_t)(&g_tc_drv_descs_multi_end))

static struct tc_drv_desc *g_tc_drvs = NULL;
static uint32_t g_tc_drvs_nr;
static struct tc_drv_desc *g_tc_drvs_multi = NULL;
static uint32_t g_tc_drvs_multi_nr;

static void tc_early_init(void)
{
    uint32_t i;
    int32_t ret;

    tlogd("early begin init tc\n");
    for (i = 0; i < g_tc_drvs_nr; i++) {
        if (g_tc_drvs[i].init != NULL && g_tc_drvs[i].priority == TC_DRV_EARLY_INIT) {
            tlogd("init %s\n", g_tc_drvs[i].name);
            ret = g_tc_drvs[i].init();
            if (ret != 0)
                tloge("\t%s init failed %d\n", g_tc_drvs[i].name, ret);
        }
    }
}

static void tc_arch_init(void)
{
    uint32_t i;
    int32_t ret;

    tlogd("begin to init tc arch\n");
    for (i = 0; i < g_tc_drvs_nr; i++) {
        if (g_tc_drvs[i].init != NULL && g_tc_drvs[i].priority == TC_DRV_ARCH_INIT) {
            tlogd("int \t%s\n", g_tc_drvs[i].name);
            ret = g_tc_drvs[i].init();
            if (ret != 0)
                tloge("%s init failed %d\n", g_tc_drvs[i].name, ret);
        }
    }
}

/*
 * After Enable cfi, there will be instuction fault will be happen;
 * Reason: some thirdparty libs as "libsec_decoder.a" can't recompile with llvm cfi;
 * The init function can't find real ".cfi" funtion ;
 * Also can Temp masked with  "__attribute__((__no_sanitize__("cfi")))" after recompile
 * */
static void tc_module_init(void)
{
    uint32_t i;
    int32_t ret;

    tlogd("begin to init tc module\n");
    for (i = 0; i < g_tc_drvs_nr; i++) {
        if (g_tc_drvs[i].init != NULL && g_tc_drvs[i].priority == TC_DRV_MODULE_INIT) {
            tlogd("%s\n", g_tc_drvs[i].name);
            ret = g_tc_drvs[i].init();
            if (ret != 0)
                tloge("%s init failed %d\n", g_tc_drvs[i].name, ret);
#ifdef TEE_SUPPORT_M_DRIVER
        } else if (g_tc_drvs[i].vendor_init != NULL && g_tc_drvs[i].priority == TC_DRV_MODULE_INIT) {
            ret = g_tc_drvs[i].vendor_init(NULL);
            if (ret != 0)
                tloge("\t%s init failed %d\n", g_tc_drvs[i].name, ret);
#endif
        }
    }
}

static void tc_late_init(void)
{
    uint32_t i;
    int32_t ret;

    tlogd("begin to init tc late\n");
    for (i = 0; i < g_tc_drvs_nr; i++) {
        if (g_tc_drvs[i].init != NULL && g_tc_drvs[i].priority == TC_DRV_LATE_INIT) {
            tlogd("%s\n", g_tc_drvs[i].name);
            ret = g_tc_drvs[i].init();
            if (ret != 0)
                tloge("%s init failed %d\n", g_tc_drvs[i].name, ret);
        }
    }
}

int32_t tc_drv_init(void)
{
    g_tc_drvs    = (struct tc_drv_desc *)(uintptr_t)TC_DRV_DESCS_START;
    g_tc_drvs_nr = (TC_DRV_DESCS_END - TC_DRV_DESCS_START) / sizeof(struct tc_drv_desc);

    g_tc_drvs_multi = (struct tc_drv_desc *)(uintptr_t)TC_DRV_DESCS_MULTI_START;
    g_tc_drvs_multi_nr = (TC_DRV_DESCS_MULTI_END - TC_DRV_DESCS_MULTI_START) / sizeof(struct tc_drv_desc);

    tlogd("initialize drivers:\n");
    tc_early_init();
    tc_arch_init();
    tc_module_init();
    tc_late_init();

    return 0;
}

#ifdef TEE_SUPPORT_M_DRIVER
static int32_t handle_vendor_call(int32_t swi_id, const struct tc_drv_desc *tc_drvs,
    uint32_t i, struct drv_param *params, uint64_t perm)
{
    int32_t ret = tc_drvs[i].vendor_call(&(tc_drvs[i].fn_entry), swi_id, params, perm);
    if (ret != 0)
        tloge("drv:%d handle cmd failed\n", swi_id);

    return ret;
}
#endif

int32_t vendor_drv_syscall(int32_t swi_id, struct drv_param *params, uint64_t perm)
{
#ifdef TEE_SUPPORT_M_DRIVER
    uint32_t i;

    for (i = 0; i < g_tc_drvs_nr; i++) {
        if (g_tc_drvs[i].vendor_call != NULL) {
            if (swi_id == g_tc_drvs[i].fn_entry.drv_id)
                return handle_vendor_call(swi_id, g_tc_drvs, i, params, perm);
        }
    }
#endif

    int32_t ret = mod_drv_syscall(swi_id, params, perm, true);
    if (ret != 0)
        tloge("no multi driver can handle swi_id 0x%x\n", swi_id);

    return ret;
}

int32_t tc_drv_syscall(int32_t swi_id, struct drv_param *params, uint64_t perm)
{
    uint32_t i;

    for (i = 0; i < g_tc_drvs_nr; i++) {
        if (g_tc_drvs[i].syscall != NULL) {
            if (g_tc_drvs[i].syscall(swi_id, params, perm) == 0) {
                /*
                 * g_tc_drvs can be used by multi thread, do not change it after platdrv init
                 */
                tlogd("driver \"%s\" handle swi %d\n", g_tc_drvs[i].name, swi_id);
                return 0;
            }
#ifdef TEE_SUPPORT_M_DRIVER
        } else if (g_tc_drvs[i].vendor_call != NULL) {
            if (swi_id == g_tc_drvs[i].fn_entry.drv_id)
                return handle_vendor_call(swi_id, g_tc_drvs, i, params, perm);
#endif
        }
    }

    if (mod_drv_syscall(swi_id, params, perm, false) == 0)
        return 0;

    tloge("no driver can handle swi_id 0x%x\n", swi_id);

    return -ENOSYS;
}

void tc_drv_sp(void)
{
    uint32_t i;
    for (i = 0; i < g_tc_drvs_nr; i++) {
        if (g_tc_drvs[i].suspend == NULL)
            continue;
        (void)g_tc_drvs[i].suspend();
    }
}

void tc_drv_sr(void)
{
    uint32_t i;
    for (i = 0; i < g_tc_drvs_nr; i++) {
        if (g_tc_drvs[i].resume == NULL)
            continue;
        (void)g_tc_drvs[i].resume();
    }
}

void tc_drv_sp_s4()
{
#ifndef TEE_SUPPORT_M_DRIVER
    uint32_t i;
    for (i = 0; i < g_tc_drvs_nr; i++) {
        if (g_tc_drvs[i].suspend_s4 == NULL)
            continue;
        (void)g_tc_drvs[i].suspend_s4();
    }
#endif
}

void tc_drv_sr_s4(void)
{
#ifndef TEE_SUPPORT_M_DRIVER
    uint32_t i;
    for (i = 0; i < g_tc_drvs_nr; i++) {
        if (g_tc_drvs[i].resume_s4 == NULL)
            continue;
        (void)g_tc_drvs[i].resume_s4();
    }
#endif
}
