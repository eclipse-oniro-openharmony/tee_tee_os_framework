/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: the functions to init library and tee hanle
 * Author: qishuai 00528667
 * Create: 2021-01-16
 */

#include "load_init.h"
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <tee_log.h>
#include <hmlog.h>
#include <sys/kuapi.h>
#include <sys/hm_priorities.h>
#include <sys/hmapi_ext.h>
#include <tee_secfile_load_agent.h>

static void *g_libtee = NULL;

int32_t get_priority(void)
{
    char *prio_var = getenv("priority");
    int32_t priority;

    if (prio_var != NULL) {
        errno = 0;
        priority = strtol(prio_var, NULL, 10); /* Convert priority to decimal */
        if ((errno != 0) || (priority < HM_PRIO_TEE_MIN) || (priority > HM_PRIO_TEE_MAX)) {
            hm_warning("bad priority set, use default HM_PRIO_TEE_TA\n");
            priority = HM_PRIO_TEE_TA;
        }
    } else {
        hm_warning("no priority set, use default HM_PRIO_TEE_TA\n");
        priority = HM_PRIO_TEE_TA;
    }

    return priority;
}

int32_t extend_utables(void)
{
    int32_t i;
    int32_t cnt = 1;

    for (i = 0; i < cnt; i++) {
        if (hmapi_extend_utable() != 0) {
            hm_error("extend utable failed %d\n", i);
            return HM_ERROR;
        }
    }

    return HM_OK;
}

void clear_libtee(void)
{
    if (g_libtee == NULL) {
        hm_error("libtee handle is NULL\n");
        return;
    }

    dlclose(g_libtee);
    g_libtee = NULL;
}

void *get_libtee_handle(void)
{
    if (g_libtee == NULL) {
        hm_error("libtee handle is NULL\n");
        return NULL;
    }

    return g_libtee;
}

void *ta_mt_dlopen(const char *name, int32_t flag)
{
    if (name == NULL) {
        hm_error("dlopen name is invalied\n");
        return NULL;
    }

    size_t length = strnlen(name, LIB_NAME_MAX);
    if (length == 0 || length >= LIB_NAME_MAX) {
        hm_error("dlopen name length is invalied\n");
        return NULL;
    }

    g_libtee = dlopen(name, flag);
    if (g_libtee == NULL) {
        hm_error("load library failed: %s\n", dlerror());
        return NULL;
    }

    return g_libtee;
}
