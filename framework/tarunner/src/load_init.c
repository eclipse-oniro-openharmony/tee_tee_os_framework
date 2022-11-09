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
