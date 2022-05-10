/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: driver module manage function and structure
 * Create: 2020-08-31
 */
#include "drv_mod.h"
#include <pthread.h>
#include <securec.h>
#include <string.h>
#include <sre_syscalls_ext.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <dlfcn.h>
#include <securec.h>
#include <errno.h>
#include <tee_defines.h>
#include <tee_log.h>
#include <procmgr_ext.h>
#include <tee_config.h>
#include "drv_param_type.h"
#include "drv_call_check.h"

struct dlist_node g_drv_mod_list;
static pthread_mutex_t g_drv_mod_mutex = PTHREAD_ROBUST_MUTEX_INITIALIZER;
#define FULL_REF_CNT 0xFFFFFFFFU
#define DRVMOD_MMAP_PTR0_INDEX 0
#define DRVMOD_ARG0_INDEX 0
#define DRVMOD_ARG1_INDEX 1
#define LIB_NAME_LEN_IDEX 1
#define LIB_NAME_OFFSET 0
#define MOD_EXIST (-2)

static void get_mod_info(struct drv_module_info *mod_info)
{
    if (mod_info == NULL)
        return;

    if (mod_info->refcnt == FULL_REF_CNT) {
        tloge("mod: %s refcnt will overflow\n", mod_info->name);
        return;
    }

    mod_info->refcnt++;
}

static void put_mod_info(struct drv_module_info *mod_info)
{
    if (mod_info == NULL)
        return;

    if (mod_info->refcnt == 0) {
        tloge("caution! %s refcnt is zero here\n", mod_info->name);
        return;
    }

    if (pthread_mutex_lock(&g_drv_mod_mutex) != 0) {
        tloge("put mod lock fail\n");
        return;
    }

    mod_info->refcnt--;
    if (mod_info->refcnt != 0) {
        if (pthread_mutex_unlock(&g_drv_mod_mutex) != 0)
            tloge("put mod unlock fail\n");
        return;
    }
    if (pthread_mutex_unlock(&g_drv_mod_mutex) != 0)
        tloge("put mod- unlock fail\n");

    if (mod_info->mod_entry != NULL && mod_info->mod_entry->exit != NULL)
        mod_info->mod_entry->exit();

    if (mod_info->mod_multi_entry != NULL && mod_info->mod_multi_entry->exit != NULL)
        mod_info->mod_multi_entry->exit();

    if (mod_info->lib_handle != NULL) {
        dlclose(mod_info->lib_handle);
        tlogd("%s refcnt is zero and dlclose\n", mod_info->name);
    }
    free(mod_info);
}

static struct drv_module_info *find_mod(const char *name)
{
    struct drv_module_info *mod_info = NULL;

    tlogd("name: %s is being found\n", name);
    if (pthread_mutex_lock(&g_drv_mod_mutex) != 0) {
        tloge("find mod lock fail\n");
        return mod_info;
    }
    dlist_for_each_entry(mod_info, &g_drv_mod_list, struct drv_module_info, list) {
        if (!strcmp(name, mod_info->name)) {
            get_mod_info(mod_info);
            if (pthread_mutex_unlock(&g_drv_mod_mutex) != 0)
                tloge("find mod unlock fail\n");
            return mod_info;
        }
    }
    if (pthread_mutex_unlock(&g_drv_mod_mutex) != 0)
        tloge("find mod- unlock fail\n");

    return NULL;
}

static int32_t get_drv_desc(struct drv_module_info *mod_info, const char *prefix)
{
    char str_name[FUNC_NAME_SIZE] = { 0 };
    void *str_sym = NULL;
    int ret;

    if (snprintf_s(str_name, FUNC_NAME_SIZE, sizeof(str_name) - 1, "%s%s", "__drv_desc_", prefix) <= 0) {
        tloge("combine struct name failed\n");
        return -1;
    }

    str_sym = dlsym(mod_info->lib_handle, str_name);
    if (str_sym == NULL) {
        tloge("dlsym %s failed: %s\n", str_name, dlerror());
        return -1;
    }
    mod_info->mod_entry = str_sym;

    if (mod_info->mod_entry->init == NULL)
        return 0;

    ret = mod_info->mod_entry->init();
    if (ret != 0)
        tloge("\t%s init failed %d\n", mod_info->name, ret);
    return ret;
}

static int32_t get_multi_drv_desc(struct drv_module_info *mod_info, const char *prefix)
{
    char str_name[FUNC_NAME_SIZE] = { 0 };
    void *str_sym = NULL;
    int ret;

    if (snprintf_s(str_name, FUNC_NAME_SIZE, sizeof(str_name) - 1, "%s%s", "__drv_desc_multi_", prefix) <= 0) {
        tloge("combine multi struct name failed\n");
        return DRV_CALL_ERROR;
    }

    str_sym = dlsym(mod_info->lib_handle, str_name);
    if (str_sym == NULL) {
        if (errno == ENOENT) {
            tlogi("no multi mod entry\n");
            return 0;
        }
        tloge("dlsym %s failed: %s\n", str_name, dlerror());
        return DRV_CALL_ERROR;
    }

    mod_info->mod_multi_entry = str_sym;
    if (mod_info->mod_multi_entry->init == NULL)
        return 0;

    ret = mod_info->mod_multi_entry->init();
    if (ret != 0)
        tloge("\t%s multi init failed %d\n", mod_info->name, ret);
    return ret;
}

static int32_t fill_mod_info(struct drv_module_info *mod_info)
{
    char name_bak[DRV_MOD_NAME_LEN] = { 0 };
    char *ptr = name_bak;
    char *prefix = NULL;

    if (memcpy_s(name_bak, DRV_MOD_NAME_LEN, mod_info->name, DRV_MOD_NAME_LEN) != 0)
        return DRV_CALL_ERROR;

    prefix = strsep(&ptr, ".");
    if (prefix == NULL) {
        tloge("bad lib name: %s\n", mod_info->name);
        return DRV_CALL_ERROR;
    }

    mod_info->lib_handle = dlopen(mod_info->name, RTLD_NOW | RTLD_GLOBAL);
    if (mod_info->lib_handle == NULL) {
        tloge("open lib failed: %s, reason: %s\n", mod_info->name, dlerror());
        return DRV_CALL_ERROR;
    }

    if (get_drv_desc(mod_info, prefix) != 0)
        goto free_handle;

    if (get_multi_drv_desc(mod_info, prefix) != 0)
        goto free_handle;

    return 0;

free_handle:
    dlclose(mod_info->lib_handle);
    return -1;
}

static int32_t get_drv_name(const struct drv_param *params, char *name,
                            uint32_t name_len, uint32_t *used_len)
{
    char *data = (char *)(uintptr_t)params->data;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    if (data == NULL || args == NULL) {
        tloge("invalid param\n");
        return DRV_CALL_ERROR;
    }

    uint64_t len = args[LIB_NAME_LEN_IDEX];
    if (len == 0 || len >= name_len) { /* reserved one char for '\0' */
        tloge("name len:0x%x is invalid\n", (uint32_t)len);
        return DRV_CALL_ERROR;
    }

    if (args[LIB_NAME_OFFSET] != 0) {
        tloge("drv name offset:0x%x is not zero\n", (uint32_t)args[LIB_NAME_OFFSET]);
        return DRV_CALL_ERROR;
    }

    if (memcpy_s(name, name_len, data, len) != EOK) {
        tloge("copy name failed\n");
        return DRV_CALL_ERROR;
    }

    name[len] = '\0';

    if (used_len != NULL)
        *used_len = len + 1;

    return DRV_CALL_OK;
}

static int32_t install_module(const struct drv_param *params)
{
    struct drv_module_info *mod_info = NULL;
    spawn_uuid_t uuid = {0};
    uint32_t pid = params->pid;
    uid_t uid = params->uid;
    char name[DRV_MOD_NAME_LEN] = {0};
    uint32_t name_len;

    if (get_drv_name(params, name, sizeof(name), &name_len) != DRV_CALL_OK)
        return DRV_CALL_ERROR;

    if (hm_getuuid(pid, &uuid) < 0) {
        tloge("get uuid error!\n");
        return DRV_CALL_ERROR;
    }

    if (!is_modload_perm_valid(&uuid.uuid, name)) {
        tloge("uuid: 0x%x has no perm to open lib: %s\n", uuid.uuid.timeLow, name);
        return DRV_CALL_ERROR;
    }

    mod_info = find_mod(name);
    if (mod_info != NULL) {
        tloge("name: %s has been installed\n", mod_info->name);
        put_mod_info(mod_info);
        return MOD_EXIST;
    }

    mod_info = malloc(sizeof(*mod_info));
    if (mod_info == NULL) {
        tloge("malloc mod info failed\n");
        return DRV_CALL_ERROR;
    }

    if (memset_s(mod_info, sizeof(*mod_info), 0, sizeof(*mod_info)) != 0 ||
        memcpy_s(mod_info->name, sizeof(mod_info->name), name, name_len) != 0) {
        free(mod_info);
        return DRV_CALL_ERROR;
    }

    if (fill_mod_info(mod_info) != 0) {
        free(mod_info);
        return DRV_CALL_ERROR;
    }

    mod_info->uid = uid;
    mod_info->refcnt = 1;
    if (pthread_mutex_lock(&g_drv_mod_mutex) != 0) {
        tloge("inst mod lock fail\n");
        free(mod_info);
        return DRV_CALL_ERROR;
    }
    dlist_insert_tail(&mod_info->list, &g_drv_mod_list);
    if (pthread_mutex_unlock(&g_drv_mod_mutex) != 0)
        tloge("inst mod unlock fail\n");
    return 0;
}

static int32_t uninstall_module(const struct drv_param *params)
{
    struct drv_module_info *mod_info = NULL;
    spawn_uuid_t uuid = {0};
    uint32_t pid = params->pid;
    uid_t uid = params->uid;
    char name[DRV_MOD_NAME_LEN] = {0};

    if (get_drv_name(params, name, sizeof(name), NULL) != DRV_CALL_OK)
        return DRV_CALL_ERROR;

    if (hm_getuuid(pid, &uuid) < 0) {
        tloge("get uuid error!\n");
        return DRV_CALL_ERROR;
    }

    if (!is_modload_perm_valid(&uuid.uuid, name)) {
        tloge("uuid: 0x%x has no perm to close lib: %s\n", uuid.uuid.timeLow, name);
        return DRV_CALL_ERROR;
    }

    mod_info = find_mod(name);
    if (mod_info == NULL) {
        tloge("%s not installed\n", name);
        return DRV_CALL_ERROR;
    }

    if (mod_info->uid != uid) {
        tloge("%s is not opened by this TA\n", name);
        put_mod_info(mod_info);
        return DRV_CALL_ERROR;
    }

    if (pthread_mutex_lock(&g_drv_mod_mutex) != 0) {
        tloge("uninst lock fail\n");
        put_mod_info(mod_info);
        return DRV_CALL_ERROR;
    }
    dlist_delete(&mod_info->list);
    if (pthread_mutex_unlock(&g_drv_mod_mutex) != 0)
        tloge("uninst unlock fail\n");

    put_mod_info(mod_info);
    put_mod_info(mod_info); /* pair with install */
    return 0;
}

int mod_drv_syscall(int32_t swi_id, struct drv_param *params, uint64_t perm, bool multi)
{
    struct drv_module_info *mod_info = NULL;
    struct drv_module_info *tmp = NULL;
    struct tc_drv_dyn_desc *mod_entry = NULL;

    if (pthread_mutex_lock(&g_drv_mod_mutex) != 0) {
        tloge("mod syscall lock fail\n");
        return DRV_CALL_ERROR;
    }
    mod_info = dlist_first_entry(&g_drv_mod_list, struct drv_module_info, list);
    if (&(mod_info->list) == &g_drv_mod_list) {
        if (pthread_mutex_unlock(&g_drv_mod_mutex) != 0)
            tloge("mod syscall unlock fail\n");
        return DRV_CALL_ERROR;
    }
    get_mod_info(mod_info);
    if (pthread_mutex_unlock(&g_drv_mod_mutex) != 0)
        tloge("mod syscall- unlock fail\n");

    do {
        if (multi)
            mod_entry = mod_info->mod_multi_entry;
        else
            mod_entry = mod_info->mod_entry;

        if (mod_entry != NULL && mod_entry->syscall != NULL) {
            if (mod_entry->syscall(swi_id, params, perm) == 0) {
                tlogd("driver \"%s\" handle swi %d\n", mod_info->name, swi_id);
                put_mod_info(mod_info);
                return 0;
            }
        }

        tmp = mod_info;
        if (pthread_mutex_lock(&g_drv_mod_mutex) != 0) {
            tloge("drv syscall lock fail\n");
            put_mod_info(tmp);
            return DRV_CALL_ERROR;
        }
        mod_info = dlist_next_entry(mod_info, struct drv_module_info, list);
        if (mod_info->list.next == &mod_info->list) /* mod is deleted from list, we start from begin */
            mod_info = dlist_first_entry(&g_drv_mod_list, struct drv_module_info, list);

        if (&(mod_info->list) == &g_drv_mod_list) {
            if (pthread_mutex_unlock(&g_drv_mod_mutex) != 0)
                tloge("drv syscall unlock fail\n");
            put_mod_info(tmp);
            return DRV_CALL_ERROR;
        }
        get_mod_info(mod_info);
        if (pthread_mutex_unlock(&g_drv_mod_mutex) != 0)
            tloge("drv syscall- unlock fail\n");
        put_mod_info(tmp);
    } while (1);
}

int32_t mod_manage_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    int32_t ret;

    if (params == NULL || params->args == 0)
        return DRV_CALL_ERROR;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    switch (swi_id) {
    case SW_SYSCALL_OPEN_MOD:
        ret = check_call_permission(permissions, GENERAL_GROUP_PERMISSION);
        if (ret != DRV_CALL_OK) {
            tloge("OPEN_MOD has no permission to access swi_id 0x%x\n", swi_id);
            args[0] = (uint64_t)ret;
            break;
        }
        ret = install_module(params);
        args[0] = (uint64_t)ret;
        break;
    case SW_SYSCALL_CLOSE_MOD:
        ret = check_call_permission(permissions, GENERAL_GROUP_PERMISSION);
        if (ret != DRV_CALL_OK) {
            tloge("CLOSE_MOD has no permission to access swi_id 0x%x\n", swi_id);
            args[0] = (uint64_t)ret;
            break;
        }
        ret = uninstall_module(params);
        args[0] = (uint64_t)ret;
        break;
    default:
        return DRV_CALL_ERROR;
    }

    return 0;
}

int32_t mod_manage_init(void)
{
    dlist_init(&g_drv_mod_list);
    return 0;
}

DECLARE_TC_DRV(
    mod_manage,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    mod_manage_init,
    NULL,
    mod_manage_syscall,
    NULL,
    NULL
);
