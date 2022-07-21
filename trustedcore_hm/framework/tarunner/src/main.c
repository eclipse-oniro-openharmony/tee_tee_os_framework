/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: TA work thread function.
 * Create: 2019-05-18
 */

#include "main.h"
#include <stdio.h>
#include <stdlib.h>
#include <enable_free_uncommit.h> /* libc header file */
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/hm_priorities.h> /* for `HM_PRIO_TEE_*` */
#include <sys/fileio.h>
#include <api/tee_common.h>
#include <procmgr_ext.h>
#include <ipclib.h>
#include <cs.h>
#include <teecall_cap.h>
#include <ta_framework.h>
#include <tee_task.h>
#include <tee_drv_internal.h>
#include <spawn_init.h>
#include <target_type.h>
#include <tee_drv_entry.h>
#include "get_spawn_env.h"
#include "load_init.h"
#include "ta_mt.h"

#define RTLD_TA 0x100000
#define IPC_CHANNEL_NUM 2

#ifdef __aarch64__
static const char *g_tarunner_path = "/tarunner.elf";
static const char *g_drv_so_path = "libdrv_shared.so";
static const char *g_tee_share_so_path = "libtee_shared.so";
#else
static const char *g_tarunner_path = "/tarunner_a32.elf";
static const char *g_drv_so_path = "libdrv_shared_a32.so";
static const char *g_tee_share_so_path = "libtee_shared_a32.so";
#endif

static int32_t param_check(int32_t argc, const char * const * argv, bool *free_uncommit)
{
    size_t length;

    if (argc < (ARGV_TERMINATE_INDEX - 1)) {
        hm_error("invalid argc %d\n", argc);
        return HM_ERROR;
    }

    if (strncmp(argv[ARGV_UNCOMMIT_INDEX], "no_uc", sizeof("no_uc")) == 0)
        *free_uncommit = false;

    length = strnlen(argv[ARGV_TASK_NAME_INDEX], ARGV0_SIZE);
    if (length == 0 || length >= ARGV0_SIZE) {
        hm_error("invalid service name\n");
        return HM_ERROR;
    }

    if (strncmp(argv[ARGV_TASK_NAME_INDEX], g_tarunner_path, (strlen(g_tarunner_path) + 1)) == 0) {
        hm_error("load TA in buffer not implemented\n");
        return HM_ERROR;
    }

    length = strnlen(argv[ARGV_TASK_PATH_INDEX], ARGV_SIZE);
    if (length == 0 || length >= ARGV_SIZE) {
        hm_error("invalid path name\n");
        return HM_ERROR;
    }

    return HM_OK;
}

/*
 * they work for many TAs
 * which helps TA to extend utilities
 */
static bool is_agent(const char *task_name)
{
    if (strncmp(task_name, "task_ssa", strlen("task_ssa") + 1) == HM_OK)
        return true;
    return false;
}

static bool extend_one_more_utable(const char *task_name)
{
    return is_agent(task_name);
}

static const char *get_target_type_name(const struct env_param *param)
{
    const char *name = NULL;

    if (param->target_type == DRV_TARGET_TYPE)
        name = "DRV";
    else
        name = "TA";

    return name;
}

static void load_info_print(const char *task_name, const struct env_param *param, bool free_uncommit)
{
    const char *type = get_target_type_name(param);

    /* Always print, but not an error */
#ifdef __aarch64__
    std_log("TRACE", "*", __LINE__, "Start dynlink 64bit %s %s: pid=%d ca=%u %s\n", type, task_name, hm_getpid(),
        param->ca, free_uncommit ? "" : " no-uncommit");
#else
    std_log("TRACE", "*", __LINE__, "Start dynlink %s %s: pid=%d ca=%u %s\n", type, task_name, hm_getpid(), param->ca,
        free_uncommit ? "" : " no-uncommit");
#endif
}

static int32_t create_task_channel(const char *task_name, const struct env_param *param, cref_t *drv_channel)
{
    int32_t ret;
    struct reg_items_st reg_items = { true, false, false };

    if (param->target_type == DRV_TARGET_TYPE) {
        /* used for cs_server_loop */
        ret = hm_create_ipc_native(task_name, drv_channel);
        if (ret != HM_OK) {
            hm_error("create drv:%s channel failed\n", task_name);
            return HM_ERROR;
        }

        hm_debug("create drv:%s channel:0x%llx\n", task_name, (unsigned long long)(*drv_channel));

        /* used for irq thread */
        ret = hm_create_multi_ipc_channel(NULL, IPC_CHANNEL_NUM, NULL, reg_items);
        if (ret != HM_OK) {
            hm_error("create drv irq channel failed\n");
            return HM_ERROR;
        }
    } else {
        /* Create 2 IPC channels */
        ret = hm_create_multi_ipc_channel(task_name, IPC_CHANNEL_NUM, NULL, reg_items);
        if (ret != HM_OK) {
            hm_error("create multi ipc channel failed: %d\n", ret);
            return HM_ERROR;
        }
    }

    return 0;
}

static int32_t init1(const char *task_name, const struct env_param *param, bool free_uncommit, cref_t *drv_channel)
{
    int32_t ret;

    load_info_print(task_name, param, free_uncommit);

    /* Extend utable for drv or agent, such as SSA */
    if ((param->target_type == DRV_TARGET_TYPE) || extend_one_more_utable(task_name)) {
        ret = extend_utables();
        if (ret != HM_OK) {
            hm_error("extend utable for \"%s\" failed: %d\n", task_name, ret);
            return HM_ERROR;
        }
    }

    ret = create_task_channel(task_name, param, drv_channel);
    if (ret != 0)
        return HM_ERROR;

    ret = fileio_init();
    if (ret != HM_OK) {
        hm_error("file io init failed: %d\n", ret);
        return HM_ERROR;
    }

    return HM_OK;
}

static int32_t init2(void *libtee, const char *task_name, uint32_t target_type)
{
    const void **pp = NULL;
    int32_t (*func)(void) = NULL;

    /* Change debug prefix */
    pp = dlsym(libtee, "g_debug_prefix");
    if (pp != NULL)
        *pp = task_name;

#if defined(TEE_SUPPORT_PLATDRV_64BIT) || defined(TEE_SUPPORT_PLATDRV_32BIT)
    if (target_type != DRV_TARGET_TYPE) {
        func = dlsym(libtee, "hm_ccmgr_init");
        if ((func == NULL) || (func() != HM_OK)) {
            hm_error("ccmgr init failed\n");
            return HM_ERROR;
        }
    }
#else
    (void)target_type;
#endif

#ifndef CONFIG_OFF_DRV_TIMER
    func = dlsym(libtee, "hm_timer_init");
    if ((func == NULL) || (func() != HM_OK)) {
        hm_error("timer init failed\n");
        return HM_ERROR;
    }
#endif

    (void)func;
    return HM_OK;
}

static int32_t driver_job_handler(void *libtee, uint32_t target_type)
{
    int32_t (*func)(void) = NULL;

#if defined(TEE_SUPPORT_PLATDRV_64BIT) || defined(TEE_SUPPORT_PLATDRV_32BIT)
    if (target_type != DRV_TARGET_TYPE) {
        func = dlsym(libtee, "renew_hmdrv_job_handler");
        if ((func == NULL) || (func() != HM_OK)) {
            hm_error("renew drv handler failed\n");
            return HM_ERROR;
        }
    }
#else
    (void)target_type;
#endif

    func = dlsym(libtee, "renew_hmtimer_job_handler");
    if ((func == NULL) || (func() != HM_OK)) {
        hm_error("renew timer handler failed\n");
        return HM_ERROR;
    }

    return HM_OK;
}

static int32_t init3(bool free_uncommit, const struct env_param *param, void *libtee)
{
    int32_t ret;

    if (free_uncommit)
        enable_free_uncommit();

    ret = hm_setuid(param->uid);
    if (ret != HM_OK) {
        hm_error("failed to setuid: %d\n", ret);
        return HM_ERROR;
    }

    /* Reject taldr cap, and grant TA cap */
    if (delete_rref_and_grant() != HM_OK) {
        hm_error("delete rref grant failed\n");
        return HM_ERROR;
    }

    if (driver_job_handler(libtee, param->target_type) != HM_OK)
        return HM_ERROR;

    ret = mprotect(&__tcb_cref, PAGE_SIZE, PROT_READ);
    if (ret != HM_OK) {
        hm_error("protect tcb cref failed: %d\n", ret);
        return HM_ERROR;
    }

    return HM_OK;
}

static int32_t library_init(const char *task_name, bool free_uncommit, const struct env_param *param, void **libtee)
{
    /* Load TEE library */
    *libtee = ta_mt_dlopen(g_tee_share_so_path, RTLD_NOW | RTLD_GLOBAL | RTLD_TA);
    if (*libtee == NULL)
        return HM_ERROR;

    /* TEE library initialization */
    if (init2(*libtee, task_name, param->target_type) != HM_OK)
        return HM_ERROR;

    if (init3(free_uncommit, param, *libtee) != HM_OK)
        return HM_ERROR;

    return HM_OK;
}

static void send_fail_msg_to_drvmgr(void)
{
    cref_t ch = 0;
    int32_t ret = hm_ipc_get_ch_from_path(DRV_SPAWN_SYNC_NAME, &ch);
    if (ret != 0) {
        hm_error("something wrong, spawn fail get drvmgr sync channel fail\n");
        return;
    }

    struct spawn_sync_msg msg = { 0 };
    msg.msg_id = PROCESS_INIT_FAIL;

    ret = hm_msg_notification(ch, &msg, sizeof(msg));
    if (ret != 0) {
        hm_error("spawn fail notify to drvmgr fail\n");
        return;
    }

    if (hm_ipc_release_path(DRV_SPAWN_SYNC_NAME, ch) != 0)
        hm_error("release drvmgr sync channel fail\n");
}

static void send_load_fail_msg(uint32_t target_type)
{
    if (target_type == DRV_TARGET_TYPE) {
        send_fail_msg_to_drvmgr();
    } else {
        /*
         * TA load failed, send error to global task
         * uwMsgHandle is 0 mean we don't need handle msg in msg function
         * uwMsgID is 0 means we don't care about the context
         * ucDstID is 1 means the recevier's channel ID is 1
         */
        if (ipc_msg_qsend(DEFAULT_MSG_HANDLE, CREATE_THREAD_FAIL, GLOBAL_HANDLE, SECOND_CHANNEL) != 0)
            hm_error("failed to reply GTASK for MT ta\n");
    }
}

static void load_fail(uint32_t target_type)
{
    clear_libtee();

    send_load_fail_msg(target_type);
}

static int32_t get_routine_info(void *handle, uint32_t size, struct ta_routine_info *routine)
{
    /* no need to check function entry since TA may not define it */
    routine->info[CREATE_ENTRY_INDEX] = dlsym(handle, "TA_CreateEntryPoint");
    routine->info[OPEN_SESSION_INDEX] = dlsym(handle, "TA_OpenSessionEntryPoint");
    routine->info[INVOKE_COMMAND_INDEX] = dlsym(handle, "TA_InvokeCommandEntryPoint");
    routine->info[CLOSE_SESSION_INDEX] = dlsym(handle, "TA_CloseSessionEntryPoint");
    routine->info[DESTROY_ENTRY_INDEX] = dlsym(handle, "TA_DestroyEntryPoint");

    /* should check caller info when open session */
    routine->addcaller_flag = true;

    if (mprotect(routine, size, PROT_READ) != HM_OK) {
        hm_error("change routine attribute failed\n");
        return HM_ERROR;
    }

    return HM_OK;
}

static void lib_tee_task_entry(void *handle, uint32_t ca_pid, int32_t priority, const char *task_name, void *libtee)
{
    struct ta_routine_info *routine = NULL;
    ta_entry_type ta_entry = { 0 };
    uint32_t size;

    ta_entry.ta_entry = dlsym(libtee, "tee_task_entry");
    if (ta_entry.ta_entry == NULL) {
        hm_error("get task entry failed: %s\n", dlerror());
        return;
    }

    /* cannot be overflow */
    size = PAGE_ALIGN_UP(sizeof(*routine));
    /* first param set as 0 means no specific address, set fd as -1 means no specific fd */
    routine = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (routine == MAP_FAILED) {
        hm_error("map for routine failed\n");
        return;
    }

    if (memset_s(routine, size, 0, size) != EOK) {
        hm_error("clear routine failed\n");
        goto err_out;
    }

    if (get_routine_info(handle, size, routine) != HM_OK)
        goto err_out;

    tee_task_entry_mt(ta_entry, ca_pid, priority, task_name, routine);

    /* tee_task_entry should never return */
    hm_panic("tee task entry returns\n");

err_out:
    if (munmap(routine, size) != HM_OK)
        hm_error("free routine failed\n");
}

static void ta_tee_task_entry(ta_entry_type ta_entry, uint32_t ca_pid, int32_t priority, const char *task_name)
{
    hm_info("ta link elf_main_entry\n");

    tee_task_entry_mt(ta_entry, ca_pid, priority, task_name, NULL);

    /* tee_task_entry should never return */
    hm_panic("tee task entry returns\n");
}

static void load_dyn_client(char *client)
{
    uint32_t size = CLIENT_NAME_SIZE * MAX_DYN_CLIENT_NUM;
    if (strnlen(client, size - 1) != size - 1)
        return;

    for (uint32_t i = 0; i < size; i++) {
        if (client[i] == '#')
            client[i] = 0;
    }

    char per_client_name[CLIENT_NAME_SIZE + 1] = {0};
    for (uint32_t i = 0; i < MAX_DYN_CLIENT_NUM; i++) {
        if (memcpy_s(per_client_name, sizeof(per_client_name),
            client + i * CLIENT_NAME_SIZE, CLIENT_NAME_SIZE) != 0)
            continue;

        if (strlen(per_client_name) == 0)
            continue;

        hm_info("load_dyn_client client_name:%s\n", per_client_name);
        (void)dlopen(per_client_name, RTLD_NOW | RTLD_GLOBAL | RTLD_TA);
        (void)memset_s(per_client_name, sizeof(per_client_name), 0, sizeof(per_client_name));
    }
}

static void tee_task_handle(const char * const *argv, const struct env_param *param, void *libtee)
{
    ta_entry_type ta_entry = { 0 };

    load_dyn_client((char *)argv[ARGV_CLIENT_NAME_INDEX]);

    /* Load TA in dlopen, will call init_array func */
    void *handle = dlopen(argv[ARGV_TASK_PATH_INDEX], RTLD_NOW | RTLD_GLOBAL | RTLD_TA);
    if (handle == NULL) {
        hm_error("dlopen %s failed: %s\n", argv[ARGV_TASK_PATH_INDEX], dlerror());
        return;
    }

    /* elf symbol reloc */
    ta_entry.ta_entry_orig = dlsym(handle, "tee_task_entry");
    /* TA has tee_task_entry */
    if (ta_entry.ta_entry_orig != NULL)
        ta_tee_task_entry(ta_entry, param->ca, param->priority, argv[ARGV_TASK_NAME_INDEX]);
    else
        lib_tee_task_entry(handle, param->ca, param->priority, argv[ARGV_TASK_NAME_INDEX], libtee);

    dlclose(handle);
}

#define DRV_FUNC_SYMBOL_APPEND 9U /* reserved mem for "g_driver_" string */
static struct tee_driver_module *dlsym_drv_func(void *drv_handle, const char *drv_name)
{
    char symbol_name[DRV_NAME_MAX_LEN + DRV_FUNC_SYMBOL_APPEND] = {0};
    if (snprintf_s(symbol_name, sizeof(symbol_name), sizeof(symbol_name) - 1, "%s%s", "g_driver_", drv_name) <= 0) {
        hm_error("get symbol_name failed\n");
        return NULL;
    }

    struct tee_driver_module *drv_func = dlsym(drv_handle, symbol_name);
    if (drv_func == NULL) {
        hm_error("cannot get drv func:%s\n", symbol_name);
        return NULL;
    }

    return drv_func;
}

static void drv_task_handle(const char * const * argv, const struct env_param *param, void *libtee, cref_t drv_channel)
{
    void *drv_so_handle = NULL;
    void *drv_handle = NULL;
    void (*use_tid_flag)(void) = NULL;

    use_tid_flag = dlsym(libtee, "set_log_use_tid_flag");
    if (use_tid_flag != NULL) {
        use_tid_flag();
    } else {
        hm_error("cannot set use tid log flag\n");
        goto drv_err;
    }

    hm_debug("target_type is %u elf_path:%s task_name:%s\n", param->target_type, argv[ARGV_TASK_PATH_INDEX],
        argv[ARGV_TASK_NAME_INDEX]);

    drv_so_handle = dlopen(g_drv_so_path, RTLD_NOW | RTLD_GLOBAL);
    if (drv_so_handle == NULL) {
        hm_error("load %s failed %s\n", g_drv_so_path, dlerror());
        goto drv_err;
    }

    drv_entry_func drv_entry = dlsym(drv_so_handle, "tee_drv_entry");
    if (drv_entry == NULL) {
        hm_error("cannot get tee drv entry\n");
        goto drv_err;
    }

    drv_handle = dlopen(argv[ARGV_TASK_PATH_INDEX], RTLD_NOW | RTLD_GLOBAL | RTLD_TA);
    if (drv_handle == NULL) {
        hm_error("dlopen drv:%s failed %s\n", argv[ARGV_TASK_PATH_INDEX], dlerror());
        goto drv_err;
    }

    /* check in drv_entry */
    struct tee_driver_module *drv_func = dlsym_drv_func(drv_handle, argv[ARGV_TASK_NAME_INDEX]);
    if (drv_func == NULL)
        goto drv_err;

    drv_entry(drv_func, argv[ARGV_TASK_NAME_INDEX], drv_channel, param);

    hm_panic("drv entry return, something wrong\n");

drv_err:
    if (drv_so_handle != NULL)
        dlclose(drv_so_handle);

    if (drv_handle != NULL)
        dlclose(drv_handle);
}

__attribute__((visibility("default"))) int32_t main(int32_t argc, const char * const * argv)
{
    bool free_uncommit = true;
    struct env_param param = { 0 };
    void *libtee = NULL;
    cref_t drv_channel = 0;

    if (param_check(argc, argv, &free_uncommit) != HM_OK) {
        hm_error("param check failed\n");
        goto err_out;
    }

    if (get_env_param(&param) != 0)
        goto err_out;

    /* task context initialization */
    if (init1(argv[ARGV_TASK_NAME_INDEX], &param, free_uncommit, &drv_channel) != HM_OK)
        goto err_out;

    /* load tee library and init it */
    if (library_init(argv[ARGV_TASK_NAME_INDEX], free_uncommit, &param, &libtee) != HM_OK)
        goto err_out;

    if (param.target_type == DRV_TARGET_TYPE) {
        drv_task_handle(argv, &param, libtee, drv_channel);
    } else {
        /* A parameter is added for transferring the client name during dynamic service loading */
        if (argc < ARGV_MAX - 1) {
            hm_error("invalid argc %d", argc);
            goto err_out;
        }

        tee_task_handle(argv, &param, libtee);
    }

err_out:
    load_fail(param.target_type);
    return HM_ERROR;
}
