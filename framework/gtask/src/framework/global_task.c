/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TEE's dispatch service
 * Author: Zhangdeyao  zhangdeyao@huawei.com
 * Create: 2019-12-20
 */

#include <stddef.h>
#include <msg_ops.h>
#include <tee_config.h>
#include "securec.h"
#include "ta_framework.h"
#include "gtask_inner.h"
#include "mem_manager.h"
#include "session_manager.h"
#include "agent_manager.h"
#include "service_manager.h"
#include "global_task.h"
#include "tee_log.h"
#include "tee_app_load_srv.h"
#include "tee_property_api.h"
#include "timer_export.h"
#include <sys/usrsyscall.h>
#include <sys/teecall.h>
#include <hmlog.h>
#include <hm_mman.h>
#include "tee_init.h"
#include <string.h>
#include <ipclib.h>
#include "tee_service.h"
#include "init.h"
#include "initlib.h"
#include "gtask_config.h"

#include "gtask_adapt.h"
#include "dynload.h"
#include "task_adaptor_pub.h"
#include "tee_property_inner.h"
#include "tee_ext_api.h"
#include "tee_task_exception.h"
#include "tee_ns_cmd_dispatch.h"
#include "tee_s_cmd_dispatch.h"
#include "tee_compat_check.h"

#define GT_MSG_REV_SIZE 512

/* From 1970 to 2050 */
#define SYSTIME_SET_MAX            ((2050U - 1970U) * 365U * 24U * 60U * 60U)
#define PHY_ADDR_HIGHER_BITS_INDEX 3
#define PHY_ADDR_LOWER_BITS_INDEX  1
#define SMC_CMD_RESULT_INDEX       0
#define SMC_CMD_ADDR_INDEX         1
#define SMC_CMD_TYPE_INDEX         2
#define SMC_CMD_ADDR_TRANS_INDEX   3

static kernel_shared_varibles_t g_k_variables;

static nwd_cmd_t *g_nwd_cmd = NULL;

/* It can be modified only by gtask, we can use it to check if the bitmap
 * in g_nwd_cmd is right. */
static DECLEAR_BITMAP(cmd_doing_bitmap, MAX_SMC_CMD);

static uint32_t g_systime_set_flag = 0;

static void acquire_smc_buf_lock(uint32_t *lock)
{
    int rc;
    rc = hmex_disable_local_irq(get_sysctrl_ref(), hm_tcb_get_cref());
    if (rc != 0)
        hm_panic("hmex_disable_local_irq failed: %s\n", hmapi_strerror(rc));
    do
        rc = __sync_bool_compare_and_swap(lock, 0, 1);
    while (!rc);
    asm volatile("dmb sy");
}

static void release_smc_buf_lock(uint32_t *lock)
{
    int rc;
    asm volatile("dmb sy");
    *lock = 0;
    asm volatile("dmb sy");
    rc = hmex_enable_local_irq(get_sysctrl_ref(), hm_tcb_get_cref());
    if (rc != 0)
        hm_panic("hmex_enable_local_irq failed: %s\n", hmapi_strerror(rc));
}

/*
 * start internal service tasks
 */
static void init_internal_tasks(void)
{
    /* load all internal tasks */
    load_internal_task(LOAD_ALL_TASKS);

    task_adapt_init();
}

/*
 * setup smc cmd shared mem for TEE
 */
static void init_smc_cmd_mem(void)
{
    bool init_done = false;
    int ret;

    /* Setup the shared buffer for communication
     * between tzdriver and global task */
    while (!init_done) {
        (void)ipc_msg_rcv(OS_WAIT_FOREVER, (uint32_t *)NULL, NULL, 0);

        tlogd("initializing...\n");
        /* the smc cmd mem setup params from REE received */
        ret = tee_pull_kernel_variables(&g_k_variables);
        if (ret != 0) {
            tloge("pullKernelVariables failed...\n");
            continue;
        }

        tlogd("init cmd: 0x%x 0x%x 0x%llx...\n", g_k_variables.params_stack[SMC_CMD_ADDR_INDEX],
              g_k_variables.params_stack[SMC_CMD_TYPE_INDEX], g_k_variables.params_stack[SMC_CMD_ADDR_TRANS_INDEX]);

        /* setup the smc cmd mem in TEE */
        if (g_k_variables.params_stack[SMC_CMD_TYPE_INDEX] == CMD_TYPE_SECURE_CONFIG) {
            /* init g_nwd_cmd */
            paddr_t tmp_phy = g_k_variables.params_stack[PHY_ADDR_LOWER_BITS_INDEX] |
                              ((paddr_t)g_k_variables.params_stack[PHY_ADDR_HIGHER_BITS_INDEX] << SHIFT_OFFSET);
            g_nwd_cmd = map_ns_cmd(tmp_phy);
            if (g_nwd_cmd == NULL) {
                tloge("map ns memory failed\n");
                continue;
            }

            init_done                       = true;
        }
    }
}

static void setup_init_info(void)
{
    generate_teeos_compat_level(((uint32_t *)(void *)g_nwd_cmd->in),
        COMPAT_LEVEL_BUF_LEN);
}

bool is_abort_cmd(const smc_cmd_t *cmd)
{
    if (cmd == NULL)
        return false;

    if (cmd->cmd_type == CMD_TYPE_GLOBAL && cmd->cmd_id == GLOBAL_CMD_ID_KILL_TASK)
        return true;

    return false;
}

void restore_cmd_in(const smc_cmd_t *cmd)
{
    uint32_t index;

    if (cmd == NULL)
        return;

    index = cmd->event_nr;
    if (index >= MAX_SMC_CMD) {
        tloge("invalid idex: %u\n", index);
        return;
    }

    acquire_smc_buf_lock(&g_nwd_cmd->smc_lock);
    if (index != g_nwd_cmd->in[index].event_nr) {
        tloge("event_nr not match, %u/%u\n", index, g_nwd_cmd->in[index].event_nr);
        release_smc_buf_lock(&g_nwd_cmd->smc_lock);
        return;
    }

    if (memcpy_s(&g_nwd_cmd->in[index], sizeof(smc_cmd_t), cmd, sizeof(smc_cmd_t)) != EOK)
        tloge("copy restore cmd failed\n");
    release_smc_buf_lock(&g_nwd_cmd->smc_lock);
}

static int get_last_in_cmd(smc_cmd_t *cmd)
{
    errno_t rc = EOK;
    int ret    = GT_ERR_END_CMD;
    static uint32_t last_index = MAX_SMC_CMD;
    uint32_t i = last_index;

    acquire_smc_buf_lock(&g_nwd_cmd->smc_lock);
    do {
        if (i == MAX_SMC_CMD)
            i = 0;
        if (hm_test_bit(i, g_nwd_cmd->in_bitmap) && !hm_test_bit(i, g_nwd_cmd->doing_bitmap)) {
            if (hm_test_bit(i, cmd_doing_bitmap) && !is_abort_cmd(&g_nwd_cmd->in[i])) {
                /* in this case, maybe the in_bitmap/doing_bitmap in g_nwd_cmd
                 * was modified by malicious, so we will skip this cmd. */
                tloge("find a unreasonable in-cmd, cmd id=0x%x, cmd type=%u\n",
                    g_nwd_cmd->in[i].cmd_id, g_nwd_cmd->in[i].cmd_type);
                hm_set_bit(i, g_nwd_cmd->doing_bitmap);
                /* skip this cmd */
                continue;
            }

            rc = memcpy_s(cmd, sizeof(smc_cmd_t), &g_nwd_cmd->in[i], sizeof(smc_cmd_t));
            if (rc != EOK) {
                break;
            }

            /* check if cmd->event_nr is compatible the index in bitmap */
            if (cmd->event_nr != i) {
                tloge("it's a invalid cmd, event_nr/bitmap=%u/%u\n", cmd->event_nr, i);
                hm_set_bit(i, g_nwd_cmd->doing_bitmap);
                /* skip this cmd */
                continue;
            }

            __asm__ volatile("isb");
            __asm__ volatile("dsb sy");
            hm_set_bit(i, g_nwd_cmd->doing_bitmap);
            if (!is_abort_cmd(&g_nwd_cmd->in[i]))
                hm_set_bit(i, cmd_doing_bitmap);

            last_index = i + 1;
            ret = GT_ERR_OK;
            break;
        }
        i++;
    } while (i != last_index);
    release_smc_buf_lock(&g_nwd_cmd->smc_lock);
    if (rc != EOK) {
        tloge("memcopy in cmd failed\n");
        ret = GT_ERR_END_CMD;
    }
    if (cmd->event_nr >= MAX_SMC_CMD) {
        tloge("invalid event_nr: %u\n", cmd->event_nr);
        ret = GT_ERR_END_CMD;
    }

    return ret;
}

int put_last_out_cmd(const smc_cmd_t *cmd)
{
    errno_t rc;

    if (cmd == NULL)
        return GT_ERR_END_CMD;

    if (cmd->event_nr >= MAX_SMC_CMD) {
        tloge("invalid event_nr: %u\n", cmd->event_nr);
        return GT_ERR_END_CMD;
    }
    /* when ta session return to REE, need to umap ca2ta releation; otherwise when ca crash may kill wrong ta session */
    if ((cmd->ret_val != TEE_PENDING) && (cmd->ret_val != TEE_PENDING2)) {
        if (g_cur_session != NULL)
            g_cur_session->cmd_in.ca_pid = 0;
    }
    acquire_smc_buf_lock(&g_nwd_cmd->smc_lock);

    rc = memcpy_s(&g_nwd_cmd->out[cmd->event_nr], sizeof(smc_cmd_t), cmd, sizeof(smc_cmd_t));
    if (rc) {
        release_smc_buf_lock(&g_nwd_cmd->smc_lock);
        tloge("memcpy out cmd failed\n");
        return GT_ERR_END_CMD;
    }
    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");
    hm_set_bit(cmd->event_nr, g_nwd_cmd->out_bitmap);
    hm_clear_bit(cmd->event_nr, cmd_doing_bitmap);
    release_smc_buf_lock(&g_nwd_cmd->smc_lock);

    return GT_ERR_OK;
}

void ns_cmd_response(smc_cmd_t *cmd)
{
    if (cmd == NULL)
        return;

    if (cmd->ret_val != TEE_PENDING) {
        TEE_Result ret = copy_pam_to_src(cmd->cmd_id, false);
        if (ret)
            cmd->ret_val = ret;

        ret = unmap_ns_operation(cmd);
        if (ret != TEE_SUCCESS)
            tloge("ns cmd unmap ns fail:%08X\n", ret);
    }

    errno_t ret_i = put_last_out_cmd(cmd);
    if (ret_i != GT_ERR_OK)
        tloge("ns cmd put fail:%d\n", ret_i);
}

TEE_Result handle_time_adjust(const smc_cmd_t *cmd)
{
    TEE_Result ret;
    tee_time_kernel time;
    uint32_t param_type = 0;
    TEE_Param *params = NULL;

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (g_systime_set_flag) {
        tlogd("The time seems already been adjusted");
        return TEE_SUCCESS;
    }

    if (cmd_global_ns_get_params(cmd, &param_type, &params) != TEE_SUCCESS) {
        tloge("cmd_global_ns_get_params failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    time.seconds = params->value.a;
    time.millis = params->value.b;
    if ((uint32_t)time.seconds <= SYSTIME_SET_MAX) {
#ifdef CONFIG_OFF_DRV_TIMER
        ret = teecall_cap_time_sync(time.seconds, time.millis);
#else
        ret = adjust_sys_time(&time);
#endif
        if (ret != TEE_SUCCESS)
            return ret;

        g_systime_set_flag = 1;
    } else {
        tloge("time adjust failed\n");
        ret = TEE_ERROR_GENERIC;
    }

    return ret;
}

/*
 * handle open_session cmds which is called from process_ta_common_cmd
 * just for Complexity check.
 * DO NOT USE this func in anyother situations. w00414120.
 */
extern struct service_struct *g_cur_service;
static TEE_Result processs_opensession(smc_cmd_t *cmd, uint32_t cmd_type, uint32_t task_id, bool *async,
                                       const struct ta2ta_info_t *ta2ta_info)
{
    TEE_Result ret;
    uint32_t userid = 0;

    ret = open_session(cmd, cmd_type, task_id, ta2ta_info);
    if (ret == TEE_SUCCESS) {
        *async = true;

        if (g_cur_session->cmd_type == CMD_TYPE_NS_TO_SECURE) {
            /*
             * here restore cmd is to save cmd->context, if TA open session is stuck,
             * we need context to find the stuck session to kill TA
             */
            restore_cmd_in(cmd);

            userid = g_cur_session->cmd_in.uid / PER_USER_RANGE;
        }

        task_adapt_register_ta(g_cur_session->task_id, userid, g_cur_service->property.ssa_enum_enable,
                               &g_cur_service->property.uuid);
    }

    return ret;
}

/*
 * handle both ca2ta and ta2ta cmds
 */
TEE_Result process_ta_common_cmd(smc_cmd_t *cmd, uint32_t cmd_type, uint32_t task_id, bool *async,
                                 const struct ta2ta_info_t *ta2ta_info)
{
    TEE_Result ret;
    bool sync = false;
    uint32_t cmd_id;

    if (cmd == NULL || async == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    cmd_id = cmd->cmd_id;
    switch (cmd_id) {
    case GLOBAL_CMD_ID_OPEN_SESSION:
        if (cmd_type == CMD_TYPE_SECURE_TO_SECURE) {
            tlogd("ta2ta is running\n");
            if (g_cur_service == NULL) {
                tloge("cur service is null\n");
                return TEE_ERROR_BAD_PARAMETERS;
            }
        }
        ret = processs_opensession(cmd, cmd_type, task_id, async, ta2ta_info);
        break;
    case GLOBAL_CMD_ID_CLOSE_SESSION:
        ret = close_session(cmd, cmd_type, &sync);
        if (ret == TEE_SUCCESS && false == sync)
            *async = true;
        break;
    default:
        ret = TEE_ERROR_INVALID_CMD;
        break;
    }

    return ret;
}

static uint32_t tee_get_max_api_level(void)
{
    uint32_t value = 0;

    if (TEE_GetPropertyAsU32(TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.api_level", &value) != TEE_SUCCESS)
        return TEE_MAX_API_LEVEL_CONFIG;

    return value;
}

TEE_Result get_tee_version(const smc_cmd_t *cmd)
{
    unsigned int version;
    uint32_t param_type  = 0;
    TEE_Param *params    = NULL;

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (cmd_global_ns_get_params(cmd, &param_type, &params) != TEE_SUCCESS) {
        tloge("cmd_global_ns_get_params failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
    if (TEE_PARAM_TYPE_GET(param_type, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT) {
        tloge("Bad expected parameter types: 0x%x\n", TEE_PARAM_TYPE_GET(param_type, 0));
        return TEE_ERROR_BAD_PARAMETERS;
    }
    version         = tee_get_max_api_level();
    params->value.a = version;

    return TEE_SUCCESS;
}

TEE_Result process_load_image(smc_cmd_t *cmd, bool *async)
{
    TEE_Result ret;

    ret = load_secure_file_image(cmd, async);
    if (ret == TEE_ERROR_IMG_VERIFY_FAIL || ret == TEE_ERROR_IMG_PARSE_FAIL || ret == TEE_ERROR_IMG_ELF_LOAD_FAIL ||
        ret == TEE_ERROR_IMG_DECRYPTO_FAIL)
        tloge("load_secure_app_image failed\n");
    return ret;
}

static int check_ns_cmd(smc_cmd_t *cmd)
{
    TEE_Result ret;

    /* check phy_addr in smc_cmd is in mailbox or not */
    ret = check_cmd_in_mailbox_range(cmd);
    if (ret != TEE_SUCCESS) {
        tloge("mailbox check failed, cmd type=%u, cmd id=%u, ret = 0x%x\n",
            cmd->cmd_type, cmd->cmd_id, ret);
        goto error;
    }

    ret = init_ta_context(cmd);
    if (ret != TEE_SUCCESS) {
        tloge("init TA context failed, cmd type=%u, cmd id=%u, ret = 0x%x\n",
            cmd->cmd_type, cmd->cmd_id, ret);
        goto error;
    }

    return GT_ERR_OK;

error:
    cmd->ret_val = ret;
    if (put_last_out_cmd(cmd) != GT_ERR_OK)
        tloge("put last out cmd fail\n");
    return GT_ERR_END_CMD;
}

static int handle_ns_cmd()
{
    int gt_err_ret;
    smc_cmd_t cmd;

    (void)memset_s(&cmd, sizeof(cmd), 0, sizeof(cmd));
    /* get lastest smc cmd from smc mem */
    gt_err_ret = get_last_in_cmd(&cmd);
    if (gt_err_ret != GT_ERR_OK)
        return gt_err_ret;

    set_tee_return_origin(&cmd, TEE_ORIGIN_TEE);

    if (cmd.cmd_type == CMD_TYPE_BUILDIN_AGENT)
        return handle_service_agent_back_cmd(&cmd);

    if (cmd.cmd_type == CMD_TYPE_TA_AGENT ||
        cmd.cmd_type == CMD_TYPE_TA2TA_AGENT)
        return handle_ta_agent_back_cmd(&cmd);

    if (cmd.cmd_type == CMD_TYPE_GLOBAL && cmd.cmd_id == GLOBAL_CMD_ID_KILL_TASK)
        return handle_kill_task(&cmd);

    gt_err_ret = check_ns_cmd(&cmd);
    if (gt_err_ret != GT_ERR_OK)
        return gt_err_ret;

    if (dispatch_ns_cmd(&cmd) != TEE_SUCCESS)
        return GT_ERR_END_CMD;

    return GT_ERR_OK;
}

static int is_cmd_in_unproceed(void)
{
    uint32_t i;
    int ret = 0;

    acquire_smc_buf_lock(&g_nwd_cmd->smc_lock);
    for (i = 0; i < MAX_SMC_CMD; i++) {
        if (hm_test_bit(i, g_nwd_cmd->in_bitmap) && !hm_test_bit(i, g_nwd_cmd->doing_bitmap)) {
            ret = 1;
            break;
        }
    }
    release_smc_buf_lock(&g_nwd_cmd->smc_lock);

    return ret;
}

static int32_t gtask_main_init(void)
{
    if (ta_framework_init()) {
        tloge("ta_framework init failed\n");
        while (1)
            hm_yield();
    }
    init_tee_service();
    init_internal_tasks();
#ifdef __aarch64__
    tlogi("Gtask (64bit) Execute Successfully and jump to Linux kernel\n");
#else
    tlogi("Gtask Execute Successfully and jump to Linux kernel\n");
#endif

    init_smc_cmd_mem();
    setup_init_info();

    return GT_ERR_OK;
}

bool is_ns_cmd(uint32_t task_id, uint32_t back_cmd)
{
    (void)back_cmd;
    if (pid_to_hmpid(task_id) == SMCMGR_PID)
        return true;
    return false;
}

void gtask_main(void)
{
    TEE_Result ret;
    uint32_t back_cmd;
    uint32_t task_id;
    tlogd("global TEETaskEntry start\n");

    if (gtask_main_init() != GT_ERR_OK)
        return;

    while (1) {
        uint8_t buffer[GT_MSG_REV_SIZE] = { 0 };

        reset_ta_context();
        back_cmd = 0;
        task_id  = TASK_ID_NULL;

        /* We still have incomming notifications, don't block yet */
        if (is_cmd_in_unproceed()) {
            if (ipc_msg_rcv_a(0, (uint32_t *)(&back_cmd), buffer, GT_MSG_REV_SIZE, &task_id)) {
                task_id  = SMCMGR_PID;
                back_cmd = 0;
                tlogd("Still having incoming notifications\n");
            }
        } else {
            ret = ipc_msg_rcv_a(OS_WAIT_FOREVER, (uint32_t *)(&back_cmd), buffer, GT_MSG_REV_SIZE, &task_id);
            if (ret != 0) {
                tloge("global_task rcv error %x\n", ret);
                continue;
            }
        }

        tlogd("received back cmd =%x, task_id=%d\n", back_cmd, task_id);

        /* tzdriver SIQ schedule is not needed NOW */
        if (is_ns_cmd(task_id, back_cmd)) {
            /* handle cmd from ree */
            (void)handle_ns_cmd();
        } else {
            /* handle cmd from tee */
            (void)handle_s_cmd(back_cmd, task_id, buffer, GT_MSG_REV_SIZE);
        }
    }
}
