/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee common public service implementation
 * Author:yanruiqing
 * Create: 2022-01-07
 */

#include "tee_dynamic_srv.h"
#include <sys/mman.h>
#include <msg_ops.h>
#include <mem_ops_ext.h>
#include <sys/usrsyscall_ext.h>
#include <sys/hmapi_ext.h>
#include <api/kcalls.h>
#include <sys/time.h>
#include "timer_export.h"
#include <procmgr_ext.h>
#include <pthread.h>
#include "tee_init.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "securec.h"
#include "ipclib.h"
#include "tee_internal_task_pub.h"
#include "sys_timer.h"
#include "lib_timer.h"
#include "hmlog.h"

TEE_Result tee_srv_get_uuid_by_sender(uint32_t sender, TEE_UUID *uuid)
{
    spawn_uuid_t sender_uuid;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    int32_t ret = hm_getuuid((pid_t)pid_to_hmpid(sender), &sender_uuid);
    if (ret != 0) {
        tloge("get uuid from hm failed, sender is 0x%x\n", sender);
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    errno_t rc = memcpy_s(uuid, sizeof(*uuid), &sender_uuid.uuid, sizeof(sender_uuid.uuid));
    if (rc != EOK) {
        tloge("copy uuid to dest failed, rc=%d\n", rc);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

int tee_srv_map_from_task(uint32_t in_task_id, uint32_t va_addr, uint32_t size, uint32_t *virt_addr)
{
    uint64_t vaddr = 0;
    int ret;

    if (virt_addr == NULL)
        return -1;

    ret = tee_map_sharemem(in_task_id, va_addr, size, &vaddr);
    if (ret == 0)
        *virt_addr = (uint32_t)vaddr;
    else
        *virt_addr = 0;

    return ret;
}

void tee_srv_unmap_from_task(uint32_t va_addr, uint32_t size)
{
    (void)munmap((void *)(uintptr_t)va_addr, size);
}

/* msg can be null, which means we do not care return msg */
static void tee_task_entry_wait_msg(uint32_t want_cmd, uint8_t *msg, uint32_t size, uint32_t want_sdr)
{
    uint32_t recv_cmd;
    uint32_t sender;
    uint32_t cp_size;
    uint8_t ret_msg[sizeof(tee_service_ipc_msg)];

    while (1) {
        recv_cmd = 0;
        sender = 0;
        (void)memset_s(ret_msg, sizeof(ret_msg), 0, sizeof(ret_msg));

        uint32_t ret = (uint32_t)ipc_msg_rcv_a(OS_WAIT_FOREVER, (uint32_t *)(&recv_cmd),
                                               ret_msg, sizeof(ret_msg), &sender);
        if (ret != SRE_OK) {
            tloge("msg rcv error %x\n", ret);
            continue;
        }

        if (recv_cmd == want_cmd && sender == want_sdr) {
            cp_size = (size < sizeof(ret_msg)) ? size : sizeof(ret_msg);
            errno_t rc = memmove_s(msg, size, ret_msg, cp_size);
            if (rc != EOK)
                tloge("copy msg, size %u error, ret %x\n", cp_size, rc);
            break;
        }
        tloge("receive unexpected msg 0x%x from 0x%x\n", recv_cmd, sender);
    }
}

static TEE_Result set_service_caller_info(uint32_t task_id, uint32_t cmd)
{
    uint32_t ret;
    struct task_caller_info caller_serv_info;

    caller_serv_info.taskid = task_id;
    caller_serv_info.cmd = cmd;
    ret = ipc_msg_snd(TEE_TASK_SET_CALLER_INFO, get_global_handle(), &caller_serv_info, sizeof(caller_serv_info));
    if (ret != SRE_OK) {
        tloge("send caller info failed 0x%x\n", ret);
        return TEE_ERROR_COMMUNICATION;
    }

    tee_task_entry_wait_msg(TEE_TASK_SET_CALLER_INFO_ACK, (uint8_t *)&ret, sizeof(ret), get_global_handle());
    if (ret != TEE_SUCCESS) {
        tloge("set callerinfo fail, recv_ret:0x%x", ret);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static void do_deal_with_msg(const struct srv_dispatch_t *dispatch, uint32_t n_dispatch,
    struct tee_service_ipc_msg_req *req_msg, tee_service_ipc_msg_rsp *rsp_msg, uint32_t task_id)
{
    tlogd("receive cmd:%d, n_dispatch:%d", req_msg->cmd, n_dispatch);

    for (uint32_t i = 0; i < n_dispatch; i++) {
        if (dispatch[i].cmd == req_msg->cmd) {
            dispatch[i].fn(&(req_msg->msg), task_id, rsp_msg);
            return;
        }
    }

    rsp_msg->ret = TEE_ERROR_BAD_PARAMETERS;
}

#ifdef DYN_SRV_MULTI_THREAD_DISABLE

static int32_t get_ipc_native_args(const char *task_name, struct tee_service_ipc_msg_req *req_msg,
    struct channel_ipc_args *ipc_args)
{
    cref_t ch = 0;

    int32_t ret = hm_create_ipc_native(task_name, &ch);
    if (ret != 0) {
        tloge("create ipc channel failed, ret=%d\n", ret);
        return ret;
    }

    ipc_args->channel = ch;
    ipc_args->recv_buf = req_msg;
    ipc_args->recv_len = (unsigned long)sizeof(*req_msg);
    return 0;
}

static void tee_srv_dispatch(const char *task_name, const struct srv_dispatch_t *dispatch, uint32_t n_dispatch)
{
    cref_t msghdl;
    uint32_t task_id;
    struct hmcap_message_info info = { 0 };
    struct tee_service_ipc_msg_req req_msg;
    tee_service_ipc_msg_rsp rsp_msg;
    struct channel_ipc_args ipc_args = { 0 };

    msghdl = hmapi_create_message();
    if (is_ref_err(msghdl)) {
        tloge("create msg hdl failed\n");
        return;
    }

    int32_t ret = get_ipc_native_args(task_name, &req_msg, &ipc_args);
    if (ret != 0)
        return;

    while (1) {
        ret = hmapi_recv_timeout(&ipc_args, &msghdl, 0, HM_NO_TIMEOUT, &info);
        if (ret < 0) {
            tloge("message receive failed, ret=0x%x, reason:%s\n", ret, hmapi_strerror(ret));
            continue;
        }

        task_id = (uint32_t)hmpid_to_pid(TCBCREF2TID(info.src_tcb_cref), info.src_cred.pid);
        if (info.src_cred.pid != get_global_handle()) {
            if (set_service_caller_info(task_id, req_msg.cmd) != TEE_SUCCESS)
                tloge("failed to set caller info, task id 0x%x, cmd 0x%x\n", task_id, req_msg.cmd);
        }

        do_deal_with_msg(dispatch, n_dispatch, &req_msg, &rsp_msg, task_id);

        if (info.msg_type == HM_MSG_TYPE_CALL) {
            ret = hm_msg_reply(msghdl, &rsp_msg, sizeof(rsp_msg));
            if (ret != 0) {
                tloge("message reply failed, ret=0x%x, reason:%s\n", ret, hmapi_strerror(ret));
                continue;
            }
        }
    }
}

void tee_srv_cs_server_loop(const char *task_name, const struct srv_dispatch_t *dispatch, uint32_t n_dispatch,
    struct srv_thread_init_info *cur_thread)
{
    (void)cur_thread;
    if (task_name == NULL || dispatch == NULL || n_dispatch == 0) {
        tloge("param invalid\n");
        return;
    }

    tlogi("------------------enter to %s srv_cs_server_loop------------------\n", task_name);

    tee_srv_dispatch(task_name, dispatch, n_dispatch);
}
#else

#define DYNAMIC_SRV_IPC_MAX_TIMEOUT 300 // 5 min
#define DYNAMIC_SRV_THREAD_NUM 4        // 4 threads

struct srv_thd_runenv {
    const struct srv_dispatch_t *dispatch;
    uint32_t n_dispatch;
    uint32_t thread_num;
    uint32_t max_thread;
    uint32_t wait_num;
    bool init_state;
    pthread_spinlock_t num_spinlock;
    sem_t wakeup_sem;
    struct srv_thd_hdl *thd_hdl;
    cref_t channel;
    uint32_t th_stack_size;
    uint32_t time_out_sec;
};
struct srv_thd_hdl {
    unsigned long work_time;
    pthread_spinlock_t time_spin_mutex;
};

struct srv_thd_start_env {
    struct srv_thd_runenv *run_env;
    uint32_t thd_inst;
};

static int32_t create_child_thread(struct srv_thd_runenv *run_env);

static void dynamic_srv_reply(uint8_t info_msg_type, tee_service_ipc_msg_rsp *rsp_msg, cref_t *msghdl)
{
    if (info_msg_type == HM_MSG_TYPE_CALL) {
        uint32_t ret = hm_msg_reply(*msghdl, rsp_msg, sizeof(*rsp_msg));
        if (ret != 0)
            tloge("message reply failed, ret=0x%x, reason:%s\n", ret, hmapi_strerror(ret));
    }
}

static int32_t get_ipc_native_args(cref_t ch, struct tee_service_ipc_msg_req *req_msg,
    struct channel_ipc_args *ipc_args)
{
    ipc_args->channel = ch;
    ipc_args->recv_buf = req_msg;
    ipc_args->recv_len = sizeof(*req_msg);
    return 0;
}

static void wake_next_thread(struct srv_thd_runenv *run_env)
{
    if (run_env == NULL || !run_env->init_state)
        return;
    int32_t ret;
    (void)pthread_spin_lock(&run_env->num_spinlock);
    if (run_env->thread_num < run_env->max_thread && run_env->wait_num == 0) {
        ret = create_child_thread(run_env);
        if (ret != 0)
            hm_error("create child thread error ret is 0x%x\n", ret);
    } else {
        if (run_env->wait_num > 0)
            run_env->wait_num--;
        sem_post(&run_env->wakeup_sem);
        hm_yield();
    }
    (void)pthread_spin_unlock(&run_env->num_spinlock);
}

static void wait_thread(struct srv_thd_runenv *run_env)
{
    if (run_env == NULL)
        return;
    (void)pthread_spin_lock(&run_env->num_spinlock);
    run_env->wait_num++;
    (void)pthread_spin_unlock(&run_env->num_spinlock);
    (void)sem_wait(&run_env->wakeup_sem);
}

struct dynamic_srv_dispatch_data {
    cref_t msghdl;
    struct hmcap_message_info info;
    struct tee_service_ipc_msg_req req_msg;
    tee_service_ipc_msg_rsp rsp_msg;
    struct channel_ipc_args ipc_args;
    struct srv_thd_hdl *thd_hdl;
};

static int32_t tee_srv_dispatch_init(struct dynamic_srv_dispatch_data *dispatch_data,
    struct srv_thd_start_env *the_start)
{
    struct srv_thd_runenv *run_env = the_start->run_env;
    dispatch_data->thd_hdl = &((run_env->thd_hdl)[the_start->thd_inst]);
    dispatch_data->msghdl = hmapi_create_message();
    if (is_ref_err(dispatch_data->msghdl)) {
        tloge("create msg hdl failed\n");
        return -1;
    }
    int32_t ret = get_ipc_native_args(run_env->channel, &(dispatch_data->req_msg), &(dispatch_data->ipc_args));
    if (ret != 0)
        return -1;
    return 0;
}

static int32_t tee_srv_dispatch_recv_wait(struct dynamic_srv_dispatch_data *dispatch_data)
{
    int32_t ret = hmapi_recv_timeout(&(dispatch_data->ipc_args), &(dispatch_data->msghdl), 0, HM_NO_TIMEOUT,
        &(dispatch_data->info));
    if (ret < 0) {
        tloge("message receive failed, ret=0x%x, reason:%s\n", ret, hmapi_strerror(ret));
        return ret;
    }
    return ret;
}

static void dynamic_srv_thread_do_work(struct dynamic_srv_dispatch_data *data, const struct srv_thd_runenv *run_env)
{
    (void)pthread_spin_lock(&(data->thd_hdl)->time_spin_mutex);
    struct timeval curtime;
    if (gettimeofday(&curtime, NULL) != 0) {
        tloge("tee dynamic srv worker, get time of day failed.\n");
        (void)pthread_spin_unlock(&(data->thd_hdl)->time_spin_mutex);
        return;
    }
    (data->thd_hdl)->work_time = curtime.tv_sec;
    (void)pthread_spin_unlock(&(data->thd_hdl)->time_spin_mutex);

    uint32_t task_id = (uint32_t)hmpid_to_pid(TCBCREF2TID((data->info).src_tcb_cref), (data->info).src_cred.pid);
    uint32_t info_pid = (data->info).src_cred.pid;

    if (info_pid != get_global_handle()) {
        if (set_service_caller_info(task_id, (data->req_msg).cmd) != TEE_SUCCESS)
            tloge("failed to set caller info, task id 0x%x, cmd 0x%x\n", task_id, (data->req_msg).cmd);
    }
    do_deal_with_msg(run_env->dispatch, run_env->n_dispatch, &(data->req_msg), &(data->rsp_msg), task_id);

    dynamic_srv_reply((data->info).msg_type, &data->rsp_msg, &(data->msghdl));

    (void)pthread_spin_lock(&(data->thd_hdl)->time_spin_mutex);
    (data->thd_hdl)->work_time = 0;
    (void)pthread_spin_unlock(&(data->thd_hdl)->time_spin_mutex);
}

static void *tee_srv_dispatch(void *data)
{
    struct srv_thd_start_env *the_start = (struct srv_thd_start_env *)data;

    struct srv_thd_runenv *run_env = the_start->run_env;
    struct dynamic_srv_dispatch_data dispatch_data;
    int32_t ret = tee_srv_dispatch_init(&dispatch_data, the_start);

    while (1) {
        ret = tee_srv_dispatch_recv_wait(&dispatch_data);
        tlogi("tee dyanmic srv, thread of working , id:%d \n", the_start->thd_inst);
        if (ret < 0) {
            tloge("message receive failed, ret=0x%x, reason:%s\n", ret, hmapi_strerror(ret));
            continue;
        }
        if (ret == 0)
            wake_next_thread(run_env);
        dynamic_srv_thread_do_work(&dispatch_data, run_env);
        if (ret == 0)
            wait_thread(run_env);
    }
    return NULL;
}

#define DYNAMIC_SRV_THREAD_STACK (16 * 4096)
static TEE_Result dynamic_srv_create_thread(void *(*thread_entry)(void *), void *thd_para, uint32_t stack_size)
{
    pthread_attr_t attr = { 0 };
    int32_t rc;

    /* Init pthread attr */
    if (pthread_attr_init(&attr) != 0) {
        tloge("pthread attr init failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* Set stack size for new thread */
    if (pthread_attr_setstacksize(&attr, stack_size) != 0) {
        tloge("pthread set stack failed, size = 0x%x\n", stack_size);
        return TEE_ERROR_GENERIC;
    }

    pthread_t thid;
    rc = pthread_create(&thid, &attr, thread_entry, thd_para);
    if (rc != 0) {
        tloge("create thread error 0x%x\n", rc);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result dispatch_create_thread(struct srv_thd_start_env *thd_start_info, uint32_t stack_size)
{
    return dynamic_srv_create_thread(tee_srv_dispatch, thd_start_info, stack_size);
}

#if (defined CONFIG_TIMER_DISABLE) || (defined CONFIG_OFF_DRV_TIMER)
static TEE_Result srv_thd_watcher_init(struct srv_thd_runenv *run_env)
{
    (void)run_env;
    return TEE_SUCCESS;
}
#else

#define TEE_DYANMIC_HALF_SECONDES 500
static void tee_dynamic_delay_sec(uint32_t seconds)
{
    while (seconds > 0) {
        SRE_DelayMs(TEE_DYANMIC_HALF_SECONDES);
        SRE_DelayMs(TEE_DYANMIC_HALF_SECONDES);
        seconds--;
    }
}

static void *srv_thd_watcher(void *data)
{
    if (data == NULL)
        return NULL;
    struct srv_thd_runenv *run_env = (struct srv_thd_runenv *)data;
    struct srv_thd_hdl *th_hdl = run_env->thd_hdl;
    uint32_t time_out_sec = run_env->time_out_sec;

    uint32_t thread_num;
    struct timeval curtime;

    while (1) {
        if (gettimeofday(&curtime, NULL) != 0) {
            tloge("tee dynamic srv watcher, get time of day failed.\n");
            return NULL;
        }
        (void)pthread_spin_lock(&run_env->num_spinlock);
        thread_num = run_env->thread_num;
        for (uint32_t i = 0; i < thread_num; i++) {
            pthread_spin_lock(&(th_hdl[i].time_spin_mutex));
            if ((th_hdl[i].work_time != 0) && (curtime.tv_sec - th_hdl[i].work_time > time_out_sec)) {
                tloge("tee_dynamic_srv_timer, time out, panic.\n");
                __hm_abort();
            }
            pthread_spin_unlock(&(th_hdl[i].time_spin_mutex));
        }
        (void)pthread_spin_unlock(&run_env->num_spinlock);
        tee_dynamic_delay_sec(1);
    }

    return NULL;
}

static TEE_Result srv_thd_watcher_init(struct srv_thd_runenv *run_env)
{
    return dynamic_srv_create_thread(srv_thd_watcher, run_env, run_env->th_stack_size);
}
#endif

static void thread_mgr_init(struct srv_thd_runenv *run_env, const struct srv_thread_init_info *thread,
    const char *task_name, const struct srv_dispatch_t *dispatch, uint32_t n_dispatch)
{
    if (thread == NULL || run_env == NULL || run_env->init_state)
        return;
    run_env->max_thread = thread->max_thread;
    run_env->th_stack_size = thread->stack_size;
    run_env->time_out_sec = thread->time_out_sec;
    run_env->init_state = true;
    run_env->thread_num = 1;
    run_env->wait_num = 0;
    (void)pthread_spin_init(&run_env->num_spinlock, PTHREAD_PROCESS_PRIVATE);
    (void)sem_init(&run_env->wakeup_sem, 0, 0);
    run_env->dispatch = dispatch;
    run_env->n_dispatch = n_dispatch;

    cref_t ch = 0;

    int32_t ret = hm_create_ipc_native(task_name, &ch);
    if (ret != 0) {
        tloge("create ipc channel failed, ret=%d\n", ret);
        return;
    }
    run_env->channel = ch;
}

static int32_t create_child_thread(struct srv_thd_runenv *run_env)
{
    struct srv_thd_start_env *thd_start = TEE_Malloc(sizeof(struct srv_thd_start_env), 0);
    if (thd_start == NULL) {
        tloge("tee dyn srv, create child thread, malloc failed");
        return -1;
    }
    thd_start->run_env = run_env;
    thd_start->thd_inst = run_env->thread_num;
    (void)pthread_spin_init(&((run_env->thd_hdl)[run_env->thread_num].time_spin_mutex), PTHREAD_PROCESS_PRIVATE);
    dispatch_create_thread(thd_start, run_env->th_stack_size);
    run_env->thread_num++;
    return 0;
}

struct srv_thread_init_info *init_cur_thread(struct srv_thread_init_info *cur_thread, bool *if_new_cur_thread)
{
    if (cur_thread == NULL) {
        *if_new_cur_thread = true;
        cur_thread = TEE_Malloc(sizeof(struct srv_thread_init_info), 0);
        if (cur_thread == NULL) {
            tloge("tee dyn srv, server loop failed, malloc failed");
            return NULL;
        }
        cur_thread->max_thread = 1;
        cur_thread->stack_size = DYNAMIC_SRV_THREAD_STACK;
        cur_thread->time_out_sec = DYNAMIC_SRV_IPC_MAX_TIMEOUT;
    } else {
        if (cur_thread->max_thread == 0) {
            tloge("tee dyn srv, server loop failed, max_thread can't be equal to zero.\n");
            return NULL;
        }
        cur_thread->max_thread =
            (cur_thread->max_thread > DYNAMIC_SRV_THREAD_NUM ? DYNAMIC_SRV_THREAD_NUM : cur_thread->max_thread);
    }
    tlogi("tee dyn srv, server loop, max thread: %d\n", cur_thread->max_thread);
    return cur_thread;
}

struct server_loop_state {
    struct srv_thd_runenv *run_env;
    struct srv_thd_hdl *w_t;
    struct srv_thd_start_env *thd_start;
};

static int32_t init_loop_state(struct server_loop_state *l_s, uint32_t max_thread)
{
    l_s->run_env = NULL;
    l_s->w_t = NULL;
    l_s->thd_start = NULL;

    l_s->run_env = TEE_Malloc(sizeof(struct srv_thd_runenv), 0);
    if (l_s->run_env == NULL) {
        tloge("tee dyn srv, run env malloc failed");
        return -1;
    }
    l_s->w_t = TEE_Malloc(max_thread * sizeof(struct srv_thd_hdl), 0);
    if (l_s->w_t == NULL) {
        tloge("tee dyn srv, thd hdl malloc failed");
        TEE_Free(l_s->run_env);
        return -1;
    }
    l_s->thd_start = TEE_Malloc(sizeof(struct srv_thd_start_env), 0);
    if (l_s->thd_start == NULL) {
        tloge("tee dyn srv, thd start malloc failed");
        TEE_Free(l_s->run_env);
        TEE_Free(l_s->w_t);
        return -1;
    }
    (l_s->run_env)->thd_hdl = l_s->w_t;
    (l_s->run_env)->init_state = false;
    return 0;
}

void tee_srv_cs_server_loop(const char *task_name, const struct srv_dispatch_t *dispatch, uint32_t n_dispatch,
    struct srv_thread_init_info *cur_thread)
{
    if (task_name == NULL || dispatch == NULL || n_dispatch == 0) {
        tloge("dyn srv param invalid\n");
        return;
    }
    bool new_cur_thread = false;
    cur_thread = init_cur_thread(cur_thread, &new_cur_thread);
    if (cur_thread == NULL)
        return;

    struct server_loop_state l_s;
    if (init_loop_state(&l_s, cur_thread->max_thread) != 0) {
        if (new_cur_thread) {
            TEE_Free(cur_thread);
            cur_thread = NULL;
        }
        return;
    }

    thread_mgr_init(l_s.run_env, cur_thread, task_name, dispatch, n_dispatch);

    TEE_Result t_ret = srv_thd_watcher_init(l_s.run_env);
    if (t_ret != TEE_SUCCESS)
        tloge("threads watching failed\n");

    tlogi("------------------enter to %s srv_cs_server_loop------------------\n", task_name);

    (l_s.thd_start)->run_env = l_s.run_env;
    (l_s.thd_start)->thd_inst = 0;
    void *ret = tee_srv_dispatch(l_s.thd_start);
    (void)ret;
}

#endif
