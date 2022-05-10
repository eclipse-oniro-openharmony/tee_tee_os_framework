/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: hm timer call define in this file.
 * Create: 2022-04-22
 */
#include <sys_timer.h>
#include <ac.h>
#include <ac_job.h>
#include <hmlog.h>
#include <hm_getpid.h>
#include <ipclib.h>
#include <security_ops.h>
#include <sys/usrsyscall_ext.h>
#include <timer_reg.h>

static cref_t g_s_rslot;
static struct ac_job g_ac_job;
static cref_t g_timer_tcb_cref;
static uint32_t g_tick_timer_fiq_num;

cref_t timer_tcb_cref_get(void)
{
    return g_timer_tcb_cref;
}

uint32_t tick_timer_fiq_num_get(void)
{
    return g_tick_timer_fiq_num;
}

int tee_renew_hmtimer_job_handler(void)
{
    int ret;
    ret = ac_create_job(AC_SID_DRV_TIMER, TASKMAP2TASK_J, &g_ac_job.rref, &g_ac_job.cref);
    if (ret != TMR_OK) {
        hm_error("libhmdrv: create ac job error: %d\n", ret);
        return ret;
    }

    return TMR_OK;
}

int tee_hm_timer_init(void)
{
    int ret;
    ret = hm_ipc_get_ch_from_path(TIMER_PATH, &g_s_rslot);
    if (ret != TMR_OK) {
        hm_error("libtimer: get timer channel failed: %d\n", hm_getpid());
        return ret;
    }

    g_tick_timer_fiq_num = TICK_TIMER_FIQ_NUMBLER;
    ret = ac_job_init(&g_ac_job, AC_SID_DRV_TIMER, TASKMAP2TASK_J);
    if (ret != TMR_OK) {
        hm_error("libhmdrv: create ac job error: %d\n", ret);
        return ret;
    }

    return TMR_OK;
}

static int timer_tcb_cref_init(struct timer_reply_msg_t rmsg)
{
    if (g_timer_tcb_cref == 0)
        g_timer_tcb_cref = rmsg.tcb_cref;

    if (g_timer_tcb_cref != rmsg.tcb_cref) {
        hm_error("timer tcb cref changed\n");
        return TMR_ERR;
    }
    return TMR_OK;
}

static uint32_t hmtimer_msg_prepare(uint16_t id, const uint64_t *args, int nr, struct timer_req_msg_t *msg)
{
    if (g_s_rslot == 0)
        tee_hm_timer_init();

    if (nr > TIMER_MSG_NUM_MAX) {
        hm_error("libtimer: args size too large\n");
        return TMR_ERR;
    }

    msg->header.send.msg_class = HM_MSG_HEADER_CLASS_TMRMGR;
    msg->header.send.msg_flags = 0;
    msg->header.send.msg_id    = id;
    msg->header.send.msg_size  = sizeof(*msg);

    for (int32_t i = 0; i < nr; i++)
        msg->args[i] = args[i];

    /* enable ac_job before calling driver */
    msg->job_handler = g_ac_job.cref;
    return TMR_OK;
}

uint32_t hmtimer_call(uint16_t id, uint64_t *args, int nr)
{
    struct timer_req_msg_t msg    = { {{ 0 }}, { 0 }, 0 };
    struct timer_reply_msg_t rmsg = { {{ 0 }}, 0, { 0 } };

    if (nr < 0) {
        hm_error("invalid parameters, please check\n");
        return TMR_ERR;
    }

    /* return 4 register value at most */
    uint32_t rmsg_cnt = (uint32_t)((nr < TIMER_RMSG_MAX_NUM) ? nr : TIMER_RMSG_MAX_NUM);
    int ret;
    uint32_t msg_ret;

    if (args == NULL) {
        hm_error("invalid parameters, please check\n");
        return TMR_ERR;
    }

    msg_ret = hmtimer_msg_prepare(id, args, nr, &msg);
    if (msg_ret != TMR_OK) {
        hm_error("prepare failed 0x%x\n", msg_ret);
        return TMR_ERR;
    }

    ret = ac_job_enable(&g_ac_job);
    if (ret != TMR_OK) {
        hm_error("timer enable failed %d\n", ret);
        return TMR_ERR;
    }

    /* send timer msg to `drv_timer` */
    ret = hm_msg_call(g_s_rslot, &msg, sizeof(msg), &rmsg, sizeof(rmsg), 0, TIME_OUT_NEVER);
    if (ret != TMR_OK) {
        hm_error("msg: 0x%x failed: %d, swi_id: %u\n", (uint32_t)g_s_rslot, ret, id);
        (void)ac_job_disable(&g_ac_job);
        return TMR_ERR;
    }

    ret = timer_tcb_cref_init(rmsg);
    if (ret != TMR_OK) {
        hm_error("cref init failed\n");
        (void)ac_job_disable(&g_ac_job);
        return TMR_ERR;
    }

    /*
     * copy back the registers value returned by `drv_timer`, note `drv_timer` will return
     * 4 register value at most.
     */
    for (uint32_t i = 0; i < rmsg_cnt; i++)
        args[i] = rmsg.regs[i];

    ret = ac_job_disable(&g_ac_job);
    if (ret != TMR_OK) {
        hm_error("timer disable failed %d\n", ret);
        return TMR_ERR;
    }

    /* if TA has no permission to call drv timer, it will set rmsg.regs[0] to -1 */
    bool flag = (args[0] == (uint64_t)(-1)) || ((uint32_t)args[0] == (uint32_t)(-1));
    if (flag)
        return TMR_ERR;
    else
        return (LOWER_32_BITS(rmsg.header.reply.ret_val) == TMR_OK) ? TMR_OK : TMR_ERR;
}
