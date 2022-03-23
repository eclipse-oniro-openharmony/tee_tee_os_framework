
#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "sre_access_control.h"

#include <sre_typedef.h>
#include <register_ops.h> // readl
#include <sre_sys.h>
#include <mem_ops.h>
#include <sre_hwi.h>
#include <tee_defines.h>
#include <sys/hmapi_ext.h>

#include "stdint.h"
#include "drv_module.h"
#include "libhwsecurec/securec.h"


#include "npu_public_sec.h"
#include "npu_task_public_sec.h"
#include "npu_task_sswq_sec.h"

#define NPU_SSWQ_HIGH_PRIO_START (0)
#define NPU_SSWQ_HIGH_PRIO_END   (NPU_SSWQ_HIGH_PRIO_START + NPU_SSWQ_HIGH_FIFO_DEPTH - 1)
#define NPU_SSWQ_LOW_PRIO_START  (NPU_SSWQ_HIGH_PRIO_START + NPU_SSWQ_HIGH_FIFO_DEPTH)
#define NPU_SSWQ_LOW_PRIO_END    (NPU_SSWQ_HIGH_PRIO_START + NPU_SSWQ_HIGH_FIFO_DEPTH + NPU_SSWQ_LOW_FIFO_DEPTH - 1)

#define NPU_MASK_TASK_INTERRUPT_FLAG  (1)
#define NPU_ALL_FINISH_INTERRUPT_FLAG (2)

/* the npu self start config status */
typedef enum {
    NPU_SSCFG_START = 0,
    NPU_SSCFG_EMPTY = NPU_SSCFG_START,
    /*First*/
    NPU_SSCFG_CF_DONE = (0x1<<0),
    NPU_SSCFG_SA_DONE = (0x1<<1),
    NPU_SSCFG_SS_DONE = (0x1<<2),
    NPU_SSCFG_ID_DONE = (0x1<<3),
    NPU_SSCFG_DB_DONE = (0x1<<4),
    NPU_SSCFG_PH_DONE = (0x1<<5),
    NPU_SSCFG_CP_DONE = (0x1<<6),
    NPU_SSCFG_DONE    = (0x007F),
    NPU_SSCFG_LOAD    = (0xFFFF),
    /*Add new to here*/
    NPU_SSCFG_END
} NPU_SSCFG_STATUS_E;

/* the npu self start config */
typedef struct {
    unsigned int sscfg_flag;
    unsigned int push_workqueue;
    unsigned int self_start_cfg;
    unsigned int self_start_id;
    unsigned int self_start_size;
    unsigned int self_start_ddr_base;
    unsigned long long self_start_addr;
    /*use to mark task status*/
    volatile NPU_SSWQ_TASK_STATUS_E *self_start_status;
} NPU_SELF_START_CFG_S;

/* the npu self start workqueue kfifo */
typedef struct {
    unsigned int core_id;
    unsigned int in;
    unsigned int out;
    unsigned int mask;
    unsigned int queue_id_base;
    NPU_SELF_START_CFG_S self_start_task[NPU_SSWQ_FIFO_DEPTH];
}NPU_SSWQ_KFIFO_S;

/* the npu self start workqueue kfifo */
typedef struct {
    NPU_SSWQ_KFIFO_S sswq_low_fifo[MAX_SUPPORT_CORE_NUM];
    NPU_SSWQ_KFIFO_S sswq_high_fifo[MAX_SUPPORT_CORE_NUM];
} NPU_TASK_KFIFO_PRIVATE_S;

NPU_TASK_KFIFO_PRIVATE_S g_task_fifo;

#define NPU_SSWQ_FIFO_RESET(sswq_fifo_ptr)  \
({\
    (sswq_fifo_ptr)->in  = (sswq_fifo_ptr)->out = 0;    \
})

#define NPU_SSWQ_FIFO_CLEAR(sswq_fifo_ptr)  \
({\
    (sswq_fifo_ptr)->out = (sswq_fifo_ptr)->in; \
})

#define NPU_SSWQ_FIFO_LEN(sswq_fifo_ptr)    \
({\
    (sswq_fifo_ptr)->in - (sswq_fifo_ptr)->out; \
})

#define NPU_SSWQ_FIFO_IS_EMPTY(sswq_fifo_ptr)   \
({\
    (sswq_fifo_ptr)->out == (sswq_fifo_ptr)->in;    \
})

#define NPU_SSWQ_FIFO_IS_FULL(sswq_fifo_ptr)    \
({\
    NPU_SSWQ_FIFO_LEN(sswq_fifo_ptr) > (sswq_fifo_ptr)->mask;\
})

#define NPU_SSWQ_FIFO_SKIP(sswq_fifo_ptr)   \
({\
    (sswq_fifo_ptr)->out++; \
})

#define NPU_SSWQ_FIFO_PUT_N(sswq_fifo_ptr, n)   \
({\
    (sswq_fifo_ptr)->out += n; \
})

typedef struct {
    /*sswq interrupt status*/
    unsigned int interrupt_status;
    /*sswq finish status*/
    unsigned int finish_status;
    unsigned int task_bitmap;
} NPU_INTERRUPT_MSG_S;

static NPU_INTERRUPT_MSG_S g_interrupt_msg[MAX_SUPPORT_CORE_NUM];

#define NPU_SET_INTERRUPT_TASK_BIT(core_id, task_id)    \
({  \
    g_interrupt_msg[core_id].task_bitmap |= ((0x1 << task_id) & 0xFFFF);    \
})

#define NPU_CLR_INTERRUPT_TASK_BIT(core_id, task_id)    \
({  \
    g_interrupt_msg[core_id].task_bitmap &= ~((0x1 << task_id) & 0xFFFF);   \
})

#define NPU_SSWQ_FINISH_STATUS(core_id) \
    (g_interrupt_msg[core_id].interrupt_status & WORK_QUEUE_FINISH_IS_MASK) \

#define NPU_SSWQ_MASK_FINISH_STATUS(core_id) \
    (g_interrupt_msg[core_id].interrupt_status & WORK_QUEUE_MASK_FINISH_IS_MASK) \

#define NPU_SSWQ_ALL_FINISH_STATUS(core_id) \
    (g_interrupt_msg[core_id].interrupt_status & WORK_QUEUE_ALL_FINISH_IS_MASK) \

static int npu_task_fifo_init(unsigned int core_id)
{
    UNUSED_PARAMETER(core_id);
    return 0;
}

static void npu_self_start_task_fifo_init(unsigned int core_id)
{
    g_task_fifo.sswq_low_fifo[core_id].core_id = core_id;
    g_task_fifo.sswq_low_fifo[core_id].in   = 0;
    g_task_fifo.sswq_low_fifo[core_id].out  = 0;
    g_task_fifo.sswq_low_fifo[core_id].mask = (NPU_SSWQ_LOW_FIFO_DEPTH - 1);
    g_task_fifo.sswq_low_fifo[core_id].queue_id_base = NPU_SSWQ_LOW_PRIO_START;
    memset_s(g_task_fifo.sswq_low_fifo[core_id].self_start_task, (sizeof(NPU_SELF_START_CFG_S)*NPU_SSWQ_FIFO_DEPTH),
        0, (sizeof(NPU_SELF_START_CFG_S)*NPU_SSWQ_FIFO_DEPTH));

    g_task_fifo.sswq_high_fifo[core_id].core_id = core_id;
    g_task_fifo.sswq_high_fifo[core_id].in   = 0;
    g_task_fifo.sswq_high_fifo[core_id].out  = 0;
    g_task_fifo.sswq_high_fifo[core_id].mask = (NPU_SSWQ_HIGH_FIFO_DEPTH - 1);
    g_task_fifo.sswq_high_fifo[core_id].queue_id_base = NPU_SSWQ_HIGH_PRIO_START;
    memset_s(g_task_fifo.sswq_high_fifo[core_id].self_start_task, (sizeof(NPU_SELF_START_CFG_S)*NPU_SSWQ_FIFO_DEPTH),
        0, (sizeof(NPU_SELF_START_CFG_S)*NPU_SSWQ_FIFO_DEPTH));

    return;
}

int npu_task_sswq_init(void)
{
    int ret = 0;
    unsigned int core_id = 0;

    memset_s(&g_task_fifo, sizeof(NPU_TASK_KFIFO_PRIVATE_S), 0, sizeof(NPU_TASK_KFIFO_PRIVATE_S));

    for (core_id = 0; core_id < g_task_private.core_num; core_id++) {
        ret = npu_task_fifo_init(core_id);
        if (ret) {
            NPU_ERR("Call npu_task_fifo_init is failed!");
            return -1;
        }

        npu_self_start_task_fifo_init(core_id);

        memset_s(&g_interrupt_msg[core_id], sizeof(NPU_INTERRUPT_MSG_S), 0, sizeof(NPU_INTERRUPT_MSG_S));
    }
    return SUCCESS;
}

void npu_task_sswq_exit(void)
{
    memset_s(&g_task_fifo, sizeof(NPU_TASK_KFIFO_PRIVATE_S), 0, sizeof(NPU_TASK_KFIFO_PRIVATE_S));

    return;
}

static int npu_self_start_cfg(NPU_SELF_START_CFG_S *pCfg, int config)
{
    pCfg->self_start_cfg = config;
    pCfg->sscfg_flag |= NPU_SSCFG_CF_DONE;
    return 0;
}

static int npu_self_start_addr_cfg(NPU_SELF_START_CFG_S *pCfg, unsigned long long addr)
{
    pCfg->self_start_addr = addr;
    pCfg->sscfg_flag |= NPU_SSCFG_SA_DONE;
    return 0;
}

static int npu_self_start_size_cfg(NPU_SELF_START_CFG_S *pCfg, int size)
{
    pCfg->self_start_size = size;
    pCfg->sscfg_flag |= NPU_SSCFG_SS_DONE;
    return 0;
}

static int npu_self_start_id_cfg(NPU_SELF_START_CFG_S *pCfg, int taskid, int threadid)
{
    taskid = ((taskid & 0xFF) << 8 ) | 0x01;
    pCfg->self_start_id =
        (taskid << SELF_STARRT_TASK_ID_BIT) & SELF_STARRT_TASK_ID_MASK;
    pCfg->self_start_id |=
        (threadid << SELF_STARRT_TASK_ID_BIT) & SELF_STARRT_TASK_ID_MASK;
    pCfg->sscfg_flag |= NPU_SSCFG_ID_DONE;
    return 0;
}

static int npu_push_work_queue_cfg(NPU_SELF_START_CFG_S *pCfg, bool isMask, bool isSilence)
{
    /*Assign pushWorkQueue 0 due to pCfg is not initialized*/
    pCfg->push_workqueue = (isMask)? WORK_QUEUE_MASK_EN_MASK:0;

    if (isSilence)
        pCfg->push_workqueue |= WORK_QUEUE_SILENCE_EN_MASK;

    pCfg->sscfg_flag |= NPU_SSCFG_PH_DONE;
    return 0;
}

static int npu_ddr_base_addr_cfg(NPU_SELF_START_CFG_S *pCfg, unsigned int ddr_base)
{
    ddr_base >>= 20;
    pCfg->self_start_ddr_base = (unsigned int)(ddr_base & 0xFFFFFFFF);
    pCfg->sscfg_flag |= NPU_SSCFG_DB_DONE;
    return 0;
}

static int npu_wakeup_conditon_cfg(NPU_SELF_START_CFG_S *pCfg, volatile NPU_SSWQ_TASK_STATUS_E *conditon_ptr)
{
    pCfg->self_start_status = conditon_ptr;
    pCfg->sscfg_flag |= NPU_SSCFG_CP_DONE;
    return 0;
}

static void npu_sswq_config_parser
(
    NPU_SELF_START_CFG_S *cfg_ptr,
    NPU_SSWQ_TASK_ELEMENT_S *ptask_element,
    volatile NPU_SSWQ_TASK_STATUS_E *task_status
)
{
    cfg_ptr->sscfg_flag = NPU_SSCFG_EMPTY;

    npu_self_start_cfg(cfg_ptr, ptask_element->task_config);
    npu_self_start_addr_cfg(cfg_ptr, ptask_element->inst_addr_off);
    npu_self_start_size_cfg(cfg_ptr, ptask_element->inst_size);
    npu_self_start_id_cfg(cfg_ptr, ptask_element->task_id, ptask_element->thread_id);
    npu_ddr_base_addr_cfg(cfg_ptr, ptask_element->ddr_base_addr);

    if (ptask_element->task_type == NPU_SSWQU_MASK_TASK) {
        npu_push_work_queue_cfg(cfg_ptr, 1, 0);
    }
    else if (ptask_element->task_type == NPU_SSWQU_NOTIFY_TASK) {
        npu_push_work_queue_cfg(cfg_ptr, 0, 0);
    }
    else {
        npu_push_work_queue_cfg(cfg_ptr, 0, 1);
    }

    npu_wakeup_conditon_cfg(cfg_ptr, task_status);

    NPU_DEBUG("sscfg_flag 0x%x", cfg_ptr->sscfg_flag);
}

#ifdef NPU_DEBUG_SSWQ_REG
static void npu_print_self_start_reg(unsigned int core_id)
{
    unsigned int regValue = 0;
    unsigned long long selfstartaddr = 0;
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;

    /*SELF_START_CONFIG_REG*/
    regValue = readl(SOC_NPU_SSWQ_SELF_START_CONFIG_ADDR(config_reg_virt_addr));
    NPU_DEBUG("Read back: self start config : 0x%x", regValue);

    /*SELF_START_ADDR_REG*/
    selfstartaddr = readl(SOC_NPU_SSWQ_SELF_START_HI_ADDR(config_reg_virt_addr));
    NPU_DEBUG("Read back: self start hi addr : 0x%x", selfstartaddr);
    selfstartaddr = ((selfstartaddr << 32) | readl(SOC_NPU_SSWQ_SELF_START_LO_ADDR(config_reg_virt_addr)));
    NPU_DEBUG("Read back:  self start addr  : 0x%x", selfstartaddr);

    /*SELF_START_SIZE_REG*/
    regValue = readl(SOC_NPU_SSWQ_SELF_START_SIZE_ADDR(config_reg_virt_addr));
    NPU_DEBUG("Read back:  self start size  : 0x%x", regValue);

    /*SELF_START_ID_REG*/
    regValue = readl(SOC_NPU_SSWQ_SELF_START_ID_ADDR(config_reg_virt_addr));
    NPU_DEBUG("Read back:  self start id    : 0x%x", regValue);

    /*SELF_START_DDR_BASE*/
    regValue = readl(SOC_NPU_SSWQ_DDR_BASE_ADDR(config_reg_virt_addr));
    NPU_DEBUG("Read back:self start ddr base : 0x%x", regValue);

    /*PUSH_WORK_QUEUE*/
    regValue = readl(SOC_NPU_SSWQ_PUSH_WORK_QUEUE_ADDR(config_reg_virt_addr));
    NPU_DEBUG("Read back: push work queue   : 0x%x", regValue);

    UNUSED_PARAMETER(regValue);

    return;
}

static void npu_print_fifo_info(NPU_SSWQ_KFIFO_S* sswq_fifo_ptr)
{
    int index;

    for (index = 0; index < NPU_SSWQ_FIFO_DEPTH; index++) {
        NPU_DEBUG("self_start_task[%d](0x%x): 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x",
        index,
        &sswq_fifo_ptr->self_start_task[index],
        sswq_fifo_ptr->self_start_task[index].sscfg_flag,
        sswq_fifo_ptr->self_start_task[index].push_workqueue,
        sswq_fifo_ptr->self_start_task[index].self_start_cfg,
        sswq_fifo_ptr->self_start_task[index].self_start_id,
        sswq_fifo_ptr->self_start_task[index].self_start_size,
        sswq_fifo_ptr->self_start_task[index].self_start_ddr_base,
        sswq_fifo_ptr->self_start_task[index].self_start_addr,
        (unsigned long)sswq_fifo_ptr->self_start_task[index].self_start_status);
    }

    UNUSED_PARAMETER(sswq_fifo_ptr);

    return;
}
#endif

static int npu_task_start(unsigned int core_id, NPU_SELF_START_CFG_S *cfg_ptr, const int eID)
{
    unsigned int regValue = 0;
    unsigned long long selfstartaddr = 0;
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;

    /**For Debug*/
#ifdef NPU_DEBUG_SSWQ_REG
    npu_print_self_start_reg(core_id);
    regValue = readl(SOC_NPU_SSWQ_WORK_QUEUE_INFO_ADDR(config_reg_virt_addr));
    NPU_DEBUG("work queue info  0x%x", regValue);
    regValue = readl(SOC_NPU_SSWQ_WORK_QUEUE_FINISH_ADDR(config_reg_virt_addr));
    NPU_DEBUG("work queue finish  0x%x", regValue);
#endif
    NPU_DEBUG("self start config_reg_virt_addr=0x%x", config_reg_virt_addr);

    if (NPU_SSCFG_DONE == cfg_ptr->sscfg_flag) {
        /*SELF_START_CONFIG_REG*/
        regValue = cfg_ptr->self_start_cfg;
        NPU_DEBUG("self start config reg write 0x%x", regValue);
        writel(regValue, SOC_NPU_SSWQ_SELF_START_CONFIG_ADDR(config_reg_virt_addr));

        /*SELF_START_ADDR_REG*/
        selfstartaddr = cfg_ptr->self_start_addr;
        NPU_DEBUG("self start addr reg write 0x%x", selfstartaddr);
        writel(selfstartaddr & 0xFFFFFFFF, SOC_NPU_SSWQ_SELF_START_LO_ADDR(config_reg_virt_addr));
        selfstartaddr >>= 32;
        writel(selfstartaddr & 0xFFFFFFFF, SOC_NPU_SSWQ_SELF_START_HI_ADDR(config_reg_virt_addr));

        /*SELF_START_SIZE_REG*/
        regValue = cfg_ptr->self_start_size;
        NPU_DEBUG("self start size reg wrte 0x%x", regValue);
        writel(regValue, SOC_NPU_SSWQ_SELF_START_SIZE_ADDR(config_reg_virt_addr));

        /*SELF_START_ID_REG*/
        regValue = cfg_ptr->self_start_id;
        NPU_DEBUG("self start id reg wrte 0x%x", regValue);
        writel(regValue, SOC_NPU_SSWQ_SELF_START_ID_ADDR(config_reg_virt_addr));

        /*SELF_START_DDR_BASE*/
        regValue = cfg_ptr->self_start_ddr_base;
        NPU_DEBUG("self start ddr base reg write 0x%x", regValue);
        writel(regValue, SOC_NPU_SSWQ_DDR_BASE_ADDR(config_reg_virt_addr));

        /*PUSH_WORK_QUEUE*/
        regValue = cfg_ptr->push_workqueue;
        regValue |= (eID << WORK_QUEUE_ID_BIT) & WORK_QUEUE_ID_MASK;
        regValue |= PUSH_WORK_QUEUE_EN_MASK;
        NPU_DEBUG("push work queue reg write 0x%x", regValue);
        writel(regValue, SOC_NPU_SSWQ_PUSH_WORK_QUEUE_ADDR(config_reg_virt_addr));

        /*INTERRUPT TASK BITMAP*/
        if (( WORK_QUEUE_MASK_EN_MASK == cfg_ptr->push_workqueue) || (0 == cfg_ptr->push_workqueue)){
            NPU_SET_INTERRUPT_TASK_BIT(core_id, eID);
        }
        cfg_ptr->sscfg_flag= NPU_SSCFG_LOAD;

        /**For Debug*/
#ifdef NPU_DEBUG_SSWQ_REG
        npu_print_self_start_reg(core_id);
        regValue = readl(SOC_NPU_SSWQ_WORK_QUEUE_INFO_ADDR(config_reg_virt_addr));
        NPU_DEBUG("work queue info  0x%x", regValue);
        regValue = readl(SOC_NPU_SSWQ_WORK_QUEUE_FINISH_ADDR(config_reg_virt_addr));
        NPU_DEBUG("work queue finish  0x%x", regValue);
#endif
    } else {
        NPU_ERR("LOAD ERR!! CFG image usingFlag = 0x%x", cfg_ptr->sscfg_flag);
        return -1;
    }
    return SUCCESS;
}

static int npu_sswq_put_task_to_workqueue(NPU_SSWQ_KFIFO_S *sswq_fifo_ptr, NPU_SELF_START_CFG_S *ss_config_in)
{
    unsigned int ret;
    unsigned int eID = 0;
    NPU_SELF_START_CFG_S *ss_cfg_ptr;
    unsigned int core_id = sswq_fifo_ptr->core_id;
    unsigned int queue_id_base = sswq_fifo_ptr->queue_id_base;

    ret = NPU_SSWQ_FIFO_IS_FULL(sswq_fifo_ptr);
    if (ret) {
        NPU_DEBUG("sswq fifo is full!");
        return ret;
    }

    ss_cfg_ptr = &(sswq_fifo_ptr->self_start_task[sswq_fifo_ptr->in & sswq_fifo_ptr->mask]);
    NPU_DEBUG("Copy self start config data!sswq_fifo_ptr->in=%d,sswq_fifo_ptr->mask=%d", sswq_fifo_ptr->mask, sswq_fifo_ptr->mask);
    memcpy_s(ss_cfg_ptr, sizeof(NPU_SELF_START_CFG_S), ss_config_in, sizeof(NPU_SELF_START_CFG_S));
    NPU_DEBUG("push 0x%x , config 0x%x, id 0x%x, size 0x%x,"
            " addr 0x%x, base 0x%x, flag 0x%x, conditon 0x%x",
            ss_cfg_ptr->push_workqueue,
            ss_cfg_ptr->self_start_cfg,
            ss_cfg_ptr->self_start_id,
            ss_cfg_ptr->self_start_size,
            ss_cfg_ptr->self_start_addr,
            ss_cfg_ptr->self_start_ddr_base,
            ss_cfg_ptr->sscfg_flag,
            ss_cfg_ptr->self_start_status);
    NPU_DEBUG("ssCfgptr = 0x%x", ss_cfg_ptr);
    eID = queue_id_base + (sswq_fifo_ptr->in & sswq_fifo_ptr->mask);

    sswq_fifo_ptr->in++;

    npu_task_start(core_id, ss_cfg_ptr, eID);

    return ret;
}

static void npu_sswq_task_proc(NPU_SSWQ_TASK_ELEMENT_S *sswq_task)
{
    NPU_SELF_START_CFG_S self_start_config;
    NPU_SSWQ_KFIFO_S *sswq_fifo_ptr = NULL;

    if (sswq_task->task_priority == NPU_TASK_PRIO_HI) {
        sswq_fifo_ptr = &g_task_fifo.sswq_high_fifo[sswq_task->core_id];
    } else {
        sswq_fifo_ptr = &g_task_fifo.sswq_low_fifo[sswq_task->core_id];
    }

    if (sswq_fifo_ptr->core_id != sswq_task->core_id) {
        NPU_DEBUG("sswq_fifo_ptr->core_id=%d core_id=%d", sswq_fifo_ptr->core_id, sswq_task->core_id);
        sswq_fifo_ptr->core_id = sswq_task->core_id;
    }

    NPU_DEBUG("Get task from task fifo successed");
    NPU_DEBUG("Core-Id %d, Task-type %d, I-Addr 0x%llx, I-Size 0x%x,"
        " T-Id 0x%x, TH-Id 0x%x, Cfg 0x%x, DDR-Base 0x%llx",
        sswq_task->core_id,
        sswq_task->task_type,
        sswq_task->inst_addr_off & 0xffffffff,
        sswq_task->inst_size,
        sswq_task->task_id,
        sswq_task->thread_id,
        sswq_task->task_config,
        sswq_task->ddr_base_addr & 0xffffffff);
    npu_sswq_config_parser(&self_start_config, sswq_task, sswq_fifo_ptr->self_start_task[sswq_fifo_ptr->in & sswq_fifo_ptr->mask].self_start_status);

    npu_sswq_put_task_to_workqueue(sswq_fifo_ptr, &self_start_config);

    return;
}

static void npu_self_start_fifo_restore(unsigned int core_id, unsigned int task_priority, NPU_SSWQ_KFIFO_S* sswq_kfifo_ptr)
{
    unsigned int index;
    unsigned int eID = 0;
    NPU_SELF_START_CFG_S *sswq_cfg_ptr;

    NPU_DEBUG("sswq_fifo_ptr->out=%d,sswq_fifo_ptr->in=%d", sswq_kfifo_ptr->out, sswq_kfifo_ptr->in);
    if (NPU_SSWQ_FIFO_IS_EMPTY(sswq_kfifo_ptr)) {
        NPU_DEBUG("core_id %d task_prio[%d] is empty", core_id, task_priority);
        return;
    }

    sswq_cfg_ptr = &(sswq_kfifo_ptr->self_start_task[sswq_kfifo_ptr->out & sswq_kfifo_ptr->mask]);
    /*TODO: wake user thread*/
    if (NULL != sswq_cfg_ptr->self_start_status) {
        *(sswq_cfg_ptr->self_start_status) = NPU_SSWQ_TASK_DONE;
    } else {
        NPU_DEBUG("core_id %d self_start_config.self_start_status is empty", core_id);
    }

    /* Start restoring the next frame task */
    sswq_kfifo_ptr->out++;

    /* restore task to workqueue */
    for (index = sswq_kfifo_ptr->out; index < sswq_kfifo_ptr->in; index++) {
        sswq_cfg_ptr = &(sswq_kfifo_ptr->self_start_task[index & sswq_kfifo_ptr->mask]);
        sswq_cfg_ptr->sscfg_flag = NPU_SSCFG_DONE;
        eID = sswq_kfifo_ptr->queue_id_base + (index & sswq_kfifo_ptr->mask);
        NPU_DEBUG("index=%d,eID=0x%x,sswq_fifo_ptr->mask=0x%x,sswq_fifo_ptr->queue_id_base=0x%x", index, eID, sswq_kfifo_ptr->mask, sswq_kfifo_ptr->queue_id_base);
        npu_task_start(core_id, sswq_cfg_ptr, eID);
    }

    UNUSED_PARAMETER(task_priority);

    return;
}

void npu_sswq_task_restore(unsigned int core_id)
{
    /* restore low fifo task to workqueue */
    NPU_DEBUG("Restore low fifo task to workqueue! core_id:%d", core_id);
    npu_self_start_fifo_restore(core_id, NPU_TASK_PRIO_LOW, &g_task_fifo.sswq_low_fifo[core_id]);

    /* restore high fifo task to workqueue */
    NPU_DEBUG("Restore high fifo task to workqueue! core_id:%d", core_id);
    npu_self_start_fifo_restore(core_id, NPU_TASK_PRIO_HI, &g_task_fifo.sswq_high_fifo[core_id]);

    return;
}

int npu_push_sswq_task(const void *arg)
{
    bool do_block_push = 0;
    NPU_SSWQ_KFIFO_S *sswq_fifo_ptr = NULL;
    NPU_SSWQ_TASK_ELEMENT_S task_element;
    volatile NPU_SSWQ_TASK_STATUS_E task_status = NPU_SSWQ_TASK_NONE;

    memcpy_s((void *)&task_element, sizeof(NPU_SSWQ_TASK_ELEMENT_S), arg, sizeof(NPU_SSWQ_TASK_ELEMENT_S));

    if (NPU_TASK_PRIO_NUM <= task_element.task_priority) {
        NPU_ERR("Input task_priority is error! task_priority=%d", task_element.task_priority);
        return -1;
    }

    NPU_DEBUG("core_id=%d task_priority=%d", task_element.core_id, task_element.task_priority);

    if (task_element.task_priority == NPU_TASK_PRIO_HI) {
        sswq_fifo_ptr = &g_task_fifo.sswq_high_fifo[task_element.core_id];
    } else {
        sswq_fifo_ptr = &g_task_fifo.sswq_low_fifo[task_element.core_id];
    }

    while (NPU_SSWQ_FIFO_IS_FULL(sswq_fifo_ptr)) {
         hmapi_yield();
		 //SRE_DelayMs(1);
	}

    npu_task_fifo_opt_lock(task_element.core_id);

    /*Ensure point correct*/
    sswq_fifo_ptr->self_start_task[sswq_fifo_ptr->in & sswq_fifo_ptr->mask].self_start_status = NULL;

    switch (task_element.task_type) {
        case NPU_SSWQU_MASK_TASK: {
            NPU_DEBUG("NPU task is IPU_SSWQU_MASK_TASK");
            sswq_fifo_ptr->self_start_task[sswq_fifo_ptr->in & sswq_fifo_ptr->mask].self_start_status = &task_status;
            NPU_DEBUG("Pointer of task_status is 0x%x",
                sswq_fifo_ptr->self_start_task[sswq_fifo_ptr->in & sswq_fifo_ptr->mask].self_start_status);
            do_block_push = 1;
            break;
        }
        default: {
            NPU_ERR("NPU task is UNKNOW task_type [%d]\n", task_element.task_type);
            goto error;
        }
    }

    NPU_DEBUG("FIFO_TaskElements[%d] inqueue success", task_element.core_id);
    npu_sswq_task_proc(&task_element);

    npu_task_fifo_opt_unlock(task_element.core_id);

    if (do_block_push) {
        NPU_DEBUG("To wait interrupt wake the thread. task_status=%d coreID=%d", task_status, task_element.core_id);
        NPU_PRINT("-------to wait------\n");
        while (NPU_SSWQ_TASK_DONE != task_status) {
            //SRE_SwMsleep(50);
            hmapi_yield();
        }
        task_status = NPU_SSWQ_TASK_NONE;

        NPU_PRINT("-------up ok------\n");
    }

    return SUCCESS;

error:
    npu_task_fifo_opt_unlock(task_element.core_id);
    task_status = NPU_SSWQ_TASK_NONE;

    return -1;
}

void npu_sswq_get_interrupt_status(unsigned int core_id)
{
    unsigned int ret;
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;

    ret = readl(SOC_NPU_IS_ADDR(config_reg_virt_addr));
    g_interrupt_msg[core_id].interrupt_status = ret;

    ret = readl(SOC_NPU_SSWQ_WORK_QUEUE_FINISH_ADDR(config_reg_virt_addr));
    ret &= WORK_QUEUE_FINISH_MASK;
    g_interrupt_msg[core_id].finish_status = ret;

    NPU_PRINT("interrupt_status=0x%x,finish_status=0x%x",g_interrupt_msg[core_id].interrupt_status, g_interrupt_msg[core_id].finish_status);

    return;
}

#define ffs(x) ({\
unsigned int i = 0;\
if((x) == 0)\
    i = 0;\
else {\
    while(((x) & (1<<i)) == 0)\
    {\
        i ++;\
    }\
    i++;\
    }\
 i;})

static unsigned int npu_sswq_get_interrupt_task_id(unsigned int core_id)
{
    unsigned int ret;
    //todo:
    ret = ffs(g_interrupt_msg[core_id].finish_status & g_interrupt_msg[core_id].task_bitmap) - 1;

    return ret;
}

static void npu_sswq_fifo_skip_to_task_id(NPU_SSWQ_KFIFO_S* sswq_fifo_ptr, unsigned int task_id)
{
    if (task_id >= ((sswq_fifo_ptr->out) & (sswq_fifo_ptr->mask))) {
        task_id += ((sswq_fifo_ptr->out) & (~(sswq_fifo_ptr->mask)));
    }
    else {
        task_id += ((sswq_fifo_ptr->in) & (~(sswq_fifo_ptr->mask)));
    }

    sswq_fifo_ptr->out = task_id;

    return;
}

static int npu_sswq_fifo_get_task(NPU_SSWQ_KFIFO_S* sswq_fifo_ptr, NPU_SELF_START_CFG_S *ss_config_out)
{
    unsigned int ret;
    unsigned int index;
    NPU_SELF_START_CFG_S *ss_cfg_ptr;

    ret = NPU_SSWQ_FIFO_IS_EMPTY(sswq_fifo_ptr);
    if (ret) {
        NPU_ERR("sswq fifo is empty!");
        return ret;
    }

    index = sswq_fifo_ptr->out & sswq_fifo_ptr->mask;
    ss_cfg_ptr = &(sswq_fifo_ptr->self_start_task[index]);
    memcpy_s(ss_config_out, sizeof(NPU_SELF_START_CFG_S), ss_cfg_ptr, sizeof(NPU_SELF_START_CFG_S));
    sswq_fifo_ptr->out++;

    return SUCCESS;
}

static void npu_sswq_core_interrupt_proc(unsigned int core_id, unsigned int* tast_prio_ptr)
{
    unsigned int working_task_id;
    NPU_SELF_START_CFG_S self_start_config;

    working_task_id = npu_sswq_get_interrupt_task_id(core_id);
    NPU_CLR_INTERRUPT_TASK_BIT(core_id, working_task_id);
    NPU_DEBUG("core_id %d working_task_id = %d", core_id, working_task_id);
    if (working_task_id > NPU_SSWQ_HIGH_PRIO_END) {
        working_task_id -= NPU_SSWQ_LOW_FIFO_DEPTH;
        npu_sswq_fifo_skip_to_task_id(&g_task_fifo.sswq_low_fifo[core_id], working_task_id);
        npu_sswq_fifo_get_task(&g_task_fifo.sswq_low_fifo[core_id], &self_start_config);
    } else {
        npu_sswq_fifo_skip_to_task_id(&g_task_fifo.sswq_high_fifo[core_id], working_task_id);
        npu_sswq_fifo_get_task(&g_task_fifo.sswq_high_fifo[core_id], &self_start_config);
        *tast_prio_ptr = NPU_TASK_PRIO_HI;
    }

    if (self_start_config.self_start_status != NULL) {
        *(self_start_config.self_start_status) = NPU_SSWQ_TASK_DONE;
    } else {
        NPU_DEBUG("core_id %d self_start_config.self_start_status is empty", core_id);
    }

    return;
}

static unsigned int __attribute__((unused)) npu_sswq_get_finish_info(unsigned int core_id)
{
    unsigned int ret;
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;

    ret = readl(SOC_NPU_SSWQ_WORK_QUEUE_FINISH_ADDR(config_reg_virt_addr));
    ret &= WORK_QUEUE_FINISH_MASK;
    ret >>= WORK_QUEUE_FINISH_BIT;
    return ret;
}

static int __attribute__((unused)) npu_sswq_get_finish_task_num(unsigned int core_id, unsigned int prio_level)
{
    unsigned int num = 0;
    unsigned int val;

    val = g_interrupt_msg[core_id].finish_status;

    if(prio_level == NPU_TASK_PRIO_HI) {
        val = val & 0xff;
    }
    else {
        val = val & 0xff00;
    }

    while (val) {
        num += val & 1;
        val >>= 1;
    }

    return num;
}

void npu_sswq_workqueue_finish_reg_clear(unsigned int core_id)
{
    unsigned int config_reg_virt_addr = g_task_private.reg_space[core_id].config_reg_virt_addr;

    writel(g_interrupt_msg[core_id].finish_status, SOC_NPU_SSWQ_WORK_QUEUE_FINISH_ADDR(config_reg_virt_addr));
    return;
}

void npu_sswq_interrupt_msg_clear(unsigned int core_id)
{
    g_interrupt_msg[core_id].interrupt_status= 0;
    g_interrupt_msg[core_id].finish_status = 0;

    return;
}

//todo: need add
void npu_sswq_core_interrupt_handler(unsigned int core_id)
{
    unsigned int prio_level = NPU_TASK_PRIO_LOW;
    unsigned int to_npu_start = 0;

    NPU_DEBUG("core_id %d", core_id);

    if (NPU_SSWQ_FINISH_STATUS(core_id)) {
        NPU_ERR("Not support, Work queue finish interrupt occurs.");
    }

    if (NPU_SSWQ_MASK_FINISH_STATUS(core_id)) {
        NPU_DEBUG("Work queue mask finish interrupt occurs.");
        npu_sswq_core_interrupt_proc(core_id, &prio_level);

#ifdef NPU_DEBUG_SSWQ_REG
        NPU_DEBUG("core_id:%d low fifo info!", core_id);
        npu_print_fifo_info(&g_task_fifo.sswq_low_fifo[core_id]);
        NPU_DEBUG("core_id:%d high fifo info!", core_id);
        npu_print_fifo_info(&g_task_fifo.sswq_high_fifo[core_id]);
#endif
        to_npu_start = NPU_MASK_TASK_INTERRUPT_FLAG;
    }

    if (NPU_SSWQ_ALL_FINISH_STATUS(core_id)) {
        NPU_DEBUG("Not support, Work queue all finish interrupt occurs.");
    }

    UNUSED_PARAMETER(to_npu_start);

    return;
}

